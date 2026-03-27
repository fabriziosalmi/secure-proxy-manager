import logging
import sqlite3
from datetime import datetime

import requests
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from ..auth import authenticate, auth_attempts
from ..config import MAX_ATTEMPTS, RATE_LIMIT_WINDOW
from ..database import get_db
from ..models import InternalAlert

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/api/internal/alert", dependencies=[Depends(authenticate)])
def receive_internal_alert(alert: InternalAlert, background_tasks: BackgroundTasks):
    """Receive alerts from internal services like WAF."""
    event = {
        "timestamp": datetime.now().isoformat(),
        "client_ip": alert.details.get('client_ip', 'unknown'),
        "event_type": alert.event_type,
        "message": alert.message,
        "level": alert.level,
        **{k: v for k, v in alert.details.items() if k != 'client_ip'}
    }
    background_tasks.add_task(send_security_notification, event)
    return {"status": "success"}


def send_security_notification(event):
    """Send security notifications to configured providers."""
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT setting_name, setting_value FROM settings WHERE setting_name IN "
            "('enable_notifications', 'webhook_url', 'gotify_url', 'gotify_token', "
            "'teams_webhook_url', 'telegram_bot_token', 'telegram_chat_id')"
        )
        settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}

        if settings.get('enable_notifications') != 'true':
            return

        emoji = "🔴" if event.get('level') == 'error' else "⚠️" if event.get('level') == 'warning' else "ℹ️"
        title = f"{emoji} Secure Proxy Alert: {event.get('event_type', 'Unknown').replace('_', ' ').title()}"

        message_lines = [
            f"**Message:** {event.get('message', 'No details')}",
            f"**Time:** {event.get('timestamp')}",
            f"**Client IP:** {event.get('client_ip', 'Unknown')}"
        ]
        if event.get('username'):
            message_lines.append(f"**User:** {event.get('username')}")
        for key, value in event.items():
            if key not in ['timestamp', 'client_ip', 'username', 'event_type', 'message', 'level']:
                message_lines.append(f"**{key.title()}:** {value}")

        plain_text = f"{title}\n\n" + "\n".join(message_lines)

        # 1. Custom Webhook
        webhook_url = settings.get('webhook_url')
        if webhook_url:
            try:
                requests.post(webhook_url, json=event, timeout=5)
            except requests.RequestException as e:
                logger.error(f"Failed to send webhook notification: {e}")

        # 2. Gotify
        gotify_url = settings.get('gotify_url')
        gotify_token = settings.get('gotify_token')
        if gotify_url and gotify_token:
            try:
                if not gotify_url.endswith('/'):
                    gotify_url += '/'
                requests.post(
                    f"{gotify_url}message?token={gotify_token}",
                    json={"title": title, "message": plain_text,
                          "priority": 8 if event.get('level') == 'error' else 5},
                    timeout=5
                )
            except requests.RequestException as e:
                logger.error(f"Failed to send Gotify notification: {e}")

        # 3. Microsoft Teams
        teams_url = settings.get('teams_webhook_url')
        if teams_url:
            try:
                teams_payload = {
                    "@type": "MessageCard",
                    "@context": "http://schema.org/extensions",
                    "themeColor": "FF0000" if event.get('level') == 'error' else "FFA500",
                    "summary": title,
                    "sections": [{
                        "activityTitle": title,
                        "facts": [
                            {"name": line.split(':**')[0].replace('**', '') + ":",
                             "value": line.split(':**')[1].strip() if ':**' in line else line}
                            for line in message_lines
                        ],
                        "markdown": True
                    }]
                }
                requests.post(teams_url, json=teams_payload, timeout=5)
            except requests.RequestException as e:
                logger.error(f"Failed to send MS Teams notification: {e}")

        # 4. Telegram
        telegram_token = settings.get('telegram_bot_token')
        telegram_chat_id = settings.get('telegram_chat_id')
        if telegram_token and telegram_chat_id:
            try:
                tg_text = f"*{title}*\n\n" + "\n".join(message_lines)
                requests.post(
                    f"https://api.telegram.org/bot{telegram_token}/sendMessage",
                    json={"chat_id": telegram_chat_id, "text": tg_text, "parse_mode": "Markdown"},
                    timeout=5
                )
            except requests.RequestException as e:
                logger.error(f"Failed to send Telegram notification: {e}")

    except (sqlite3.Error, requests.RequestException) as e:
        logger.error(f"Error in notification system: {e}")
    finally:
        if conn:
            conn.close()


@router.get("/api/security/rate-limits", dependencies=[Depends(authenticate)])
def get_rate_limits():
    try:
        now = datetime.now()
        rate_limit_data = []
        for ip, attempts in list(auth_attempts.items()):
            valid_attempts = [t for t in attempts if (now - t).total_seconds() < RATE_LIMIT_WINDOW]
            auth_attempts[ip] = valid_attempts
            if valid_attempts:
                rate_limit_data.append({
                    'ip': ip,
                    'attempt_count': len(valid_attempts),
                    'is_blocked': len(valid_attempts) >= MAX_ATTEMPTS,
                    'oldest_attempt': valid_attempts[0].isoformat() if valid_attempts else None,
                    'newest_attempt': valid_attempts[-1].isoformat() if valid_attempts else None,
                    'time_remaining': int(RATE_LIMIT_WINDOW - (now - valid_attempts[0]).total_seconds()) if valid_attempts else 0
                })
        return {"status": "success", "data": rate_limit_data, "meta": {"max_attempts": MAX_ATTEMPTS, "window_seconds": RATE_LIMIT_WINDOW}}
    except Exception as e:
        logger.error(f"Error retrieving rate limit data: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving rate limit data: {str(e)}")


@router.delete("/api/security/rate-limits/{ip}", dependencies=[Depends(authenticate)])
def clear_rate_limit(ip: str):
    try:
        if ip in auth_attempts:
            del auth_attempts[ip]
            return {"status": "success", "message": f"Rate limit cleared for IP {ip}"}
        else:
            raise HTTPException(status_code=404, detail=f"No active rate limit found for IP {ip}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing rate limit for IP {ip}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error clearing rate limit: {str(e)}")


@router.get("/api/security/score", dependencies=[Depends(authenticate)])
def get_security_score():
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute(
            'SELECT setting_name, setting_value FROM settings WHERE setting_name IN (?, ?, ?, ?, ?, ?, ?, ?)',
            ('enable_ip_blacklist', 'enable_domain_blacklist', 'block_direct_ip',
             'enable_content_filtering', 'enable_https_filtering', 'default_password_changed',
             'enable_time_restrictions', 'enable_waf'))
        settings = {row['setting_name']: row['setting_value'] for row in cursor.fetchall()}
    finally:
        db.close()

    score = 0
    recommendations = []

    checks = [
        ('enable_ip_blacklist', 15, 'Enable IP blacklisting to block known malicious IP addresses'),
        ('enable_domain_blacklist', 15, 'Enable domain blacklisting to block malicious websites'),
        ('block_direct_ip', 10, 'Enable direct IP access blocking to prevent bypassing domain filters'),
        ('enable_content_filtering', 10, 'Enable content filtering to block risky file types'),
        ('enable_waf', 25, 'Enable Outbound WAF (ICAP) to block SQLi, XSS, and Data Leaks'),
        ('enable_https_filtering', 15, 'Consider enabling HTTPS filtering for complete security coverage'),
        ('default_password_changed', 5, 'Change the default admin password to improve security'),
        ('enable_time_restrictions', 5, 'Enable time restrictions to limit proxy usage to working hours'),
    ]

    for key, points, recommendation in checks:
        if settings.get(key) == 'true':
            score += points
        else:
            recommendations.append(recommendation)

    return {"status": "success", "data": {"score": score, "max_score": 100, "recommendations": recommendations}}
