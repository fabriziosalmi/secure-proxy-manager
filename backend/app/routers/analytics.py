import io
import logging
import sqlite3
from datetime import datetime, timedelta

import requests
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response

from ..auth import authenticate
from ..config import PROXY_HOST
from ..database import get_db

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/api/status", dependencies=[Depends(authenticate)])
def get_status():
    """Get the current status of the proxy service."""
    try:
        response = requests.get(f"http://{PROXY_HOST}:3128",
                               proxies={"http": f"http://{PROXY_HOST}:3128"},
                               timeout=1)
        proxy_status = "running" if response.status_code == 400 else "error"
    except requests.exceptions.RequestException:
        proxy_status = "error"

    stats = {
        "proxy_status": proxy_status,
        "proxy_host": PROXY_HOST,
        "proxy_port": "3128",
        "timestamp": datetime.now().isoformat(),
        "version": "1.5.0"
    }

    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute(
            "SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= ? AND timestamp < date(?, '+1 day')",
            (today, today))
        result = cursor.fetchone()
        stats["requests_count"] = result[0] if result else 0
    except sqlite3.Error as e:
        logger.warning(f"Could not fetch request count: {e}")
        stats["requests_count"] = 0
    finally:
        if conn:
            conn.close()

    stats["memory_usage"] = "N/A"
    stats["cpu_usage"] = "N/A"
    stats["uptime"] = "N/A"

    return {"status": "success", "data": stats}


@router.get("/api/traffic/statistics", dependencies=[Depends(authenticate)])
def get_traffic_statistics(period: str = 'day'):
    conn = None
    try:
        end_time = datetime.now()
        if period == 'hour':
            start_time = end_time - timedelta(hours=1)
            interval = 'strftime("%Y-%m-%d %H:%M", timestamp)'
            interval_format = '%Y-%m-%d %H:%M'
            delta = timedelta(minutes=5)
        elif period == 'day':
            start_time = end_time - timedelta(days=1)
            interval = 'strftime("%Y-%m-%d %H", timestamp)'
            interval_format = '%Y-%m-%d %H'
            delta = timedelta(hours=1)
        elif period == 'week':
            start_time = end_time - timedelta(weeks=1)
            interval = 'strftime("%Y-%m-%d", timestamp)'
            interval_format = '%Y-%m-%d'
            delta = timedelta(days=1)
        elif period == 'month':
            start_time = end_time - timedelta(days=30)
            interval = 'strftime("%Y-%m-%d", timestamp)'
            interval_format = '%Y-%m-%d'
            delta = timedelta(days=1)
        else:
            raise HTTPException(status_code=400, detail="Invalid period parameter")

        intervals = []
        current = start_time
        while current <= end_time:
            intervals.append(current.strftime(interval_format))
            current += delta

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(f"""
                SELECT {interval} as bucket,
                       COUNT(*) as total,
                       SUM(CASE WHEN status LIKE '%DENIED%' OR status LIKE '%BLOCKED%' THEN 1 ELSE 0 END) as blocked
                FROM proxy_logs WHERE timestamp >= ? GROUP BY bucket
            """, (start_time.strftime('%Y-%m-%d %H:%M:%S'),))
            bucket_map = {row['bucket']: row for row in cursor.fetchall()}
        except sqlite3.OperationalError as e:
            logger.warning(f"Traffic statistics query failed: {e}")
            bucket_map = {}

        labels = intervals
        inbound = [bucket_map[lbl]['total'] if lbl in bucket_map else 0 for lbl in labels]
        outbound = [0] * len(labels)
        blocked = [bucket_map[lbl]['blocked'] if lbl in bucket_map else 0 for lbl in labels]

        return {"status": "success", "data": {"labels": labels, "inbound": inbound, "outbound": outbound, "blocked": blocked}}
    except sqlite3.Error as e:
        logger.error(f"Error getting traffic statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            conn.close()


@router.get("/api/clients/statistics", dependencies=[Depends(authenticate)])
def client_statistics():
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT source_ip as ip_address, COUNT(*) as requests, 'Active' as status
                FROM proxy_logs WHERE source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip ORDER BY requests DESC LIMIT 50
            """)
            clients = [dict(row) for row in cursor.fetchall()]
            cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM proxy_logs WHERE source_ip IS NOT NULL AND source_ip != ''")
            total_clients = cursor.fetchone()[0] or 0
        except sqlite3.OperationalError as e:
            logger.warning(f"Client statistics query failed: {e}")
            clients = []
            total_clients = 0
        return {"status": "success", "data": {"total_clients": total_clients, "clients": clients}}
    except sqlite3.Error as e:
        logger.error(f"An error occurred while fetching client statistics: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching client statistics")
    finally:
        if conn:
            conn.close()


@router.get("/api/domains/statistics", dependencies=[Depends(authenticate)])
def domain_statistics():
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT destination as domain_name, COUNT(*) as requests,
                       SUM(CASE WHEN status LIKE '%DENIED%' OR status LIKE '%BLOCKED%' OR status LIKE '%403%' THEN 1 ELSE 0 END) as blocked_requests
                FROM proxy_logs WHERE destination IS NOT NULL AND destination != ''
                GROUP BY destination ORDER BY requests DESC LIMIT 50
            """)
            domains_raw = [dict(row) for row in cursor.fetchall()]
            cursor.execute("SELECT domain FROM domain_blacklist")
            blacklisted_domains = [row['domain'] for row in cursor.fetchall()]
        except sqlite3.OperationalError as e:
            logger.warning(f"Domain statistics query failed: {e}")
            domains_raw = []
            blacklisted_domains = []

        # Convert blacklist to set for O(1) exact lookup + collect wildcards separately
        bl_exact = set(blacklisted_domains)
        bl_wildcards = [bl[2:] for bl in blacklisted_domains if bl.startswith('*.')]

        domains = []
        for domain in domains_raw:
            domain_name = domain['domain_name']
            is_blocked = (
                domain_name in bl_exact
                or any(domain_name.endswith(w) for w in bl_wildcards)
                or domain.get('blocked_requests', 0) > 0
            )
            domains.append({'domain_name': domain_name, 'requests': domain['requests'], 'status': 'Blocked' if is_blocked else 'Allowed'})

        return {"status": "success", "data": domains}
    except sqlite3.Error as e:
        logger.error(f"An error occurred while fetching domain statistics: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching domain statistics")
    finally:
        if conn:
            conn.close()


@router.get("/api/cache/statistics", dependencies=[Depends(authenticate)])
def get_cache_statistics():
    return {
        "status": "success",
        "data": {
            "hit_rate": 0, "byte_hit_rate": 0, "cache_size": "N/A",
            "max_cache_size": "N/A", "objects_cached": 0, "simulated": True
        }
    }


@router.get("/api/analytics/report/pdf", dependencies=[Depends(authenticate)])
def download_pdf_report():
    conn = None
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet

        conn = get_db()
        cursor = conn.cursor()
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        elements.append(Paragraph("Secure Proxy Manager - Security Report", styles['Title']))
        elements.append(Spacer(1, 12))

        try:
            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= date('now', '-7 days')")
            total_reqs = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '403%' AND timestamp >= date('now', '-7 days')")
            total_blocks = cursor.fetchone()[0]
        except sqlite3.OperationalError as e:
            logger.warning(f"PDF report query failed: {e}")
            total_reqs = 0
            total_blocks = 0

        elements.append(Paragraph("Summary (Last 7 Days)", styles['Heading2']))
        data = [["Metric", "Value"], ["Total Requests", str(total_reqs)], ["Blocked Requests", str(total_blocks)]]
        t = Table(data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)
        doc.build(elements)
        pdf_data = buffer.getvalue()
        buffer.close()

        return Response(
            content=pdf_data,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.now().strftime('%Y%m%d')}.pdf"}
        )
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")
    finally:
        if conn:
            conn.close()


@router.get("/api/waf/stats", dependencies=[Depends(authenticate)])
def get_waf_stats():
    """Proxy WAF traffic intelligence stats from the Go ICAP server."""
    try:
        resp = requests.get("http://waf:8080/stats", timeout=3)
        if resp.status_code == 200:
            return {"status": "success", "data": resp.json()}
        raise HTTPException(status_code=502, detail="WAF stats unavailable")
    except requests.RequestException as e:
        logger.error(f"Error fetching WAF stats: {e}")
        raise HTTPException(status_code=502, detail="WAF service unreachable")


@router.post("/api/counters/reset", dependencies=[Depends(authenticate)])
def reset_all_counters():
    """Reset all counters: clear proxy logs DB + reset WAF stats."""
    import sqlite3 as _sqlite3
    results = {}

    # Clear proxy logs
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM proxy_logs")
        deleted = cursor.rowcount
        conn.commit()
        results["logs_cleared"] = deleted
    except _sqlite3.Error as e:
        logger.error(f"Error clearing proxy logs: {e}")
        results["logs_error"] = str(e)
    finally:
        if conn:
            conn.close()

    # Reset WAF stats
    try:
        resp = requests.post("http://waf:8080/reset", timeout=3)
        results["waf_reset"] = resp.status_code == 200
    except requests.RequestException:
        results["waf_reset"] = False

    return {"status": "success", "message": "All counters reset", "data": results}


@router.get("/api/dashboard/summary", dependencies=[Depends(authenticate)])
def get_dashboard_summary():
    """Aggregated dashboard data in a single API call."""
    conn = None
    result = {}

    try:
        conn = get_db()
        cursor = conn.cursor()

        # Total + blocked counts
        cursor.execute("SELECT COUNT(*) FROM proxy_logs")
        result["total_requests"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%'")
        result["blocked_requests"] = cursor.fetchone()[0]

        # Today's requests
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= ?", (today,))
        result["today_requests"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%') AND timestamp >= ?", (today,))
        result["today_blocked"] = cursor.fetchone()[0]

        # Top blocked destinations (last 24h)
        cursor.execute("""
            SELECT destination, COUNT(*) as cnt FROM proxy_logs
            WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%')
            AND timestamp >= datetime('now', '-1 day')
            GROUP BY destination ORDER BY cnt DESC LIMIT 10
        """)
        result["top_blocked"] = [{"dest": r["destination"], "count": r[0] if isinstance(r[0], int) else r["cnt"]} for r in cursor.fetchall()]

        # Top client IPs (last 24h)
        cursor.execute("""
            SELECT source_ip, COUNT(*) as cnt FROM proxy_logs
            WHERE timestamp >= datetime('now', '-1 day') AND source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
        """)
        result["top_clients"] = [{"ip": r["source_ip"], "count": r["cnt"]} for r in cursor.fetchall()]

        # Threat categories (from WAF blocks, extract from destination patterns)
        cursor.execute("""
            SELECT
                CASE
                    WHEN destination LIKE '%.exe%' OR destination LIKE '%.dll%' THEN 'Malware'
                    WHEN destination LIKE '%phish%' OR destination LIKE '%login%fake%' THEN 'Phishing'
                    WHEN status LIKE '%DENIED%' AND destination LIKE '%:%' THEN 'Direct IP'
                    WHEN status LIKE '%403%' THEN 'WAF Block'
                    ELSE 'Policy'
                END as category,
                COUNT(*) as cnt
            FROM proxy_logs
            WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%')
            AND timestamp >= datetime('now', '-7 days')
            GROUP BY category ORDER BY cnt DESC
        """)
        result["threat_categories"] = [{"category": r["category"], "count": r["cnt"]} for r in cursor.fetchall()]

        # Blacklist counts
        cursor.execute("SELECT COUNT(*) FROM ip_blacklist")
        result["ip_blacklist_count"] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM domain_blacklist")
        result["domain_blacklist_count"] = cursor.fetchone()[0]

        # Recent blocks (last 10)
        cursor.execute("""
            SELECT timestamp, source_ip, method, destination, status FROM proxy_logs
            WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%'
            ORDER BY id DESC LIMIT 10
        """)
        result["recent_blocks"] = [dict(r) for r in cursor.fetchall()]

    except sqlite3.OperationalError as e:
        logger.warning(f"Dashboard summary query failed: {e}")
    finally:
        if conn:
            conn.close()

    # WAF stats (non-blocking)
    try:
        waf_resp = requests.get("http://waf:8080/stats", timeout=2)
        if waf_resp.status_code == 200:
            result["waf"] = waf_resp.json()
    except requests.RequestException:
        result["waf"] = None

    return {"status": "success", "data": result}


# ── Sprint 2: Intelligence endpoints ─────────────────────────────────

KNOWN_SAAS = {
    "dropbox.com": "Dropbox", "wetransfer.com": "WeTransfer", "mega.nz": "Mega",
    "mediafire.com": "MediaFire", "sendspace.com": "SendSpace",
    "drive.google.com": "Google Drive", "onedrive.live.com": "OneDrive",
    "icloud.com": "iCloud", "box.com": "Box",
    "slack.com": "Slack", "discord.com": "Discord", "telegram.org": "Telegram",
    "web.whatsapp.com": "WhatsApp Web",
    "notion.so": "Notion", "trello.com": "Trello", "asana.com": "Asana",
    "airtable.com": "Airtable", "monday.com": "Monday",
    "canva.com": "Canva", "figma.com": "Figma",
    "pastebin.com": "Pastebin", "hastebin.com": "Hastebin",
    "ngrok.io": "ngrok", "ngrok.com": "ngrok",
    "tailscale.com": "Tailscale", "zerotier.com": "ZeroTier",
    "anydesk.com": "AnyDesk", "teamviewer.com": "TeamViewer",
    "tor2web.org": "Tor2Web",
    "chatgpt.com": "ChatGPT", "claude.ai": "Claude", "gemini.google.com": "Gemini",
    "reddit.com": "Reddit", "facebook.com": "Facebook", "instagram.com": "Instagram",
    "tiktok.com": "TikTok", "twitter.com": "Twitter/X", "x.com": "Twitter/X",
    "youtube.com": "YouTube", "twitch.tv": "Twitch", "netflix.com": "Netflix",
    "spotify.com": "Spotify",
}


def _extract_domain(dest: str) -> str:
    """Extract domain from destination URL like 'http://example.com:443/path'."""
    d = dest
    for prefix in ("http://", "https://", "ftp://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
            break
    d = d.split("/")[0].split(":")[0]
    return d.lower()


@router.get("/api/analytics/shadow-it", dependencies=[Depends(authenticate)])
def shadow_it_detector():
    """Detect SaaS/cloud services accessed through the proxy."""
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT destination, COUNT(*) as cnt FROM proxy_logs
            WHERE destination IS NOT NULL AND destination != ''
            AND timestamp >= datetime('now', '-7 days')
            GROUP BY destination ORDER BY cnt DESC LIMIT 500
        """)
        rows = cursor.fetchall()
    except sqlite3.OperationalError as e:
        logger.warning(f"Shadow IT query failed: {e}")
        rows = []
    finally:
        if conn:
            conn.close()

    # Aggregate by SaaS service
    services: dict = {}
    for row in rows:
        domain = _extract_domain(row["destination"])
        for saas_domain, saas_name in KNOWN_SAAS.items():
            if domain == saas_domain or domain.endswith("." + saas_domain):
                if saas_name not in services:
                    services[saas_name] = {"name": saas_name, "domain": saas_domain, "requests": 0, "category": "unknown"}
                services[saas_name]["requests"] += row["cnt"]
                break

    # Categorize
    categories = {
        "File Sharing": ["Dropbox", "WeTransfer", "Mega", "MediaFire", "SendSpace", "Google Drive", "OneDrive", "iCloud", "Box"],
        "Messaging": ["Slack", "Discord", "Telegram", "WhatsApp Web"],
        "Productivity": ["Notion", "Trello", "Asana", "Airtable", "Monday", "Canva", "Figma"],
        "Paste/Code": ["Pastebin", "Hastebin"],
        "Tunneling": ["ngrok", "Tailscale", "ZeroTier", "AnyDesk", "TeamViewer", "Tor2Web"],
        "AI": ["ChatGPT", "Claude", "Gemini"],
        "Social": ["Reddit", "Facebook", "Instagram", "TikTok", "Twitter/X", "YouTube", "Twitch"],
        "Streaming": ["Netflix", "Spotify"],
    }
    for cat, names in categories.items():
        for name in names:
            if name in services:
                services[name]["category"] = cat

    result = sorted(services.values(), key=lambda x: x["requests"], reverse=True)
    return {"status": "success", "data": result}


@router.get("/api/analytics/user-agents", dependencies=[Depends(authenticate)])
def user_agent_breakdown():
    """Analyze User-Agent strings from proxy logs (extracted from destination patterns)."""
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        # Extract method distribution as proxy for UA (Squid logs don't store UA directly)
        # Instead we analyze the destination patterns to infer client types
        cursor.execute("""
            SELECT method, COUNT(*) as cnt FROM proxy_logs
            WHERE method IS NOT NULL AND method != '' AND method != '-'
            AND timestamp >= datetime('now', '-7 days')
            GROUP BY method ORDER BY cnt DESC
        """)
        methods = [{"name": r["method"], "count": r["cnt"]} for r in cursor.fetchall()]

        # Analyze destination patterns for client type inference
        cursor.execute("""
            SELECT
                CASE
                    WHEN destination LIKE '%googleapis.com%' OR destination LIKE '%google.com%' THEN 'Google Services'
                    WHEN destination LIKE '%microsoft.com%' OR destination LIKE '%office.com%' OR destination LIKE '%live.com%' THEN 'Microsoft'
                    WHEN destination LIKE '%apple.com%' OR destination LIKE '%icloud.com%' THEN 'Apple'
                    WHEN destination LIKE '%github.com%' OR destination LIKE '%gitlab%' THEN 'Dev Tools'
                    WHEN destination LIKE '%docker%' OR destination LIKE '%registry%' THEN 'Containers'
                    WHEN destination LIKE '%npm%' OR destination LIKE '%pypi%' OR destination LIKE '%maven%' THEN 'Package Managers'
                    WHEN destination LIKE '%cdn%' OR destination LIKE '%cloudflare%' OR destination LIKE '%akamai%' THEN 'CDN'
                    WHEN destination LIKE '%update%' OR destination LIKE '%patch%' THEN 'Updates'
                    ELSE 'Other'
                END as service_type,
                COUNT(*) as cnt
            FROM proxy_logs
            WHERE timestamp >= datetime('now', '-7 days') AND destination IS NOT NULL
            GROUP BY service_type ORDER BY cnt DESC
        """)
        service_types = [{"name": r["service_type"], "count": r["cnt"]} for r in cursor.fetchall()]

    except sqlite3.OperationalError as e:
        logger.warning(f"User agent breakdown query failed: {e}")
        methods = []
        service_types = []
    finally:
        if conn:
            conn.close()

    return {"status": "success", "data": {"methods": methods, "service_types": service_types}}


@router.get("/api/analytics/file-extensions", dependencies=[Depends(authenticate)])
def file_extension_distribution():
    """Analyze file extensions in proxied requests."""
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT destination FROM proxy_logs
            WHERE destination IS NOT NULL AND destination != ''
            AND timestamp >= datetime('now', '-7 days')
        """)
        rows = cursor.fetchall()
    except sqlite3.OperationalError as e:
        logger.warning(f"File extension query failed: {e}")
        rows = []
    finally:
        if conn:
            conn.close()

    import re
    ext_pattern = re.compile(r'\.([a-zA-Z0-9]{1,10})(?:\?|$|#)')
    ext_counts: dict = {}
    for row in rows:
        dest = row["destination"]
        # Strip query params for cleaner matching
        path = dest.split("?")[0].split("#")[0]
        match = ext_pattern.search(path)
        if match:
            ext = match.group(1).lower()
            # Skip common non-file extensions
            if ext in ("com", "net", "org", "io", "dev", "app", "me", "co"):
                continue
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

    # Categorize
    categories = {
        "Web": ["html", "htm", "css", "js", "jsx", "ts", "tsx", "woff", "woff2", "ttf", "svg", "ico", "webmanifest"],
        "Images": ["png", "jpg", "jpeg", "gif", "webp", "bmp", "avif", "tiff"],
        "Documents": ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf"],
        "Archives": ["zip", "tar", "gz", "bz2", "7z", "rar", "xz"],
        "Media": ["mp4", "mp3", "avi", "mkv", "wav", "ogg", "flac", "m4a"],
        "Code": ["py", "go", "rs", "java", "c", "cpp", "rb", "php", "sh", "yaml", "yml", "json", "xml", "toml"],
        "Executables": ["exe", "msi", "dmg", "deb", "rpm", "apk", "bin"],
        "Data": ["sql", "db", "sqlite", "bak", "dump"],
    }

    result = sorted(
        [{"ext": f".{k}", "count": v} for k, v in ext_counts.items()],
        key=lambda x: x["count"], reverse=True,
    )[:30]

    # Also return by category
    cat_counts: dict = {}
    for ext, count in ext_counts.items():
        cat = "Other"
        for cat_name, exts in categories.items():
            if ext in exts:
                cat = cat_name
                break
        cat_counts[cat] = cat_counts.get(cat, 0) + count

    cat_result = sorted(
        [{"category": k, "count": v} for k, v in cat_counts.items()],
        key=lambda x: x["count"], reverse=True,
    )

    return {"status": "success", "data": {"extensions": result, "categories": cat_result}}


@router.get("/api/analytics/top-domains", dependencies=[Depends(authenticate)])
def top_domains():
    """Top accessed domains for word cloud / domain analysis."""
    conn = None
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT destination, COUNT(*) as cnt FROM proxy_logs
            WHERE destination IS NOT NULL AND destination != ''
            AND timestamp >= datetime('now', '-7 days')
            GROUP BY destination ORDER BY cnt DESC LIMIT 200
        """)
        rows = cursor.fetchall()
    except sqlite3.OperationalError as e:
        logger.warning(f"Top domains query failed: {e}")
        rows = []
    finally:
        if conn:
            conn.close()

    # Aggregate by root domain
    domain_counts: dict = {}
    for row in rows:
        domain = _extract_domain(row["destination"])
        # Get root domain (last 2 parts)
        parts = domain.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        domain_counts[root] = domain_counts.get(root, 0) + row["cnt"]

    result = sorted(
        [{"domain": k, "count": v} for k, v in domain_counts.items()],
        key=lambda x: x["count"], reverse=True,
    )[:50]

    return {"status": "success", "data": result}
