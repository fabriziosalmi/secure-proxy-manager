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
        "version": "1.3.0"
    }

    try:
        conn = get_db()
        cursor = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        cursor.execute(
            "SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= ? AND timestamp < date(?, '+1 day')",
            (today, today))
        result = cursor.fetchone()
        stats["requests_count"] = result[0] if result else 0
        conn.close()
    except sqlite3.Error:
        stats["requests_count"] = 0

    stats["memory_usage"] = "N/A"
    stats["cpu_usage"] = "N/A"
    stats["uptime"] = "N/A"

    return {"status": "success", "data": stats}


@router.get("/api/traffic/statistics", dependencies=[Depends(authenticate)])
def get_traffic_statistics(period: str = 'day'):
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
        except sqlite3.OperationalError:
            bucket_map = {}

        labels = intervals
        inbound = [bucket_map[lbl]['total'] if lbl in bucket_map else 0 for lbl in labels]
        outbound = [0] * len(labels)
        blocked = [bucket_map[lbl]['blocked'] if lbl in bucket_map else 0 for lbl in labels]

        return {"status": "success", "data": {"labels": labels, "inbound": inbound, "outbound": outbound, "blocked": blocked}}
    except sqlite3.Error as e:
        logger.error(f"Error getting traffic statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/clients/statistics", dependencies=[Depends(authenticate)])
def client_statistics():
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
        except sqlite3.OperationalError:
            clients = []
            total_clients = 0
        conn.close()
        return {"status": "success", "data": {"total_clients": total_clients, "clients": clients}}
    except sqlite3.Error as e:
        logger.error(f"An error occurred while fetching client statistics: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching client statistics")


@router.get("/api/domains/statistics", dependencies=[Depends(authenticate)])
def domain_statistics():
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
        except sqlite3.OperationalError:
            domains_raw = []
            blacklisted_domains = []
        conn.close()

        domains = []
        for domain in domains_raw:
            domain_name = domain['domain_name']
            is_in_blacklist = domain_name in blacklisted_domains
            if not is_in_blacklist:
                for bl in blacklisted_domains:
                    if bl.startswith('*.') and domain_name.endswith(bl[2:]):
                        is_in_blacklist = True
                        break
            status = 'Blocked' if (is_in_blacklist or domain.get('blocked_requests', 0) > 0) else 'Allowed'
            domains.append({'domain_name': domain_name, 'requests': domain['requests'], 'status': status})

        return {"status": "success", "data": domains}
    except sqlite3.Error as e:
        logger.error(f"An error occurred while fetching domain statistics: {e}")
        raise HTTPException(status_code=500, detail="An error occurred while fetching domain statistics")


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
        except sqlite3.OperationalError:
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
        conn.close()

        return Response(
            content=pdf_data,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=security_report_{datetime.now().strftime('%Y%m%d')}.pdf"}
        )
    except Exception as e:
        logger.error(f"Error generating PDF report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")
