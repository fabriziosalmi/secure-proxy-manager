import logging
import sqlite3
import ipaddress
import urllib.parse
from datetime import datetime

import requests
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks

from ..auth import authenticate
from ..database import get_db
from ..models import IPBlacklistItem, DomainBlacklistItem, ImportBlacklistRequest, ImportGeoBlacklistRequest

logger = logging.getLogger(__name__)
router = APIRouter()


# ── IP Blacklist ──────────────────────────────────────────────────────────────

@router.get("/api/ip-blacklist", dependencies=[Depends(authenticate)])
def get_ip_blacklist(limit: int = 100, offset: int = 0, search: str = ""):
    conn = get_db()
    try:
        cursor = conn.cursor()
        if search:
            cursor.execute("SELECT COUNT(*) FROM ip_blacklist WHERE ip LIKE ? OR description LIKE ?",
                           (f"%{search}%", f"%{search}%"))
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM ip_blacklist WHERE ip LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                           (f"%{search}%", f"%{search}%", limit, offset))
        else:
            cursor.execute("SELECT COUNT(*) FROM ip_blacklist")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM ip_blacklist ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        blacklist = [dict(row) for row in cursor.fetchall()]
        return {"status": "success", "data": blacklist, "total": total, "limit": limit, "offset": offset}
    finally:
        conn.close()


@router.post("/api/ip-blacklist", dependencies=[Depends(authenticate)])
def add_ip_to_blacklist(item: IPBlacklistItem, background_tasks: BackgroundTasks):
    ip = item.ip.strip()
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM ip_blacklist WHERE ip = ?", (ip,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="IP address already in blacklist")

        try:
            cursor.execute("INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)", (ip, item.description))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to add IP to blacklist")

        background_tasks.add_task(logger.info, f"Added IP {ip} to blacklist")
        return {"status": "success", "message": "IP added to blacklist"}
    finally:
        conn.close()


@router.delete("/api/ip-blacklist/{id}", dependencies=[Depends(authenticate)])
def delete_ip_from_blacklist(id: int, background_tasks: BackgroundTasks):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ip_blacklist WHERE id = ?", (id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="IP not found in blacklist")
        conn.commit()
        background_tasks.add_task(logger.info, f"Removed IP id {id} from blacklist")
        return {"status": "success", "message": "IP removed from blacklist"}
    finally:
        conn.close()


@router.post("/api/ip-blacklist/bulk-delete", dependencies=[Depends(authenticate)])
def bulk_delete_ips(ids: list[int], background_tasks: BackgroundTasks):
    """Delete multiple IPs from blacklist at once."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(ids))
        cursor.execute(f"DELETE FROM ip_blacklist WHERE id IN ({placeholders})", ids)
        deleted = cursor.rowcount
        conn.commit()
        background_tasks.add_task(logger.info, f"Bulk deleted {deleted} IPs from blacklist")
        return {"status": "success", "message": f"Deleted {deleted} entries", "data": {"deleted": deleted}}
    finally:
        conn.close()


@router.post("/api/domain-blacklist/bulk-delete", dependencies=[Depends(authenticate)])
def bulk_delete_domains(ids: list[int], background_tasks: BackgroundTasks):
    """Delete multiple domains from blacklist at once."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        placeholders = ','.join('?' * len(ids))
        cursor.execute(f"DELETE FROM domain_blacklist WHERE id IN ({placeholders})", ids)
        deleted = cursor.rowcount
        conn.commit()
        background_tasks.add_task(logger.info, f"Bulk deleted {deleted} domains from blacklist")
        return {"status": "success", "message": f"Deleted {deleted} entries", "data": {"deleted": deleted}}
    finally:
        conn.close()


@router.delete("/api/ip-blacklist/clear-all", dependencies=[Depends(authenticate)])
def clear_all_ips(background_tasks: BackgroundTasks):
    """Delete ALL IPs from blacklist."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ip_blacklist")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM ip_blacklist")
        conn.commit()
        background_tasks.add_task(logger.info, f"Cleared all {count} IPs from blacklist")
        return {"status": "success", "message": f"Cleared {count} entries"}
    finally:
        conn.close()


@router.delete("/api/domain-blacklist/clear-all", dependencies=[Depends(authenticate)])
def clear_all_domains(background_tasks: BackgroundTasks):
    """Delete ALL domains from blacklist."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM domain_blacklist")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM domain_blacklist")
        conn.commit()
        background_tasks.add_task(logger.info, f"Cleared all {count} domains from blacklist")
        return {"status": "success", "message": f"Cleared {count} entries"}
    finally:
        conn.close()


# ── IP Whitelist ──────────────────────────────────────────────────────────────

@router.get("/api/ip-whitelist", dependencies=[Depends(authenticate)])
def get_ip_whitelist(limit: int = 100, offset: int = 0, search: str = ""):
    conn = get_db()
    try:
        cursor = conn.cursor()
        if search:
            cursor.execute("SELECT COUNT(*) FROM ip_whitelist WHERE ip LIKE ? OR description LIKE ?",
                           (f"%{search}%", f"%{search}%"))
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM ip_whitelist WHERE ip LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                           (f"%{search}%", f"%{search}%", limit, offset))
        else:
            cursor.execute("SELECT COUNT(*) FROM ip_whitelist")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM ip_whitelist ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        whitelist = [dict(row) for row in cursor.fetchall()]
        return {"status": "success", "data": whitelist, "total": total, "limit": limit, "offset": offset}
    finally:
        conn.close()


@router.post("/api/ip-whitelist", dependencies=[Depends(authenticate)])
def add_ip_to_whitelist(item: IPBlacklistItem, background_tasks: BackgroundTasks):
    ip = item.ip.strip()
    try:
        ipaddress.ip_network(ip, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP/Network format")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM ip_whitelist WHERE ip = ?", (ip,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="IP network already in whitelist")

        try:
            cursor.execute("INSERT INTO ip_whitelist (ip, description) VALUES (?, ?)", (ip, item.description))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to add IP to whitelist")

        background_tasks.add_task(logger.info, f"Added IP/Network {ip} to whitelist")
        return {"status": "success", "message": "IP added to whitelist"}
    finally:
        conn.close()


@router.delete("/api/ip-whitelist/{id}", dependencies=[Depends(authenticate)])
def delete_ip_from_whitelist(id: int, background_tasks: BackgroundTasks):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM ip_whitelist WHERE id = ?", (id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="IP not found in whitelist")
        conn.commit()
        background_tasks.add_task(logger.info, f"Removed IP id {id} from whitelist")
        return {"status": "success", "message": "IP removed from whitelist"}
    finally:
        conn.close()


# ── Domain Whitelist ─────────────────────────────────────────────────────────

@router.get("/api/domain-whitelist", dependencies=[Depends(authenticate)])
def get_domain_whitelist(limit: int = 100, offset: int = 0, search: str = ""):
    conn = get_db()
    try:
        cursor = conn.cursor()
        if search:
            cursor.execute("SELECT COUNT(*) FROM domain_whitelist WHERE domain LIKE ? OR description LIKE ?",
                           (f"%{search}%", f"%{search}%"))
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM domain_whitelist WHERE domain LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                           (f"%{search}%", f"%{search}%", limit, offset))
        else:
            cursor.execute("SELECT COUNT(*) FROM domain_whitelist")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM domain_whitelist ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        whitelist = [dict(row) for row in cursor.fetchall()]
    except sqlite3.OperationalError as e:
        logger.warning(f"Domain whitelist query failed: {e}")
        whitelist = []
        total = 0
    finally:
        conn.close()
    return {"status": "success", "data": whitelist, "total": total, "limit": limit, "offset": offset}


@router.post("/api/domain-whitelist", dependencies=[Depends(authenticate)])
def add_domain_to_whitelist(item: DomainBlacklistItem, background_tasks: BackgroundTasks):
    domain = item.domain.strip().lower()
    if not domain or ' ' in domain:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    # Determine type: if contains regex chars, it's url-regex; otherwise fqdn
    entry_type = 'url-regex' if any(c in domain for c in ['*', '?', '[', '(', '|', '\\']) else 'fqdn'
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM domain_whitelist WHERE domain = ?", (domain,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Domain already in whitelist")
        try:
            cursor.execute("INSERT INTO domain_whitelist (domain, type, description) VALUES (?, ?, ?)",
                          (domain, entry_type, item.description))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error adding domain to whitelist: {e}")
            raise HTTPException(status_code=500, detail=f"Database error: {e}")
        background_tasks.add_task(logger.info, f"Added {entry_type} {domain} to domain whitelist")
        return {"status": "success", "message": f"Domain added to whitelist (type: {entry_type})"}
    finally:
        conn.close()


@router.delete("/api/domain-whitelist/{id}", dependencies=[Depends(authenticate)])
def delete_domain_from_whitelist(id: int, background_tasks: BackgroundTasks):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM domain_whitelist WHERE id = ?", (id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Domain not found in whitelist")
        conn.commit()
        background_tasks.add_task(logger.info, f"Removed domain id {id} from whitelist")
        return {"status": "success", "message": "Domain removed from whitelist"}
    finally:
        conn.close()


# ── Domain Blacklist ──────────────────────────────────────────────────────────

@router.get("/api/domain-blacklist", dependencies=[Depends(authenticate)])
def get_domain_blacklist(limit: int = 100, offset: int = 0, search: str = ""):
    conn = get_db()
    try:
        cursor = conn.cursor()
        if search:
            cursor.execute("SELECT COUNT(*) FROM domain_blacklist WHERE domain LIKE ? OR description LIKE ?",
                           (f"%{search}%", f"%{search}%"))
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM domain_blacklist WHERE domain LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?",
                           (f"%{search}%", f"%{search}%", limit, offset))
        else:
            cursor.execute("SELECT COUNT(*) FROM domain_blacklist")
            total = cursor.fetchone()[0]
            cursor.execute("SELECT * FROM domain_blacklist ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
        blacklist = [dict(row) for row in cursor.fetchall()]
        return {"status": "success", "data": blacklist, "total": total, "limit": limit, "offset": offset}
    finally:
        conn.close()


@router.post("/api/domain-blacklist", dependencies=[Depends(authenticate)])
def add_domain_to_blacklist(item: DomainBlacklistItem, background_tasks: BackgroundTasks):
    domain = item.domain.strip().lower()
    if not domain or ' ' in domain or domain.startswith('-'):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    if domain.startswith('http://') or domain.startswith('https://'):
        try:
            parsed = urllib.parse.urlparse(domain)
            domain = parsed.netloc
        except Exception as e:
            logger.warning(f"Failed to parse domain URL: {e}")
            raise HTTPException(status_code=400, detail="Invalid domain format")

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM domain_blacklist WHERE domain = ?", (domain,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="Domain already in blacklist")

        try:
            cursor.execute("INSERT INTO domain_blacklist (domain, description) VALUES (?, ?)", (domain, item.description))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Database error: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to add domain to blacklist")

        background_tasks.add_task(logger.info, f"Added domain {domain} to blacklist")
        return {"status": "success", "message": "Domain added to blacklist"}
    finally:
        conn.close()


@router.delete("/api/domain-blacklist/{id}", dependencies=[Depends(authenticate)])
def delete_domain_from_blacklist(id: int, background_tasks: BackgroundTasks):
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM domain_blacklist WHERE id = ?", (id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Domain not found in blacklist")
        conn.commit()
        background_tasks.add_task(logger.info, f"Removed domain id {id} from blacklist")
        return {"status": "success", "message": "Domain removed from blacklist"}
    finally:
        conn.close()


# ── Import ────────────────────────────────────────────────────────────────────

@router.post("/api/blacklists/import", dependencies=[Depends(authenticate)])
def import_blacklist(request_data: ImportBlacklistRequest, background_tasks: BackgroundTasks):
    """Import blacklist entries from URL or direct content."""
    try:
        blacklist_type = request_data.type.lower()
        if blacklist_type not in ['ip', 'domain']:
            raise HTTPException(status_code=400, detail="Type must be 'ip' or 'domain'")

        content = None

        if request_data.url:
            # SSRF Protection
            parsed_url = urllib.parse.urlparse(request_data.url)
            if parsed_url.scheme not in ['http', 'https']:
                raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed")
            if not parsed_url.hostname:
                raise HTTPException(status_code=400, detail="Invalid URL: missing hostname")

            try:
                import socket as _socket
                try:
                    resolved_ip = _socket.gethostbyname(parsed_url.hostname)
                except _socket.gaierror:
                    raise HTTPException(status_code=400, detail="Unable to resolve hostname")
                ip_obj = ipaddress.ip_address(resolved_ip)
                if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                        or ip_obj.is_reserved or ip_obj.is_unspecified or ip_obj.is_multicast):
                    raise HTTPException(
                        status_code=403,
                        detail="Requests to private, loopback, link-local, or reserved networks are blocked"
                    )

                logger.info(f"Fetching blacklist from URL: {request_data.url}")
                headers = {'User-Agent': 'SecureProxyManager/1.0'}
                last_exc = None
                last_status = None
                for attempt in range(3):
                    try:
                        resp = requests.get(request_data.url, timeout=180, headers=headers, stream=True)
                        if resp.status_code == 200:
                            # Stream large files in chunks to avoid OOM
                            chunks = []
                            max_size = 200 * 1024 * 1024  # 200MB hard limit
                            downloaded = 0
                            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                                downloaded += len(chunk)
                                if downloaded > max_size:
                                    raise HTTPException(status_code=400, detail="File too large (>200MB)")
                                chunks.append(chunk)
                            content = b''.join(chunks).decode('utf-8', errors='ignore')
                            break
                        last_status = resp.status_code
                        logger.warning(f"Attempt {attempt+1}: HTTP {last_status} from {request_data.url}")
                    except HTTPException:
                        raise
                    except requests.exceptions.RequestException as exc:
                        last_exc = exc
                        logger.warning(f"Attempt {attempt+1} failed: {exc}")
                    if attempt < 2:
                        import time as _time
                        _time.sleep(2 ** attempt)
                if content is None:
                    detail = f"HTTP {last_status}" if last_status else str(last_exc)
                    raise HTTPException(status_code=400, detail=f"Failed to fetch URL after 3 attempts: {detail}")
            except HTTPException:
                raise
            except requests.exceptions.RequestException as e:
                logger.error(f"Error fetching URL: {str(e)}")
                raise HTTPException(status_code=400, detail=f"Error fetching URL: {str(e)}")
        elif request_data.content:
            content = request_data.content
        else:
            raise HTTPException(status_code=400, detail="Either 'url' or 'content' must be provided")

        if not content:
            raise HTTPException(status_code=400, detail="No content to process")

        lines = content.splitlines()
        entries_added = 0
        entries_skipped = 0

        conn = get_db()
        try:
            cursor = conn.cursor()

            table_name = "ip_blacklist" if blacklist_type == "ip" else "domain_blacklist"
            column_name = "ip" if blacklist_type == "ip" else "domain"

            to_insert = []
            existing_entries = set()

            cursor.execute(f"SELECT {column_name} FROM {table_name}")
            for row in cursor.fetchall():
                existing_entries.add(row[column_name])

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if not parts:
                    continue

                entry = parts[-1]

                if blacklist_type == 'ip':
                    try:
                        ipaddress.ip_network(entry, strict=False)
                        if entry not in existing_entries:
                            to_insert.append((entry, f"Imported on {datetime.now().strftime('%Y-%m-%d')}"))
                            existing_entries.add(entry)
                            entries_added += 1
                        else:
                            entries_skipped += 1
                    except ValueError:
                        entries_skipped += 1
                else:
                    if entry.startswith('http://') or entry.startswith('https://'):
                        try:
                            parsed = urllib.parse.urlparse(entry)
                            entry = parsed.netloc
                        except Exception as e:
                            logger.debug(f"Failed to parse URL during import: {e}")
                            entries_skipped += 1
                            continue

                    if '.' in entry and not entry.startswith('.') and not entry.endswith('.'):
                        if entry not in existing_entries:
                            to_insert.append((entry, f"Imported on {datetime.now().strftime('%Y-%m-%d')}"))
                            existing_entries.add(entry)
                            entries_added += 1
                        else:
                            entries_skipped += 1
                    else:
                        entries_skipped += 1

            # Batch insert in chunks to avoid huge transactions
            BATCH_SIZE = 5000
            for i in range(0, len(to_insert), BATCH_SIZE):
                batch = to_insert[i:i + BATCH_SIZE]
                cursor.executemany(
                    f"INSERT OR IGNORE INTO {table_name} ({column_name}, description) VALUES (?, ?)",
                    batch
                )
                conn.commit()
        finally:
            conn.close()

        background_tasks.add_task(logger.info, f"Imported {entries_added} {blacklist_type}s")

        return {
            "status": "success",
            "message": f"Successfully imported {entries_added} entries ({entries_skipped} skipped/invalid)",
            "data": {"added": entries_added, "skipped": entries_skipped}
        }

    except HTTPException:
        raise
    except sqlite3.Error as e:
        logger.error(f"Error during import: {str(e)}")
        raise HTTPException(status_code=500, detail="Import operation failed")


@router.post("/api/blacklists/import-geo", dependencies=[Depends(authenticate)])
def import_geo_blacklist(request_data: ImportGeoBlacklistRequest, background_tasks: BackgroundTasks):
    """Import IP blocks for specific countries."""
    try:
        if not request_data.countries:
            raise HTTPException(status_code=400, detail="No countries provided")

        conn = get_db()
        try:
            cursor = conn.cursor()

            total_imported = 0
            existing_ips = set()
            cursor.execute("SELECT ip FROM ip_blacklist")
            for row in cursor.fetchall():
                existing_ips.add(row['ip'])

            fetch_errors = []
            for country in request_data.countries:
                country = country.lower()
                urls_to_try = [
                    f"https://www.ipdeny.com/ipblocks/data/countries/{country}.zone",
                    f"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{country}.cidr",
                ]
                headers = {'User-Agent': 'SecureProxyManager/1.0'}
                content = None
                last_error = None

                for url in urls_to_try:
                    logger.info(f"Fetching GeoIP block for {country} from {url}")
                    try:
                        resp = requests.get(url, timeout=30, headers=headers)
                        if resp.status_code == 200:
                            content = resp.text
                            break
                        else:
                            last_error = f"HTTP {resp.status_code} from {url}"
                            logger.warning(last_error)
                    except requests.RequestException as e:
                        last_error = str(e)
                        logger.warning(f"Error fetching GeoIP for {country} from {url}: {e}")

                if content is None:
                    fetch_errors.append(f"{country.upper()}: {last_error}")
                    continue

                to_insert = []
                for line in content.splitlines():
                    ip = line.strip()
                    if ip and not ip.startswith('#') and ip not in existing_ips:
                        to_insert.append((ip, f"GeoIP: {country.upper()}"))
                        existing_ips.add(ip)
                        total_imported += 1

                if to_insert:
                    cursor.executemany(
                        "INSERT INTO ip_blacklist (ip, description) VALUES (?, ?)",
                        to_insert
                    )
                    conn.commit()

            if fetch_errors and total_imported == 0:
                raise HTTPException(
                    status_code=502,
                    detail=f"Failed to fetch GeoIP data: {'; '.join(fetch_errors)}"
                )
        finally:
            conn.close()
        background_tasks.add_task(logger.info, f"Imported {total_imported} GeoIP blocks")

        return {
            "status": "success",
            "message": f"Successfully imported {total_imported} IP blocks for {len(request_data.countries)} countries",
            "data": {"imported": total_imported}
        }
    except HTTPException:
        raise
    except sqlite3.Error as e:
        logger.error(f"Error during GeoIP import: {str(e)}")
        raise HTTPException(status_code=500, detail="GeoIP import operation failed")


# Legacy endpoints
@router.post("/api/ip-blacklist/import", dependencies=[Depends(authenticate)])
def import_ip_blacklist(request_data: ImportBlacklistRequest, background_tasks: BackgroundTasks):
    request_data.type = 'ip'
    return import_blacklist(request_data, background_tasks)


@router.post("/api/domain-blacklist/import", dependencies=[Depends(authenticate)])
def import_domain_blacklist(request_data: ImportBlacklistRequest, background_tasks: BackgroundTasks):
    request_data.type = 'domain'
    return import_blacklist(request_data, background_tasks)
