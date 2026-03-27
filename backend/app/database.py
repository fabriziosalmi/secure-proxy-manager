import os
import sys
import logging
import sqlite3
from contextlib import contextmanager

from . import config
from .auth import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)


def get_db():
    """Get a SQLite connection with row factory."""
    conn = sqlite3.connect(config.DATABASE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db_ctx():
    """Context manager for database connections. Auto-closes on exit."""
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize database schema and seed the admin user."""
    data_dir = os.path.dirname(config.DATABASE_PATH)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)

    conn = get_db()
    try:
        conn.execute('PRAGMA journal_mode=WAL;')
    except sqlite3.OperationalError as e:
        logger.warning(f"Could not set WAL mode (might be read-only mount): {e}")

    # Integrity check on startup
    try:
        result = conn.execute('PRAGMA integrity_check;').fetchone()
        if result and result[0] == 'ok':
            logger.info("Database integrity check: OK")
        else:
            logger.error(f"Database integrity check FAILED: {result}")
    except sqlite3.Error as e:
        logger.error(f"Could not run integrity check: {e}")

    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        description TEXT,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ip_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        description TEXT,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS domain_blacklist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        description TEXT,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS domain_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        type TEXT DEFAULT 'fqdn',
        description TEXT,
        added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS proxy_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        method TEXT,
        destination TEXT,
        status TEXT,
        bytes INTEGER,
        unix_timestamp REAL
    )
    ''')

    # Migrate existing DBs: add columns that may not exist yet
    for col, col_type in [('source_ip', 'TEXT'), ('unix_timestamp', 'REAL'), ('method', 'TEXT')]:
        try:
            cursor.execute(f"ALTER TABLE proxy_logs ADD COLUMN {col} {col_type}")
            logger.info(f"Migration: added column proxy_logs.{col}")
        except sqlite3.OperationalError as e:
            if "duplicate column" in str(e).lower():
                pass  # Already exists
            else:
                logger.warning(f"Migration: could not add proxy_logs.{col}: {e}")

    # Add indexes for common query patterns
    for idx_name, idx_sql in [
        ("idx_proxy_logs_timestamp", "CREATE INDEX IF NOT EXISTS idx_proxy_logs_timestamp ON proxy_logs(timestamp)"),
        ("idx_proxy_logs_source_ip", "CREATE INDEX IF NOT EXISTS idx_proxy_logs_source_ip ON proxy_logs(source_ip)"),
        ("idx_proxy_logs_status", "CREATE INDEX IF NOT EXISTS idx_proxy_logs_status ON proxy_logs(status)"),
        ("idx_proxy_logs_destination", "CREATE INDEX IF NOT EXISTS idx_proxy_logs_destination ON proxy_logs(destination)"),
    ]:
        try:
            cursor.execute(idx_sql)
        except sqlite3.OperationalError as e:
            logger.warning(f"Could not create index {idx_name} (might be read-only): {e}")

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        setting_name TEXT UNIQUE NOT NULL,
        setting_value TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT (datetime('now')),
        username TEXT,
        action TEXT NOT NULL,
        target TEXT,
        details TEXT
    )
    ''')
    try:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
    except sqlite3.OperationalError:
        pass

    # Seed admin user from environment
    env_username = os.environ.get('BASIC_AUTH_USERNAME')
    env_password = os.environ.get('BASIC_AUTH_PASSWORD')

    if env_username and env_password:
        cursor.execute("SELECT password FROM users WHERE username = ?", (env_username,))
        row = cursor.fetchone()
        if row is None:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                          (env_username, generate_password_hash(env_password)))
        elif not check_password_hash(row['password'], env_password):
            # Only re-hash if password changed or hash is a legacy format (scrypt/pbkdf2)
            cursor.execute("UPDATE users SET password = ? WHERE username = ?",
                         (generate_password_hash(env_password), env_username))
    else:
        logger.error("CRITICAL SECURITY ERROR: BASIC_AUTH_USERNAME and BASIC_AUTH_PASSWORD environment variables are not set.")
        sys.exit(1)

    conn.commit()
    conn.close()


def audit(username: str, action: str, target: str = "", details: str = ""):
    """Record an action in the audit log."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (username, action, target, details) VALUES (?, ?, ?, ?)",
            (username, action, target, details[:500])
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Audit log write failed: {e}")


def export_blacklists_to_files():
    """Export current database blacklists and whitelists to the text files used by squid."""
    try:
        conn = get_db()
        cursor = conn.cursor()

        os.makedirs('/config', exist_ok=True)

        cursor.execute("SELECT ip FROM ip_blacklist")
        with open('/config/ip_blacklist.txt', 'w') as f:
            for row in cursor.fetchall():
                f.write(f"{row['ip']}\n")

        cursor.execute("SELECT ip FROM ip_whitelist")
        with open('/config/ip_whitelist.txt', 'w') as f:
            for row in cursor.fetchall():
                f.write(f"{row['ip']}\n")

        cursor.execute("SELECT domain FROM domain_blacklist")
        domains = [row['domain'] for row in cursor.fetchall()]
        with open('/config/domain_blacklist.txt', 'w') as f:
            for d in domains:
                f.write(f"{d}\n")

        # Load domain whitelist (FQDN entries bypass the DNS blackhole)
        whitelisted_domains = set()
        try:
            cursor.execute("SELECT domain FROM domain_whitelist WHERE type = 'fqdn'")
            for row in cursor.fetchall():
                whitelisted_domains.add(row['domain'].strip().lower())
        except sqlite3.OperationalError:
            pass  # Table may not exist yet on first run

        # Generate dnsmasq blocklist for DNS blackhole (L3 blocking)
        os.makedirs('/config/dnsmasq.d', exist_ok=True)
        blocked_count = 0
        with open('/config/dnsmasq.d/blocklist.conf', 'w') as f:
            f.write("# Auto-generated by Secure Proxy Manager\n")
            f.write(f"# Whitelisted domains excluded: {len(whitelisted_domains)}\n")
            for d in domains:
                d = d.strip()
                if d and not d.startswith('#') and d.lower() not in whitelisted_domains:
                    f.write(f"address=/{d}/0.0.0.0\n")
                    f.write(f"address=/{d}/::\n")
                    blocked_count += 1
        logger.info(f"DNS blocklist generated: {blocked_count} domains blocked ({len(whitelisted_domains)} whitelisted)")

        conn.close()
        logger.info("Successfully exported database lists to config files")
    except sqlite3.Error as e:
        logger.error(f"Failed to export lists to files (database error): {e}")
    except OSError as e:
        logger.error(f"Failed to export lists to files (filesystem error): {e}")
