#!/usr/bin/env bash
# Restore a pre-upgrade backup taken by deploy/install.sh.
#
# SECURE-DATA-02: install.sh created data.bak.* directories and pruned them, and
# nothing anywhere ever read one back — there was no restore script, no restore
# test and no documented drill. An untested restore is not a backup.
set -euo pipefail

G="\033[0;32m"; R="\033[0;31m"; Y="\033[1;33m"; N="\033[0m"
ok()   { printf "${G}[OK]${N} %s\n" "$1"; }
warn() { printf "${Y}[WARN]${N} %s\n" "$1"; }
fail() { printf "${R}[FAIL]${N} %s\n" "$1"; exit 1; }

cd "$(dirname "$0")/.."

if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup-dir>"
    echo
    echo "Available backups:"
    ls -1dt data.bak.* 2>/dev/null | sed 's/^/  /' || echo "  (none)"
    exit 1
fi

BACKUP="$1"
[ -d "$BACKUP" ] || fail "no such backup: $BACKUP"
[ -f "$BACKUP/proxy_manager.db" ] || fail "$BACKUP does not contain proxy_manager.db"

# Verify BEFORE swapping: a backup that does not pass an integrity check is not
# a backup, and finding that out after replacing the live database is too late.
if command -v sqlite3 >/dev/null 2>&1; then
    res=$(sqlite3 "$BACKUP/proxy_manager.db" 'PRAGMA integrity_check' 2>&1 | head -1)
    [ "$res" = "ok" ] || fail "integrity check on the backup failed: $res"
    # integrity_check validates pages that hold data. It returns "ok" for
    # damage confined to a header or to free space — verified directly on a
    # 24KB database, where corruption at byte 2000 and 4200 is not detected and
    # 8300 is. So this is "structurally sound", not "byte-for-byte intact".
    ok "backup passes PRAGMA integrity_check (structural: pages and indexes)"
else
    warn "sqlite3 not installed — skipping the integrity check on the backup"
fi

echo "This will replace ./data with $BACKUP."
printf "Type 'restore' to continue: "
read -r reply
[ "$reply" = "restore" ] || fail "aborted"

docker compose down
if [ -d data ]; then
    aside="data.before-restore.$(date +%Y%m%d-%H%M%S)"
    mv data "$aside"
    ok "current data/ moved aside -> $aside"
fi
cp -a "$BACKUP" data
ok "restored $BACKUP -> data/"

docker compose up -d
ok "stack started; check: docker compose ps"
