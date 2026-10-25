#!/usr/bin/env bash
# The /config volume is a contract of filenames between three languages, and
# nothing compared the copies.
#
# The backend writes the list files (Go), the watchdog copies them into Squid's
# ACL directories (Python), and the generator copies them again at boot (shell).
# Rename or add one on the Go side and both proxy-side copiers keep looking for
# the old name: the database and the UI show the entry, Squid never enforces it,
# and no test fails — the divergence lives in the enforcement path and is
# silent (SECURE-ARCH-02).
#
# This is the same shape as scripts/check-waf-keys.sh, which already gates a
# different cross-file contract. Portable to bash 3.2 (macOS): no associative
# arrays.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
R="\033[0;31m"; G="\033[0;32m"; N="\033[0m"
fail=0

# The names the backend exports, from the export function itself.
go_names="$(grep -oE 'configDir\+"/[a-z_]+\.txt"' backend-go/internal/database/db.go \
            | sed 's|.*/||; s|"||' | sort -u)"

# The sources the watchdog copies, from its PAIRS table. The sources are written
# as f"{CONFIG_DIR}/name.txt" (one constant for the directory, so the manifest
# path can share it); the literal "/config/name.txt" form is still accepted.
py_names="$(sed -n '/^PAIRS = \[/,/^\]/p' proxy/blacklist_watchdog.py \
            | grep -oE '(\{CONFIG_DIR\}|"/config)/[a-z_]+\.txt' | sed 's|.*/||' | sort -u)"

# The sources the generator copies. Since the boot copy goes through the
# watchdog's verified sync (blacklist_watchdog.py --sync-lists, which copies
# PAIRS against the backend's manifest), the generator consumes exactly the
# watchdog's names; it must call that sync on a non-comment line, and must not
# copy an exported list itself, which would bypass the manifest check.
if grep -vE '^[[:space:]]*#' proxy/generate_squid_conf.sh | grep -q -- '--sync-lists'; then
    sh_names="$py_names"
    for n in $go_names; do
        if grep -vE '^[[:space:]]*#' proxy/generate_squid_conf.sh | grep -qE "cp [^|;]*/config/${n}"; then
            printf "${R}BYPASS${N}: generate_squid_conf.sh copies %s with cp instead of the verified sync\n" "$n"
            fail=1
        fi
    done
else
    sh_names="$(grep -vE '^[[:space:]]*#' proxy/generate_squid_conf.sh \
                | grep -oE '/config/[a-z_]+\.txt' | sed 's|.*/||' | sort -u)"
fi

[ -n "$go_names" ] || { printf "${R}FAIL${N}: found no exported filenames in db.go — has the export moved?\n"; exit 1; }
[ -n "$py_names" ] || { printf "${R}FAIL${N}: found no PAIRS entries in blacklist_watchdog.py\n"; exit 1; }
[ -n "$sh_names" ] || { printf "${R}FAIL${N}: generate_squid_conf.sh neither calls --sync-lists nor copies any /config/*.txt\n"; exit 1; }

# Every file the backend writes must be consumed by both copiers. The reverse is
# not required: the generator also references files the backend does not export
# (custom_squid_extra.conf and friends live outside this list by design).
for n in $go_names; do
    if ! grep -qx "$n" <<<"$py_names"; then
        printf "${R}MISSING${N}: the backend exports %s but blacklist_watchdog.py's PAIRS does not copy it\n" "$n"
        fail=1
    fi
    if ! grep -qx "$n" <<<"$sh_names"; then
        printf "${R}MISSING${N}: the backend exports %s but generate_squid_conf.sh does not copy it\n" "$n"
        fail=1
    fi
done

# And a name the copiers expect that the backend no longer writes is a stale
# reference: Squid would keep enforcing whatever is left on disk.
for n in $py_names; do
    if ! grep -qx "$n" <<<"$go_names"; then
        printf "${R}STALE${N}: blacklist_watchdog.py copies %s, which the backend does not export\n" "$n"
        fail=1
    fi
done

if [ "$fail" -eq 0 ]; then
    count=$(wc -w <<<"$go_names" | tr -d ' ')
    printf "${G}OK${N}: the %s /config filenames agree across db.go, blacklist_watchdog.py and generate_squid_conf.sh\n" "$count"
fi
exit "$fail"
