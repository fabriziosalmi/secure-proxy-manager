#!/usr/bin/env python3
"""Squid sidecar maintained by supervisord.

Two jobs, both on a 2-second tick:

1. Live blacklist reload. Watches the /config blacklist files the backend
   rewrites and, when one changes, copies it into the Squid ACL directory and
   runs `squid -k reconfigure` so new rules take effect without a container
   restart.

2. Log readability. Squid's log daemon creates access.log/cache.log mode 0640,
   recreating them on rotation. The backend runs in a separate container with a
   userns-remapped UID and cannot read 0640 (even as root), so it would ingest
   zero log lines and the dashboard / Logs page would stay empty. Re-assert
   0644 every tick.

This is shipped as a real file and registered statically in
squid-supervisor.conf (rather than generated at runtime) so supervisord always
picks it up on a fresh boot.
"""
import os
import subprocess
import time

# (source in /config written by the backend, destination Squid reads)
PAIRS = [
    ("/config/ip_blacklist.txt", "/etc/squid/blacklists/ip/local.txt"),
    ("/config/ip_whitelist.txt", "/etc/squid/whitelists/ip/local.txt"),
    ("/config/domain_blacklist.txt", "/etc/squid/blacklists/domain/local.txt"),
]

LOGS = [
    "/var/log/squid/access.log",
    "/var/log/squid/cache.log",
    "/var/log/squid/store.log",
]


def mtime(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def main():
    import shutil

    mtimes = {src: mtime(src) for src, _ in PAIRS}
    print("[watchdog] started", flush=True)

    while True:
        time.sleep(2)

        # Keep Squid logs world-readable for the backend tailer.
        for log in LOGS:
            try:
                os.chmod(log, 0o644)
            except OSError:
                pass

        # Sync changed blacklist files and reconfigure Squid.
        changed = False
        for src, dst in PAIRS:
            mt = mtime(src)
            if mt != mtimes[src]:
                mtimes[src] = mt
                if os.path.exists(src):
                    try:
                        shutil.copy2(src, dst)
                        changed = True
                        print(f"[watchdog] synced {src} -> {dst}", flush=True)
                    except OSError as exc:
                        print(f"[watchdog] copy failed: {exc}", flush=True)

        if changed:
            try:
                result = subprocess.run(
                    ["/usr/sbin/squid", "-k", "reconfigure"],
                    capture_output=True,
                    timeout=10,
                )
                print(f"[watchdog] squid reconfigure rc={result.returncode}", flush=True)
            except Exception as exc:  # noqa: BLE001 - log and keep running
                print(f"[watchdog] reconfigure error: {exc}", flush=True)


if __name__ == "__main__":
    main()
