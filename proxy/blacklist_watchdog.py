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
    # Egress destination allowlists (default-deny mode). Enforced only when
    # /config/egress_default_deny exists; the lists sync regardless so a later
    # toggle picks them up on reconfigure.
    ("/config/dst_allow_ip.txt", "/etc/squid/allowlists/dst_ip/local.txt"),
    ("/config/dst_allow_domain.txt", "/etc/squid/allowlists/dst_domain/local.txt"),
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
    mtimes["/config/.reload-squid"] = mtime("/config/.reload-squid")
    mtimes["/config/.clear-cache"] = mtime("/config/.clear-cache")
    last_rotate_day = time.gmtime().tm_yday
    last_stats_time = 0
    print("[watchdog] started", flush=True)

    # Write Squid version at startup to /config/squid_version.txt
    try:
        res = subprocess.run(["/usr/sbin/squid", "-v"], capture_output=True, timeout=5, text=True)
        if res.returncode == 0:
            with open("/config/squid_version.txt", "w") as f:
                f.write(res.stdout)
    except Exception as exc:
        print(f"[watchdog] squid version check failed: {exc}", flush=True)

    while True:
        time.sleep(2)

        # Periodically dump Squid cache stats to a shared file in /config
        if time.time() - last_stats_time > 10:
            last_stats_time = time.time()
            try:
                res = subprocess.run(
                    ["/usr/sbin/squidclient", "-h", "127.0.0.1", "-p", "3128", "mgr:info"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                if res.returncode == 0:
                    with open("/config/cache_stats.txt", "w") as f:
                        f.write(res.stdout)
            except Exception as exc:
                print(f"[watchdog] stats extraction error: {exc}", flush=True)

        # Keep Squid logs world-readable for the backend tailer.
        for log in LOGS:
            try:
                os.chmod(log, 0o644)
            except OSError:
                pass

        # Daily log rotation (with logfile_rotate 5 in squid.conf this keeps
        # access/cache logs bounded instead of growing without limit).
        day = time.gmtime().tm_yday
        if day != last_rotate_day:
            last_rotate_day = day
            try:
                subprocess.run(["/usr/sbin/squid", "-k", "rotate"], capture_output=True, timeout=10)
                print("[watchdog] daily squid -k rotate", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[watchdog] rotate error: {exc}", flush=True)

        # Check reload-squid trigger
        mt_reload = mtime("/config/.reload-squid")
        if mt_reload != mtimes["/config/.reload-squid"]:
            mtimes["/config/.reload-squid"] = mt_reload
            if os.path.exists("/config/.reload-squid"):
                print("[watchdog] reload-squid trigger detected, regenerating config...", flush=True)
                try:
                    # Run the configuration generator script
                    gen_res = subprocess.run(["/usr/local/bin/generate_squid_conf.sh"], capture_output=True, timeout=30)
                    print(f"[watchdog] generate_squid_conf.sh rc={gen_res.returncode}", flush=True)
                    # Reconfigure Squid
                    rec_res = subprocess.run(["/usr/sbin/squid", "-k", "reconfigure"], capture_output=True, timeout=10)
                    print(f"[watchdog] squid reconfigure rc={rec_res.returncode}", flush=True)
                except Exception as exc:
                    print(f"[watchdog] reload error: {exc}", flush=True)

        # Check clear-cache trigger
        mt_clear = mtime("/config/.clear-cache")
        if mt_clear != mtimes["/config/.clear-cache"]:
            mtimes["/config/.clear-cache"] = mt_clear
            if os.path.exists("/config/.clear-cache"):
                print("[watchdog] clear-cache trigger detected, purging cache...", flush=True)
                try:
                    purge_res = subprocess.run(["/usr/sbin/squid", "-k", "purge"], capture_output=True, timeout=20)
                    print(f"[watchdog] squid -k purge rc={purge_res.returncode}", flush=True)
                    if purge_res.returncode != 0:
                        print("[watchdog] purge failed, trying fallback shutdown...", flush=True)
                        subprocess.run(["/usr/sbin/squid", "-k", "shutdown"], capture_output=True, timeout=20)
                except Exception as exc:
                    print(f"[watchdog] clear cache error: {exc}", flush=True)

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
