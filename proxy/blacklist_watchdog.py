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
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time

CONFIG_DIR = "/config"

# (source in /config written by the backend, destination Squid reads)
PAIRS = [
    (f"{CONFIG_DIR}/ip_blacklist.txt", "/etc/squid/blacklists/ip/local.txt"),
    (f"{CONFIG_DIR}/ip_whitelist.txt", "/etc/squid/whitelists/ip/local.txt"),
    (f"{CONFIG_DIR}/domain_blacklist.txt", "/etc/squid/blacklists/domain/local.txt"),
    # Egress destination allowlists (default-deny mode). Enforced only when
    # /config/egress_default_deny exists; the lists sync regardless so a later
    # toggle picks them up on reconfigure.
    (f"{CONFIG_DIR}/dst_allow_ip.txt", "/etc/squid/allowlists/dst_ip/local.txt"),
    (f"{CONFIG_DIR}/dst_allow_domain.txt", "/etc/squid/allowlists/dst_domain/local.txt"),
]

# The backend writes this AFTER the lists above, with a sha256 for each. A list
# is copied into Squid's ACL directory only if the bytes being copied match it.
MANIFEST = f"{CONFIG_DIR}/lists.manifest.json"
MANIFEST_VERSION = 1
SHA256_HEX_LEN = 64

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


def trigger_stamp(path, fallback):
    """The stamp the backend wrote INTO the trigger file, as an int.

    The backend writes strconv.FormatInt(time.Now().Unix()) as the file's
    CONTENT and then waits for an acknowledgement carrying a trigger_mtime it
    can compare against that value. Reading the content rather than the file's
    mtime removes two failure modes at once: os.path.getmtime returns a float,
    and Go's encoding/json refuses any float for the int64 field it decodes
    into — so every acknowledgement failed to parse and the endpoint could only
    ever answer "pending" (SECURE-API-01). Using the content also makes the
    comparison independent of filesystem timestamp granularity and of any skew
    between the writer's clock and the file's recorded mtime.
    """
    try:
        with open(path) as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return int(fallback)


def resolved_ips():
    """Current IPs of the dns + waf service names (via Docker's embedded DNS).

    squid bakes these IPs into squid.conf at config-generation time
    (dns_nameservers for dnsmasq, the ICAP service URL for the WAF). When those
    containers are recreated they get NEW IPs, leaving squid pointing at dead
    addresses — 502 on every request (dns) or ICAP failures (waf). We track the
    resolved IPs so the loop can detect that drift and regenerate in place.
    """
    ips = []
    for name in ("dns", "waf"):
        try:
            ips.append(socket.gethostbyname(name))
        except OSError:
            ips.append("")
    return ",".join(ips)


HEARTBEAT = "/var/log/squid/watchdog.heartbeat"


def write_result(trigger, trigger_mtime, gen_rc, reconf_rc):
    """Acknowledge a trigger so the backend can tell whether it was applied.

    The backend touches /config/.reload-squid and reports success to the API
    caller as soon as the file is written — whether the watchdog is alive,
    whether the generator succeeded and whether squid accepted the config were
    all invisible to it, so a user toggling egress default-deny saw a success
    toast regardless of whether the rule reached Squid (SECURE-ARCH-02).

    The result carries the trigger's own mtime, so the backend can tell an
    acknowledgement of ITS request from one for an earlier trigger.
    """
    path = f"/config/.{trigger}.result"
    payload = {
        # Always an int: Go decodes this into an int64 and encoding/json
        # refuses any JSON float for an integer field (SECURE-API-01).
        "trigger_mtime": int(trigger_mtime),
        "generator_rc": gen_rc,
        "reconfigure_rc": reconf_rc,
        "applied": gen_rc == 0 and reconf_rc == 0,
        "at": int(time.time()),
    }
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(payload, f)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"[watchdog] could not write {path}: {exc}", flush=True)


class _HashingWriter:
    """Pass writes through to a file while feeding the same bytes to a hash."""

    def __init__(self, fh, digest):
        self._fh = fh
        self._digest = digest

    def write(self, chunk):
        self._digest.update(chunk)
        return self._fh.write(chunk)


class ChecksumMismatch(Exception):
    """The bytes read from a list do not match what the manifest promises."""


def load_manifest(path=None):
    """Read the lists manifest.

    Returns ("missing", None) when there is none — a backend that predates the
    manifest, or the first moments after boot — ("invalid", reason) when it
    exists but cannot be trusted, and ("ok", {filename: sha256}) otherwise.
    A manifest that exists and is unreadable is NOT treated as missing: that
    would turn a corrupted file into permission to skip verification.
    """
    path = path or MANIFEST
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        return "missing", None
    except (OSError, ValueError) as exc:
        return "invalid", f"unreadable: {exc}"
    if not isinstance(doc, dict) or doc.get("version") != MANIFEST_VERSION:
        return "invalid", f"unsupported version {doc.get('version') if isinstance(doc, dict) else doc!r}"
    files = doc.get("files")
    if not isinstance(files, dict):
        return "invalid", "no files table"
    sums = {}
    for name, entry in files.items():
        sha = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(sha, str) or len(sha) != SHA256_HEX_LEN:
            return "invalid", f"bad checksum for {name}"
        sums[name] = sha
    return "ok", sums


def atomic_copy(src, dst, expected_sha256=None):
    """Copy src onto dst without dst ever being observed partially written.

    With expected_sha256, the copy is hashed as it streams and is published
    only if it matches; otherwise the temporary file is removed, dst keeps its
    previous contents and ChecksumMismatch is raised. Hashing the bytes that
    are copied, not re-reading the source, means there is no window between
    checking a file and using it.

    shutil.copy2 opens the destination with 'wb', truncating it, then streams —
    so a `squid -k reconfigure` landing mid-stream loaded a truncated blacklist,
    and a kill mid-stream left one on disk permanently. Writing to a temporary
    file in the same directory and renaming makes the swap atomic
    (SECURE-DATA-03).
    """
    d = os.path.dirname(dst) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=os.path.basename(dst) + ".tmp")
    try:
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as out, open(src, "rb") as inp:
            shutil.copyfileobj(inp, _HashingWriter(out, digest))
            out.flush()
            os.fsync(out.fileno())
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise ChecksumMismatch(
                f"{os.path.basename(src)}: got {digest.hexdigest()[:12]}..., manifest says {expected_sha256[:12]}...")
        shutil.copystat(src, tmp)
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def squid_config_ok():
    """Whether squid accepts the current config. Used as a gate before
    reconfigure, so an unparsable ACL set is refused rather than loaded."""
    try:
        res = subprocess.run(["/usr/sbin/squid", "-k", "parse"],
                             check=False, capture_output=True, timeout=15)
        return res.returncode == 0
    except Exception as exc:  # noqa: BLE001
        print(f"[watchdog] squid -k parse failed to run: {exc}", flush=True)
        return False


def note_refusal(refused, src, mt, reason):
    """Log a refused list once per (file mtime, manifest mtime), not every poll."""
    key = (mt, mtime(MANIFEST))
    if refused.get(src) != key:
        refused[src] = key
        print(f"[watchdog] REFUSED {src}: {reason}; Squid keeps the previous list", flush=True)


RELOAD_TRIGGER = f"{CONFIG_DIR}/.reload-squid"
CLEAR_CACHE_TRIGGER = f"{CONFIG_DIR}/.clear-cache"
SQUID = "/usr/sbin/squid"
GENERATOR = "/usr/local/bin/generate_squid_conf.sh"


class WatchdogState:
    """What the poll loop remembers between two-second ticks."""

    def __init__(self):
        self.mtimes = {src: mtime(src) for src, _ in PAIRS}
        self.mtimes[RELOAD_TRIGGER] = mtime(RELOAD_TRIGGER)
        self.mtimes[CLEAR_CACHE_TRIGGER] = mtime(CLEAR_CACHE_TRIGGER)
        # (file mtime, manifest mtime) at which each list was last refused, so a
        # refusal is logged once per state and not every poll.
        self.refused = {}
        self.last_rotate_day = time.gmtime().tm_yday
        # Baseline = the IPs squid was configured with at startup (startup.sh
        # ran generate_squid_conf.sh against the same resolution).
        self.resolv_fp = resolved_ips()


def write_squid_version():
    """Write the Squid version at startup to /config/squid_version.txt."""
    try:
        res = subprocess.run([SQUID, "-v"], check=False, capture_output=True, timeout=5, text=True)
        if res.returncode == 0:
            with open(f"{CONFIG_DIR}/squid_version.txt", "w") as f:
                f.write(res.stdout)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[watchdog] squid version check failed: {exc}", flush=True)


def touch_heartbeat():
    """Liveness heartbeat. The container healthcheck reads this file's mtime,
    because the watchdog is the only path by which a configuration change
    reaches Squid and its death was otherwise invisible: the healthcheck
    probed squid, which keeps serving, so the container stayed "healthy"
    while every change silently stopped applying (SECURE-REL-01).
    It must be touched every poll, not only when something happens —
    a quiet system is not a dead one.
    """
    try:
        with open(HEARTBEAT, "w") as hb:
            hb.write(str(int(time.time())))
    except OSError:
        pass


def heal_resolver_drift(state):
    """Self-heal stale dnsmasq/waf IPs: if either service was recreated and got
    a new IP, squid's baked dns_nameservers / ICAP URL now point at a dead
    address (502 on every request, or ICAP failures). Regenerate the config
    (re-resolves both) and reconfigure in place. Guard on both being resolvable
    so a transient lookup miss doesn't trigger a needless reload.
    """
    fp = resolved_ips()
    if fp == state.resolv_fp or not all(fp.split(",")):
        return
    print(f"[watchdog] resolver drift {state.resolv_fp} -> {fp}, regenerating config...", flush=True)
    try:
        subprocess.run([GENERATOR], check=False, capture_output=True, timeout=30)
        subprocess.run([SQUID, "-k", "reconfigure"], check=False, capture_output=True, timeout=10)
        state.resolv_fp = fp
    except Exception as exc:  # noqa: BLE001
        print(f"[watchdog] resolver-drift reload error: {exc}", flush=True)


def keep_logs_readable():
    """Keep Squid logs world-readable for the backend tailer."""
    for log in LOGS:
        try:
            os.chmod(log, 0o644)
        except OSError:
            pass


def rotate_logs_daily(state):
    """Daily log rotation (with logfile_rotate 5 in squid.conf this keeps
    access/cache logs bounded instead of growing without limit)."""
    day = time.gmtime().tm_yday
    if day == state.last_rotate_day:
        return
    state.last_rotate_day = day
    try:
        subprocess.run([SQUID, "-k", "rotate"], check=False, capture_output=True, timeout=10)
        print("[watchdog] daily squid -k rotate", flush=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[watchdog] rotate error: {exc}", flush=True)


def regenerate_and_reconfigure(stamp):
    """Regenerate squid.conf and reconfigure, acknowledging the trigger.

    Returns True when the attempt ran to completion (whatever its result, which
    is what the acknowledgement carries) and False when it raised, so the caller
    leaves the trigger unconsumed and the next poll retries.
    """
    try:
        gen_res = subprocess.run([GENERATOR], check=False, capture_output=True, timeout=30)
        print(f"[watchdog] generate_squid_conf.sh rc={gen_res.returncode}", flush=True)
        # A failed generation leaves squid.conf part-mutated — the base was
        # already copied over it, so the egress default-deny may be missing.
        # Applying that is a fail-OPEN. Keep the running config instead
        # (SECURE-ERR-07).
        if gen_res.returncode != 0:
            print("[watchdog] generation FAILED — keeping the running config, not reconfiguring", flush=True)
            print(gen_res.stderr.decode("utf-8", "replace")[:2000], flush=True)
            write_result("reload-squid", stamp, gen_res.returncode, None)
        elif not squid_config_ok():
            print("[watchdog] generated config does not parse — refusing to reconfigure", flush=True)
            write_result("reload-squid", stamp, 0, 1)
        else:
            rec_res = subprocess.run([SQUID, "-k", "reconfigure"], check=False, capture_output=True, timeout=10)
            print(f"[watchdog] squid reconfigure rc={rec_res.returncode}", flush=True)
            write_result("reload-squid", stamp, gen_res.returncode, rec_res.returncode)
        return True
    except (OSError, subprocess.SubprocessError) as exc:
        # Narrow, and it reports rather than absorbing: the backend is waiting
        # for an acknowledgement and would otherwise time out into "pending"
        # with no record that the attempt failed.
        print(f"[watchdog] reload error: {exc}", flush=True)
        write_result("reload-squid", stamp, 1, None)
        return False


def check_reload_trigger(state):
    """React to the backend touching /config/.reload-squid.

    The mtime is NOT recorded before the work is attempted. Doing so consumed
    the trigger up front, so any exception jumped to the handler, wrote no
    acknowledgement, and left the next poll seeing no change — the operator's
    configuration change was dropped permanently and never retried, while the
    database and the UI showed it as applied (SECURE-ERR-01). It is recorded
    after the attempt completes, the same rule the blacklist copy path follows.
    """
    mt_reload = mtime(RELOAD_TRIGGER)
    if mt_reload == state.mtimes[RELOAD_TRIGGER]:
        return
    stamp = trigger_stamp(RELOAD_TRIGGER, mt_reload)
    if not os.path.exists(RELOAD_TRIGGER):
        state.mtimes[RELOAD_TRIGGER] = mt_reload
        return
    print("[watchdog] reload-squid trigger detected, regenerating config...", flush=True)
    if regenerate_and_reconfigure(stamp):
        # Consume the trigger only once the attempt has run to completion. On an
        # exception the mtime stays where it was, so the next 2s poll retries
        # instead of dropping the operator's change (SECURE-ERR-01).
        state.mtimes[RELOAD_TRIGGER] = mt_reload


def check_clear_cache_trigger(state):
    """React to the backend touching /config/.clear-cache."""
    mt_clear = mtime(CLEAR_CACHE_TRIGGER)
    if mt_clear == state.mtimes[CLEAR_CACHE_TRIGGER]:
        return
    state.mtimes[CLEAR_CACHE_TRIGGER] = mt_clear
    if not os.path.exists(CLEAR_CACHE_TRIGGER):
        return
    print("[watchdog] clear-cache trigger detected, purging cache...", flush=True)
    try:
        purge_res = subprocess.run([SQUID, "-k", "purge"], check=False, capture_output=True, timeout=20)
        print(f"[watchdog] squid -k purge rc={purge_res.returncode}", flush=True)
        if purge_res.returncode != 0:
            print("[watchdog] purge failed, trying fallback shutdown...", flush=True)
            subprocess.run([SQUID, "-k", "shutdown"], check=False, capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"[watchdog] clear cache error: {exc}", flush=True)


def expected_checksum(state, src, mt, manifest_state):
    """(proceed, expected_sha256) for a list, from the manifest's state.

    A missing manifest (a backend that predates it) proceeds unverified with one
    warning; an unreadable manifest, or a list it does not name, does not
    proceed, and the refusal is logged once per state.
    """
    kind, payload = manifest_state
    if kind == "invalid":
        note_refusal(state.refused, src, mt, f"manifest {payload}")
        return False, None
    if kind == "ok":
        expected = payload.get(os.path.basename(src))
        if expected is None:
            note_refusal(state.refused, src, mt, "not listed in the manifest")
            return False, None
        return True, expected
    if not state.refused.get("__legacy__"):
        state.refused["__legacy__"] = True
        print("[watchdog] no lists manifest: copying without verification (backend predates it)", flush=True)
    return True, None


def sync_list(state, src, dst, manifest_state):
    """Copy one changed list into Squid's ACL directory. True when it was copied.

    The list is verified against the manifest the backend writes after them. A
    list newer than the manifest, or one whose bytes disagree, is NOT copied:
    Squid keeps the previous good copy, the mtime is not recorded so the next
    poll tries again, and the refusal is logged once per state.
    """
    mt = mtime(src)
    if mt == state.mtimes[src]:
        return False
    if not os.path.exists(src):
        state.mtimes[src] = mt
        return False
    proceed, expected = expected_checksum(state, src, mt, manifest_state)
    if not proceed:
        return False
    try:
        atomic_copy(src, dst, expected)
    except ChecksumMismatch as exc:
        note_refusal(state.refused, src, mt, f"checksum mismatch, keeping previous copy: {exc}")
        return False
    except OSError as exc:
        print(f"[watchdog] copy failed, will retry: {exc}", flush=True)
        return False
    # Record the mtime only AFTER a successful copy. Setting it first meant a
    # transient failure was never retried: the next poll saw no change and Squid
    # kept enforcing a truncated or stale ACL indefinitely (SECURE-DATA-03).
    state.mtimes[src] = mt
    state.refused.pop(src, None)
    print(f"[watchdog] synced {src} -> {dst}", flush=True)
    return True


def sync_lists(state):
    """Sync every changed list; True when at least one was copied."""
    manifest_state = None
    changed = False
    for src, dst in PAIRS:
        if mtime(src) == state.mtimes[src]:
            continue
        if manifest_state is None:
            manifest_state = load_manifest()
        changed = sync_list(state, src, dst, manifest_state) or changed
    return changed


def reconfigure_squid():
    try:
        result = subprocess.run([SQUID, "-k", "reconfigure"], check=False, capture_output=True, timeout=10)
        print(f"[watchdog] squid reconfigure rc={result.returncode}", flush=True)
    except Exception as exc:  # noqa: BLE001 - log and keep running
        print(f"[watchdog] reconfigure error: {exc}", flush=True)


def poll_once(state):
    """One two-second tick: every job the watchdog does, in order.

    Cache statistics are NOT collected here. This used to invoke
    /usr/sbin/squidclient, which is absent from the image and is not packaged
    for Ubuntu 26.04, so every attempt raised FileNotFoundError into a blind
    handler and /config/cache_stats.txt was never written — the dashboard
    showed zeros since the feature was added (SECURE-CONF-02). Squid's own
    cache manager is reachable only at /squid-internal-mgr/, which this
    configuration denies. The backend reports "simulated": true when the file is
    missing and the UI renders that as "not collected".
    """
    touch_heartbeat()
    heal_resolver_drift(state)
    keep_logs_readable()
    rotate_logs_daily(state)
    check_reload_trigger(state)
    check_clear_cache_trigger(state)
    if sync_lists(state):
        reconfigure_squid()


def main():
    print("[watchdog] started", flush=True)
    write_squid_version()
    state = WatchdogState()
    while True:
        time.sleep(2)
        poll_once(state)


if __name__ == "__main__":
    main()
