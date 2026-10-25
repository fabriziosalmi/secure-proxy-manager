#!/usr/bin/env python3
"""Squid sidecar maintained by supervisord.

Three jobs on a 2-second tick:

1. Live blacklist reload. Watches the /config blacklist files the backend
   rewrites and, when one changes, copies it into the Squid ACL directory and
   runs `squid -k reconfigure` so new rules take effect without a container
   restart.

2. Log readability. Squid's log daemon creates access.log/cache.log mode 0640,
   recreating them on rotation. The backend runs in a separate container with a
   userns-remapped UID and cannot read 0640 (even as root), so it would ingest
   zero log lines and the dashboard / Logs page would stay empty. Re-assert
   0644 every tick.

3. Cache statistics, once a minute: Squid's cache manager info page, read
   from localhost, written to /config/cache_stats.json for the backend.

This is shipped as a real file and registered statically in
squid-supervisor.conf (rather than generated at runtime) so supervisord always
picks it up on a fresh boot.
"""
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

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

# Squid's own copy of the domain blacklist, used by the domain_blacklist ACL
# (see generate_squid_conf.sh): the list while it is small enough for Squid to
# hold, empty above SPM_SQUID_DOMAIN_ACL_MAX (the DNS sinkhole still applies).
DOMAIN_LIST = "/etc/squid/blacklists/domain/local.txt"
DOMAIN_ACL = "/etc/squid/blacklists/domain/squid.txt"


# Squid warns once for every ACL entry another entry already covers, and Squid 7
# aborts at startup when more than 1000 messages are queued before cache.log is
# open (assertion "earlyMessages->size() < 1000" in debug.cc). A 50,772-entry
# IP import with 5,368 covered entries kept the proxy in a restart loop, on
# 3.14.1 as on 3.14.2. These lists are written in a form Squid has nothing to
# warn about.
IP_ACL_FILES = {
    "/etc/squid/blacklists/ip/local.txt",
    "/etc/squid/whitelists/ip/local.txt",
    "/etc/squid/allowlists/dst_ip/local.txt",
}


def normalize_ip_lines(lines):
    """The smallest set of networks covering the listed addresses and CIDRs,
    with the number of lines that were neither. Adjacent and nested networks
    are merged, which matches exactly the same destinations."""
    nets = {4: [], 6: []}
    bad = 0
    for raw in lines:
        s = raw.split("#", 1)[0].strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            bad += 1
            continue
        nets[net.version].append(net)
    out = []
    for version in (4, 6):
        for net in ipaddress.collapse_addresses(nets[version]):
            out.append(str(net.network_address) if net.num_addresses == 1 else str(net))
    return out, bad


def normalize_domain_lines(lines):
    """Exact names, lower case, each once. The backend writes wildcard entries
    as "*.example.com"; dstdomain reads that as a literal host name that never
    matches, so the prefix is dropped. That is the same name the DNS sinkhole
    blocks: dnsmasq gets it as an exact hosts entry. No entry starts with a
    dot, so none can cover another."""
    seen = set()
    out = []
    for raw in lines:
        s = raw.split("#", 1)[0].strip().lower()
        if s.startswith("*."):
            s = s[2:]
        s = s.lstrip(".")
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def write_lines_atomic(path, lines):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=os.path.basename(path) + ".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("".join(line + "\n" for line in lines))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# What normalize_ip_file made of each IP list Squid enforces, for the backend:
# how many entries the list had, how many networks Squid loads after merging,
# and how many lines were not an address or CIDR. The Blacklists page shows the
# merged count from this record; the backend cannot derive it on its own
# without repeating the merge. Only the two lists the page shows are recorded.
IP_ACL_STATUS = {
    "/etc/squid/blacklists/ip/local.txt": f"{CONFIG_DIR}/ip_blacklist_acl_status.json",
    "/etc/squid/whitelists/ip/local.txt": f"{CONFIG_DIR}/ip_whitelist_acl_status.json",
}


def write_ip_acl_status(path, entries, networks, dropped):
    status = IP_ACL_STATUS.get(path)
    if status is None:
        return
    try:
        write_lines_atomic(status, [json.dumps(
            {"version": 1, "entries": entries, "networks": networks, "dropped": dropped,
             "written_at": int(time.time())})])
    except OSError as exc:
        print(f"[watchdog] could not write {status}: {exc}", flush=True)


def forget_ip_acl_status(path):
    """No record rather than a stale one: after a failed normalization Squid
    holds the list as copied, which the last record does not describe."""
    status = IP_ACL_STATUS.get(path)
    if status is None:
        return
    try:
        os.unlink(status)
    except OSError:
        pass


def normalize_ip_file(path):
    """Rewrite an IP ACL file in normalized form. On failure the file is left
    as copied: Squid may refuse it, but it never silently loses entries. The
    result is recorded in IP_ACL_STATUS."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        out, bad = normalize_ip_lines(lines)
        write_lines_atomic(path, out)
    except OSError as exc:
        print(f"[watchdog] could not normalize {path}: {exc}", flush=True)
        forget_ip_acl_status(path)
        return
    n = sum(1 for line in lines if line.split("#", 1)[0].strip())
    write_ip_acl_status(path, n, len(out), bad)
    if n != len(out) or bad:
        print(f"[watchdog] {path}: {n} entries -> {len(out)} networks"
              + (f", {bad} not an address or CIDR, dropped" if bad else ""), flush=True)


def domain_acl_max():
    try:
        return int(os.environ.get("SPM_SQUID_DOMAIN_ACL_MAX", "250000"))
    except ValueError:
        return 250000


# What refresh_domain_acl decided, for the backend: how many names the list
# has, the limit, and whether Squid holds them. SPM_SQUID_DOMAIN_ACL_MAX is set
# on this container only, so the backend cannot tell on its own; the
# dashboard says "blocked at DNS only" from this file, not from a guess.
DOMAIN_ACL_STATUS = f"{CONFIG_DIR}/domain_acl_status.json"


def write_domain_acl_status(names, limit, held):
    try:
        write_lines_atomic(DOMAIN_ACL_STATUS, [json.dumps(
            {"version": 1, "names": names, "limit": limit, "held": held, "written_at": int(time.time())})])
    except OSError as exc:
        print(f"[watchdog] could not write {DOMAIN_ACL_STATUS}: {exc}", flush=True)


def refresh_domain_acl():
    """Rewrite DOMAIN_ACL from DOMAIN_LIST, or empty it when the list is too
    large for Squid. Called after every list sync, so a list that grows past
    the limit can never be loaded into Squid by a reconfigure. The decision is
    recorded in DOMAIN_ACL_STATUS."""
    try:
        with open(DOMAIN_LIST, encoding="utf-8", errors="replace") as f:
            names = normalize_domain_lines(f.read().splitlines())
    except OSError:
        names = []
    count, limit = len(names), domain_acl_max()
    if count > limit:
        print(f"[watchdog] domain blacklist has {count} entries, over SPM_SQUID_DOMAIN_ACL_MAX={limit}: "
              "Squid denies none of them itself, only the DNS sinkhole does", flush=True)
        names = []
    try:
        write_lines_atomic(DOMAIN_ACL, names)
    except OSError as exc:
        print(f"[watchdog] could not write {DOMAIN_ACL}: {exc}", flush=True)
        # Whatever Squid's file holds now, it is not this list.
        write_domain_acl_status(count, limit, False)
        return
    write_domain_acl_status(count, limit, count <= limit)


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


def squid_config_ok(path=None):
    """Whether squid accepts a config (the live one by default). Used as a gate
    before reconfigure, so an unparsable ACL set is refused rather than loaded."""
    argv = ["/usr/sbin/squid", "-k", "parse"] + (["-f", path] if path else [])
    try:
        res = subprocess.run(argv, check=False, capture_output=True, timeout=15)
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
SQUID_CONF = "/etc/squid/squid.conf"
SQUID_CONF_NEXT = SQUID_CONF + ".next"


def promote_config():
    """Move the checked config over the live one (same filesystem: atomic)."""
    os.replace(SQUID_CONF_NEXT, SQUID_CONF)


def generate_checked():
    """Generate into SQUID_CONF_NEXT, check that Squid parses it, and only then
    move it over the live file. Returns (generator result, applied).

    The generator used to write the live file in place, and the parse check ran
    afterwards: a refused config was already on disk, so the next reconfigure
    from any other path (list sync, resolver drift) or a supervisord restart
    loaded it. The resolver-drift path did not check at all.
    """
    env = dict(os.environ, SQUID_CONF=SQUID_CONF_NEXT)
    gen = subprocess.run([GENERATOR], check=False, capture_output=True, timeout=30, env=env)
    if gen.returncode != 0 or not squid_config_ok(SQUID_CONF_NEXT):
        return gen, False
    promote_config()
    return gen, True


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
        # Cache statistics: when the next collection is due (time.monotonic),
        # the problem last logged (None when the last collection worked), and
        # the disk capacity with the squid.conf mtime it was read for.
        self.cache_stats_due = 0.0
        self.cache_stats_problem = None
        self.disk_capacity_kb = None
        self.disk_capacity_conf = None


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
        _, applied = generate_checked()
        if applied:
            subprocess.run([SQUID, "-k", "reconfigure"], check=False, capture_output=True, timeout=10)
        else:
            print("[watchdog] resolver drift: the regenerated config was refused — keeping the running one", flush=True)
        # Recorded either way, so a config that will not generate is not retried every 2 s.
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
        gen_res, applied = generate_checked()
        print(f"[watchdog] generate_squid_conf.sh rc={gen_res.returncode}", flush=True)
        # A failed generation or a config that does not parse is never moved
        # over the live file, so the running config stays both in memory and
        # on disk (SECURE-ERR-07).
        if gen_res.returncode != 0:
            print("[watchdog] generation FAILED — keeping the running config, not reconfiguring", flush=True)
            print(gen_res.stderr.decode("utf-8", "replace")[:2000], flush=True)
            write_result("reload-squid", stamp, gen_res.returncode, None)
        elif not applied:
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
    if dst in IP_ACL_FILES:
        normalize_ip_file(dst)
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


# ── Cache statistics ─────────────────────────────────────────────────────────
#
# This used to invoke /usr/sbin/squidclient, which is absent from the image and
# is not packaged for Ubuntu 26.04, so every attempt raised FileNotFoundError
# into a blind handler and /config/cache_stats.txt was never written: the
# dashboard showed zeros since the feature was added (SECURE-CONF-02). The
# cache manager answers on Squid's own port at /squid-internal-mgr/, and
# squid.conf admits it from localhost only, which is where this runs. Read with
# urllib: no extra binary.
#
# What is parsed is what Squid 7.7 printed (tests/python/fixtures/
# squid_7.7_info.txt, captured from the proxy image). The format differs from
# the one the backend used to parse ("Request Hit Ratios:", "StoreEntries :"),
# which no Squid in this image prints.
CACHE_STATS = f"{CONFIG_DIR}/cache_stats.json"
CACHE_STATS_VERSION = 1
# Every collection is one request Squid counts, as a miss, in the hit ratio it
# reports: at 60 s that is 5 requests in each 5-minute window. A shorter
# interval would weigh more on a quiet proxy's ratio.
CACHE_STATS_INTERVAL = 60
CACHE_MGR_TIMEOUT = 5
# The info page is about 2.6 KB; anything this large is not it.
CACHE_MGR_MAX_BYTES = 1 << 20
# Squid takes its first statistics sample one minute after it starts. Before
# that it prints "5min: 0.0%, 60min: 0.0%" whatever it served (measured on 7.7:
# 0.0% at 7.9 to 59.4 s of uptime with hits served, 61.1% at 69.6 s). That 0.0
# is not a measurement, so the ratios are recorded as absent until then.
SQUID_FIRST_SAMPLE_S = 60

_NUM = r"(-?\d+(?:\.\d+)?)"
_RATIO_LINES = {
    "Hits as % of all requests": "request_hit_ratio",
    "Hits as % of bytes sent": "byte_hit_ratio",
}
# (pattern on a stripped line, field, type)
_INFO_FIELDS = [
    (re.compile(r"Storage Swap size:\s*(\d+) KB"), "disk_used_kb", int),
    (re.compile(r"Storage Swap capacity:\s*" + _NUM + r"% used, " + _NUM + r"% free"), "disk_used_pct", float),
    (re.compile(r"Storage Mem size:\s*(\d+) KB"), "memory_used_kb", int),
    (re.compile(r"Storage Mem capacity:\s*" + _NUM + r"% used, " + _NUM + r"% free"), "memory_used_pct", float),
    (re.compile(r"UP Time:\s*(\d+(?:\.\d+)?) seconds"), "uptime_s", float),
    (re.compile(r"(\d+) StoreEntries"), "store_entries", int),
    (re.compile(r"(\d+) Hot Object Cache Items"), "memory_objects", int),
    (re.compile(r"(\d+) on-disk objects"), "disk_objects", int),
]
_RATIO = re.compile(r"(" + "|".join(re.escape(k) for k in _RATIO_LINES) + r"):\s*5min:\s*"
                    + _NUM + r"%, 60min:\s*" + _NUM + r"%")
_STOREDIR_MAX = re.compile(r"Maximum Swap Size\s*:\s*(\d+) KB")

CACHE_STATS_FIELDS = (
    "request_hit_ratio_5min_pct", "request_hit_ratio_60min_pct",
    "byte_hit_ratio_5min_pct", "byte_hit_ratio_60min_pct",
    *(field for _, field, _ in _INFO_FIELDS),
)


def parse_squid_info(text):
    """The fields of the cache manager info page, as Squid printed them.

    Every field this does not find is None, never 0. Percentages stay
    percentages (12.3 for "12.3%"); Squid's byte hit ratio can be negative
    (it prints "-0.0%" on an idle cache) and is kept as printed.
    """
    out = dict.fromkeys(CACHE_STATS_FIELDS)
    for raw in text.splitlines():
        line = raw.strip()
        m = _RATIO.fullmatch(line)
        if m:
            name = _RATIO_LINES[m.group(1)]
            out[f"{name}_5min_pct"] = float(m.group(2))
            out[f"{name}_60min_pct"] = float(m.group(3))
            continue
        for pattern, field, kind in _INFO_FIELDS:
            m = pattern.fullmatch(line)
            if m:
                out[field] = kind(m.group(1))
                break
    uptime = out["uptime_s"]
    if uptime is None or uptime < SQUID_FIRST_SAMPLE_S:
        for name in _RATIO_LINES.values():
            out[f"{name}_5min_pct"] = out[f"{name}_60min_pct"] = None
    return out


def parse_squid_storedir(text):
    """The disk cache capacity in KB from the storedir page, None when it does
    not say. One cache_dir prints the line once; anything else is ambiguous."""
    found = [int(m.group(1)) for m in (_STOREDIR_MAX.fullmatch(raw.strip()) for raw in text.splitlines()) if m]
    return found[0] if len(found) == 1 else None


def squid_http_port(conf=None):
    """The port of the first http_port in the live squid.conf; 3128 without one.
    PROXY_PORT and squid_settings.env can move it, so it is not a constant."""
    try:
        with open(conf or SQUID_CONF, encoding="utf-8", errors="replace") as f:
            for raw in f:
                m = re.match(r"http_port\s+(?:\S*:)?(\d+)(?:\s|$)", raw)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 3128


# The cache manager is fetched directly: an http_proxy in the environment
# would otherwise send this request through itself.
_MGR_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch_cache_manager(page, port):
    """One cache manager page from Squid on localhost, as text. Raises OSError
    (urllib's errors and timeouts are OSErrors) or http.client.HTTPException."""
    url = f"http://127.0.0.1:{port}/squid-internal-mgr/{page}"
    with _MGR_OPENER.open(url, timeout=CACHE_MGR_TIMEOUT) as resp:
        return resp.read(CACHE_MGR_MAX_BYTES).decode("utf-8", "replace")


def note_cache_stats(state, problem):
    """Log a collection problem once per kind of problem, and the recovery."""
    if problem == state.cache_stats_problem:
        return
    if problem is None:
        print("[watchdog] cache statistics: collected", flush=True)
    else:
        print(f"[watchdog] cache statistics not collected: {problem}", flush=True)
    state.cache_stats_problem = problem


def _problem(page, exc):
    # The same failure prints the same text every minute ("<urlopen error
    # [Errno 111] Connection refused>", "timed out"), so it is logged once.
    return f"{page}: {type(exc).__name__}: {exc}"


def disk_capacity(state, port):
    """The disk cache capacity, from storedir. It changes only when squid.conf
    does, so it is fetched again only then: each fetch is one more request in
    Squid's hit ratio. A squid.conf younger than one interval may not be loaded
    yet (reconfigure is asynchronous), so it is asked again next time."""
    conf_mt = mtime(SQUID_CONF)
    if state.disk_capacity_kb is not None and state.disk_capacity_conf == conf_mt:
        return state.disk_capacity_kb, None
    try:
        cap = parse_squid_storedir(fetch_cache_manager("storedir", port))
    except (OSError, http.client.HTTPException) as exc:
        state.disk_capacity_kb = None
        return None, _problem("storedir", exc)
    state.disk_capacity_kb = cap
    if cap is not None and time.time() - conf_mt >= CACHE_STATS_INTERVAL:
        state.disk_capacity_conf = conf_mt
    return cap, None if cap is not None else "storedir: no Maximum Swap Size line"


def collect_cache_stats(state):
    """Every CACHE_STATS_INTERVAL seconds, write what the info page reports to
    CACHE_STATS, atomically, with the time it was collected. A failed fetch
    writes nothing: the file keeps its collected_at and the backend reports
    it as out of date. Nothing here may stop the poll loop. True when written."""
    now = time.monotonic()
    if now < state.cache_stats_due:
        return False
    state.cache_stats_due = now + CACHE_STATS_INTERVAL
    port = squid_http_port()
    try:
        stats = parse_squid_info(fetch_cache_manager("info", port))
    except (OSError, http.client.HTTPException) as exc:
        note_cache_stats(state, _problem("info", exc))
        return False
    if all(v is None for v in stats.values()):
        note_cache_stats(state, "info: none of the expected fields")
        return False
    cap, problem = disk_capacity(state, port)
    doc = {"version": CACHE_STATS_VERSION, "collected_at": int(time.time()),
           "interval_s": CACHE_STATS_INTERVAL, **stats, "disk_capacity_kb": cap}
    try:
        write_lines_atomic(CACHE_STATS, [json.dumps(doc, sort_keys=True)])
    except OSError as exc:
        note_cache_stats(state, _problem("write", exc))
        return False
    note_cache_stats(state, problem)
    return True


def poll_once(state):
    """One two-second tick: every job the watchdog does, in order. Cache
    statistics come last and run once a minute (collect_cache_stats)."""
    touch_heartbeat()
    heal_resolver_drift(state)
    keep_logs_readable()
    rotate_logs_daily(state)
    check_reload_trigger(state)
    check_clear_cache_trigger(state)
    if sync_lists(state):
        refresh_domain_acl()
        reconfigure_squid()
    collect_cache_stats(state)


def normalize_cli(args):
    """generate_squid_conf.sh writes the same files at boot through this:
    `--normalize ip FILE...` and `--normalize domain-acl`."""
    if args[:1] == ["ip"] and len(args) > 1:
        for path in args[1:]:
            if os.path.exists(path):
                normalize_ip_file(path)
        return 0
    if args == ["domain-acl"]:
        refresh_domain_acl()
        return 0
    print("usage: blacklist_watchdog.py --normalize ip FILE... | --normalize domain-acl", file=sys.stderr)
    return 2


def main():
    print("[watchdog] started", flush=True)
    write_squid_version()
    state = WatchdogState()
    while True:
        time.sleep(2)
        poll_once(state)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--normalize"]:
        sys.exit(normalize_cli(sys.argv[2:]))
    main()
