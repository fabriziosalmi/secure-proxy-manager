#!/usr/bin/env python3
"""Timeline corpora: records that carry a client and a time (wafeval -timeline).

Usage:
  timeline.py real OUT.jsonl access.log [access.log.0 ...]
  timeline.py beacons OUT.jsonl beacons.parquet N SEED [REAL.jsonl CLIENT MINUTES [START]]

real: every request of a real installation's Squid access logs ('spm'
format, see convert_real.py), in time order, with the client address as the
client. Local clients (Docker, loopback) are left out, as in convert_real.py.
Labelled benign, an assumption: it is what the network sent.

beacons: N Cobalt Strike configurations of the Fox-IT corpus, picked with
SEED among those that talk HTTP or HTTPS, each replayed for 30 minutes as
its sleep time and jitter make it (for the whole window when mixed): the beacon sleeps S, minus a random
share of S up to the jitter, for at most CAP records. HTTPS is a CONNECT to the first C2 host
(context nobump), HTTP a GET of its first URI (context bump). Each beacon
is its own client. With REAL.jsonl, CLIENT and MINUTES, each beacon is
instead mixed into a copy of MINUTES of CLIENT's records in REAL.jsonl,
from START (RFC 3339) or else from where they are densest, under a client
name of its own, so every beacon meets the same real traffic. The densest
stretch can be a burst and then silence: name START to pick a stretch where
the client is steadily active.

The beacon records are labelled attack; the real records copied next to
them stay benign. Output stays on the machine it is written on.
"""
import heapq, ipaddress, json, random, sys
from datetime import datetime, timedelta, timezone

LOCAL = [ipaddress.ip_network(n) for n in ("172.16.0.0/12", "127.0.0.0/8", "::1/128")]
START = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)
SPAN = timedelta(minutes=30)
# A sleep of a few milliseconds makes millions of records in a window; past
# this many the beacon stops, and the run says how many beacons it cut.
CAP = 100_000


def iso(t):
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def secs(x):
    # A sleep in seconds to the millisecond: "g" keeps six digits, which
    # would merge sleeps such as 1234.567 and 1234.568 into one category.
    return f"{x:.3f}".rstrip("0").rstrip(".")


def real(out_path, logs):
    recs = []
    for path in logs:
        for ln in open(path, errors="replace"):
            f = ln.split()
            if len(f) < 7:
                continue
            try:
                ip = ipaddress.ip_address(f[2])
                ts = datetime.fromtimestamp(float(f[0]), tz=timezone.utc)
            except ValueError:
                continue
            if any(ip in n for n in LOCAL):
                continue
            method, url = f[5], f[6]
            if method == "CONNECT":
                ctx = "nobump"
            elif url.startswith(("http://", "https://")):
                ctx = "bump"
            else:
                continue
            recs.append((ts, f[2], method, url, ctx))
    recs.sort()
    with open(out_path, "w") as out:
        for i, (ts, ip, method, url, ctx) in enumerate(recs):
            out.write(json.dumps({"id": f"real/{i}", "source": "real-traffic", "label": "benign",
                                  "category": "real", "context": ctx, "method": method, "url": url,
                                  "headers": [], "body": "", "client": ip, "ts": iso(ts)}, sort_keys=True) + "\n")
    print(f"real: {len(recs)} records, {len({r[1] for r in recs})} clients")


def configs(parquet, n, seed):
    import pyarrow.parquet as pq
    rows = pq.read_table(parquet, columns=["id", "config_json"]).to_pylist()
    picked = []
    for r in rows:
        try:
            s = json.loads(r["config_json"])["settings"]
        except (ValueError, KeyError, TypeError):
            continue
        proto, sleep, jitter = s.get("SETTING_PROTOCOL"), s.get("SETTING_SLEEPTIME"), s.get("SETTING_JITTER")
        dom = s.get("SETTING_DOMAINS") or ""
        parts = [p.strip() for p in str(dom).split(",") if p.strip()]
        # A host field can hold several hosts separated by spaces (see
        # convert.py): the beacon contacts the first.
        if parts:
            parts[0] = parts[0].split()[0]
        if proto not in (0, 8) or not isinstance(sleep, int) or sleep <= 0 or not isinstance(jitter, int) or len(parts) < 2:
            continue
        # SETTING_DOMAINS is "host,uri[,host,uri...]"; a few configs hold
        # something else (a URI first), which names no host to contact.
        # A host with a colon (a trailing one, or a port) makes a CONNECT
        # target that does not parse.
        if parts[0].startswith("/") or "/" in parts[0] or ":" in parts[0] or not parts[1].startswith("/"):
            continue
        port = s.get("SETTING_PORT") or (443 if proto == 8 else 80)
        picked.append({"id": str(r["id"]), "https": proto == 8, "host": parts[0], "uri": parts[1],
                       "port": port, "sleep": sleep / 1000.0, "jitter": min(max(jitter, 0), 99)})
    picked.sort(key=lambda c: c["id"])
    return random.Random(seed).sample(picked, n)


def beacon_times(c, start, span, rng):
    t, k = start, 0
    while t < start + span and k < CAP:
        yield t
        k += 1
        cut = rng.uniform(0, c["sleep"] * c["jitter"] / 100.0)
        t += timedelta(seconds=c["sleep"] - cut)


def window_of(real_path, client, minutes, start=None):
    times, recs = [], []
    for ln in open(real_path):
        r = json.loads(ln)
        if r["client"] == client:
            recs.append(r)
            times.append(datetime.fromisoformat(r["ts"].replace("Z", "+00:00")))
    w = timedelta(minutes=minutes)
    if start:
        a = datetime.fromisoformat(start.replace("Z", "+00:00"))
        sel = [(t, r) for t, r in zip(times, recs) if a <= t < a + w]
        return a, sel
    best, j = (0, 0, 0), 0
    for i in range(len(times)):
        while times[i] - times[j] >= w:
            j += 1
        if i - j + 1 > best[0]:
            best = (i - j + 1, j, i)
    _, a, b = best
    return times[a], list(zip(times[a:b + 1], recs[a:b + 1]))


def beacons(out_path, parquet, n, seed, real_path=None, client=None, minutes=30, start_at=None):
    cfgs = configs(parquet, n, seed)
    start, window, span = START, [], SPAN
    if real_path:
        start, window = window_of(real_path, client, minutes, start_at)
        span = timedelta(minutes=minutes)
        print(f"mixed into {client}: {len(window)} real records from {iso(start)}")
    rng = random.Random(seed)
    total = cut = 0
    with open(out_path, "w") as out:
        for c in cfgs:
            name = ("mix/" if real_path else "beacon/") + c["id"]
            if c["https"]:
                method, url, ctx = "CONNECT", f"{c['host']}:{c['port']}", "nobump"
            else:
                port = "" if c["port"] == 80 else f":{c['port']}"
                method, url, ctx = "GET", f"http://{c['host']}{port}{c['uri']}", "bump"  # slopless-disable-line VBC-034 -- a plain-HTTP beacon configuration is a plain-HTTP request as the proxy sees it
            sent = 0

            def beacon_recs():
                nonlocal sent
                for k, t in enumerate(beacon_times(c, start, span, rng)):
                    sent = k + 1
                    yield t, 0, {"id": f"{name}/{k}", "source": "fox-srt/cobaltstrike-beacon-corpus", "label": "attack",
                                 "category": f"sleep{secs(c['sleep'])}s-jitter{c['jitter']}", "context": ctx,
                                 "method": method, "url": url, "headers": [], "body": "", "client": name}

            real_recs = ((t, 1, dict(r, id=f"{name}/{r['id']}", client=name)) for t, r in window)
            # Both streams are in time order; on a tie the beacon goes first,
            # as the stable sort over one list did.
            for t, _, r in heapq.merge(beacon_recs(), real_recs, key=lambda x: (x[0], x[1])):
                r["ts"] = iso(t)
                out.write(json.dumps(r, sort_keys=True) + "\n")
                total += 1
            cut += sent == CAP
    print(f"beacons: {len(cfgs)} configs, {total} records, {cut} cut at {CAP} records")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "real":
        real(sys.argv[2], sys.argv[3:])
    elif mode == "beacons":
        a = sys.argv[2:]
        if len(a) == 4:
            beacons(a[0], a[1], int(a[2]), int(a[3]))
        else:
            beacons(a[0], a[1], int(a[2]), int(a[3]), a[4], a[5], int(a[6]), a[7] if len(a) > 7 else None)
    else:
        sys.exit(__doc__)
