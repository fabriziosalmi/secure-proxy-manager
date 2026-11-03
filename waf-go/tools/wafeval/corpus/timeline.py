#!/usr/bin/env python3
"""Timeline corpora: records that carry a client and a time (wafeval -timeline).

Usage:
  timeline.py real OUT.jsonl access.log [access.log.0 ...]
  timeline.py beacons OUT.jsonl beacons.parquet N SEED [REAL.jsonl CLIENT MINUTES [START]]
  timeline.py stories OUT.jsonl beacons.parquet N SEED REAL.jsonl CLIENT MINUTES [START]

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

stories: what -correlate is measured on. N configurations among those H2
can see (a mean interval of 1 to 75 seconds, a jitter of at most 68%, a C2
host that is not a private address), each the attacker of one story of a
kind in KINDS, in turn, mixed into the same window of CLIENT's records as
in beacons. A story is up to three stages: arrival, a CONNECT to a
typosquatted name at ARRIVE minutes; contact, the beacon from CONTACT
minutes to the end of the window; action at ACT minutes, either a burst of
CONNECTs to SHARD_HOSTS hosts of REAL.jsonl or a POST of a generated secret
to the C2 host (context bump: it assumes the body is inspected). The kinds
with one stage are the controls: no trajectory should come of them.
contact-shard has only signals that need corroboration (a beacon, a burst),
so -correlate does not report it either: it is what that rule costs.

The beacon and story records are labelled attack; the real records copied
next to them stay benign. Output stays on the machine it is written on.
"""
import heapq, ipaddress, json, random, string, sys
from urllib.parse import urlsplit
from datetime import datetime, timedelta, timezone

LOCAL = [ipaddress.ip_network(n) for n in ("172.16.0.0/12", "127.0.0.0/8", "::1/128")]
START = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)
SPAN = timedelta(minutes=30)
# A sleep of a few milliseconds makes millions of records in a window; past
# this many the beacon stops, and the run says how many beacons it cut.
CAP = 100_000

# Names CheckTyposquat reports (edit distance or homoglyphs of a protected
# name). Combosquats such as paypal-secure.com are not reported, so they
# are not here.
TYPOS = ["paypa1.com", "rnicrosoft.com", "gooogle.com", "githb.com", "arnazon.com", "facebok.com",
         "linkedln.com", "outlok.com", "g00gle.com", "micorsoft.com", "appel.com", "cloudfare.com",
         "protonmai1.com", "yah00.com"]
# (kind, arrival, contact, action)
KINDS = [("full", True, True, "shard"), ("contact-secret", False, True, "secret"),
         ("arrival-secret", True, False, "secret"), ("contact-shard", False, True, "shard"),
         ("beacon-only", False, True, None),
         ("typo-only", True, False, None), ("shard-only", False, False, "shard")]
ARRIVE, CONTACT, ACT = 5, 15, 60
SHARD_HOSTS, SHARD_GAP = 60, 0.8


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


def configs(parquet, n, seed, keep=None):
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
    if keep:
        picked = [c for c in picked if keep(c)]
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


def in_h2_range(c):
    try:
        lan = ipaddress.ip_address(c["host"]).is_private
    except ValueError:
        lan = False
    return not lan and c["jitter"] <= 68 and 1 <= c["sleep"] * (1 - c["jitter"] / 200) <= 75


def host_of(r):
    if r["method"] == "CONNECT":
        return r["url"].rsplit(":", 1)[0]
    return urlsplit(r["url"]).hostname or ""


def secret_body(rng):
    def pick(chars, n):
        return "".join(rng.choice(chars) for _ in range(n))
    alnum = string.ascii_letters + string.digits
    kind = rng.choice(("aws", "github", "pem"))
    if kind == "aws":
        return ("aws_access_key_id=AKIA" + pick(string.ascii_uppercase + string.digits, 16)
                + "\naws_secret_access_key=" + pick(alnum + "/+", 40))
    if kind == "github":
        return "token=ghp_" + pick(alnum, 36)
    # Built from parts so the source holds no key header for scanners to flag.
    return "-----BEGIN " + "RSA PRIVATE KEY-----\n" + pick(alnum, 64) + "\n-----END " + "RSA PRIVATE KEY-----"


def stories(out_path, parquet, n, seed, real_path, client, minutes, start_at=None):
    cfgs = configs(parquet, n, seed, keep=in_h2_range)
    start, window = window_of(real_path, client, minutes, start_at)
    span = timedelta(minutes=minutes)
    hosts = sorted({h for h in (host_of(json.loads(ln)) for ln in open(real_path)) if h})
    if len(hosts) < SHARD_HOSTS:
        sys.exit(f"stories: {real_path} names {len(hosts)} hosts, a burst needs {SHARD_HOSTS}")
    print(f"mixed into {client}: {len(window)} real records from {iso(start)}; {len(hosts)} hosts for bursts")
    rng = random.Random(seed)
    total = cut = 0
    kinds = {}
    with open(out_path, "w") as out:
        for i, c in enumerate(cfgs):
            kind, arrive, beacon, act = KINDS[i % len(KINDS)]
            kinds[kind] = kinds.get(kind, 0) + 1
            name = f"story/{kind}/{c['id']}"

            def rec(stage, k, method, url, ctx, body="", headers=(), source="synthetic-story"):
                return {"id": f"{name}/{stage}/{k}", "source": source, "label": "attack",
                        "category": f"story:{kind}:{stage}", "context": ctx, "method": method, "url": url,
                        "headers": list(headers), "body": body, "client": name}

            staged = []
            if arrive:
                staged.append((start + timedelta(minutes=ARRIVE), 0, rec("arrival", 0, "CONNECT", f"{rng.choice(TYPOS)}:443", "nobump")))
            if act == "shard":
                at = start + timedelta(minutes=ACT)
                for k, h in enumerate(rng.sample(hosts, SHARD_HOSTS)):
                    staged.append((at + timedelta(seconds=k * SHARD_GAP), 0, rec("action", k, "CONNECT", f"{h}:443", "nobump")))
            elif act == "secret":
                staged.append((start + timedelta(minutes=ACT), 0, rec("action", 0, "POST", f"https://{c['host']}/upload", "bump",
                                                                       secret_body(rng), [["Content-Type", "text/plain"]])))
            sent = 0

            def beacon_recs():
                nonlocal sent
                if not beacon:
                    return
                if c["https"]:
                    method, url, ctx = "CONNECT", f"{c['host']}:{c['port']}", "nobump"
                else:
                    port = "" if c["port"] == 80 else f":{c['port']}"
                    method, url, ctx = "GET", f"http://{c['host']}{port}{c['uri']}", "bump"  # slopless-disable-line VBC-034 -- a plain-HTTP beacon configuration is a plain-HTTP request as the proxy sees it
                at = start + timedelta(minutes=CONTACT)
                for k, t in enumerate(beacon_times(c, at, span - (at - start), rng)):
                    sent = k + 1
                    yield t, 0, rec("contact", k, method, url, ctx, source="fox-srt/cobaltstrike-beacon-corpus")

            real_recs = ((t, 1, dict(r, id=f"{name}/{r['id']}", client=name)) for t, r in window)
            for t, _, r in heapq.merge(sorted(staged, key=lambda x: x[0]), beacon_recs(), real_recs, key=lambda x: (x[0], x[1])):
                r["ts"] = iso(t)
                out.write(json.dumps(r, sort_keys=True) + "\n")
                total += 1
            cut += sent == CAP
    print(f"stories: {len(cfgs)} ({', '.join(f'{k} {v}' for k, v in kinds.items())}), {total} records, {cut} beacons cut at {CAP} records")


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
    elif mode == "stories":
        a = sys.argv[2:]
        stories(a[0], a[1], int(a[2]), int(a[3]), a[4], a[5], int(a[6]), a[7] if len(a) > 7 else None)
    else:
        sys.exit(__doc__)
