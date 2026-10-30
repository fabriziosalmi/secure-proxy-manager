#!/usr/bin/env python3
"""Corpora for both directions of traffic, from a real browser crawl.

Usage: convert_a.py DATA_DIR OUT_DIR

- prowl-up.jsonl: every prowlbench text as the body of an upload (POST
  text/plain to a paste service): the egress-leak case. Label 1 is a
  secret (tiers T1-T3), 0 a hard negative (T4: hashes, UUIDs, near misses).
- prowl-down.jsonl: the same texts as a downloaded text/plain response.
- suite-responses.jsonl: the two response cases of the adversarial suite,
  with the bodies tests/adversarial/mock-upstream/nginx.conf serves.
- tranco-requests.jsonl: real Chrome requests from the Tranco top-million
  crawl (phl-ldm/tranco_top_million, four row groups read over HTTP Range,
  hash-sampled): each request in the bump context, each distinct host once
  as CONNECT. All benign: they are the requests of ordinary page loads.
- tranco-responses.jsonl: real responses of the same crawl, headers only
  (the dataset carries no bodies), which exercises the content-type rules.

Nothing leaves the machine; NC terms of prowl apply.
"""
import hashlib, json, os, sys, urllib.request
from urllib.parse import urlsplit

import pyarrow.parquet as pq

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rangefile import RangeFile  # noqa: E402

DATA, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
UA = ["User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"]


def header_pairs(raw, skip=()):
    """The dataset joins repeated headers with a newline in one value; a
    header value cannot hold one, so each line becomes its own header."""
    try:
        d = json.loads(raw or "{}")
    except ValueError:
        return []
    out = []
    for k, v in d.items():
        if not isinstance(v, str) or k.lower() in skip:
            continue
        for line in v.split("\n"):
            out.append([k, line])
    return out


def keep(key, per_million):
    h = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big")
    return h % 1_000_000 < per_million


def write(name, recs):
    n = {}
    with open(os.path.join(OUT, name + ".tmp"), "w") as out:
        for r in recs:
            r.setdefault("headers", [])
            r.setdefault("body", "")
            out.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
            k = (r["context"], r["label"])
            n[k] = n.get(k, 0) + 1
    os.replace(os.path.join(OUT, name + ".tmp"), os.path.join(OUT, name))
    print(name, {f"{c}/{l}": v for (c, l), v in sorted(n.items())}, flush=True)


# ── prowlbench, both directions ──
t = pq.read_table(os.path.join(DATA, "Podric__prowl-secrets-corpus", "prowlbench.parquet"))
rows = list(zip(t.column("id").to_pylist(), t.column("text").to_pylist(), t.column("label").to_pylist(),
                t.column("type").to_pylist(), t.column("tier").to_pylist()))
# prowlbench labels a span, not a text: a hard negative's labelled span is a
# hash or a UUID, yet the same text can hold a whole private key (PEM header
# and key material). For a verdict on the whole body that text is a leak,
# so it is relabelled, and counted.
import re
PEM = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----\s*[A-Za-z0-9+/=\s]{40,}")
relabelled = 0
for k, (i, txt, lab, typ, tier) in enumerate(rows):
    if lab == 0 and PEM.search(txt):
        rows[k] = (i, txt, 1, "relabelled-pem-private-key", tier)
        relabelled += 1
print("  prowlbench hard negatives holding a PEM private key, relabelled:", relabelled, flush=True)
write("prowl-up.jsonl", ({"id": f"pu/{i}", "source": "prowlbench-upload", "context": "bump",
                          "label": "attack" if lab == 1 else "benign", "category": f"{tier}|{typ}",
                          "method": "POST", "url": "https://paste.example.com/api/documents",
                          "headers": [UA, ["Content-Type", "text/plain; charset=utf-8"]], "body": txt}
                         for i, txt, lab, typ, tier in rows))
write("prowl-down.jsonl", ({"id": f"pd/{i}", "source": "prowlbench-download", "context": "bump",
                            "label": "attack" if lab == 1 else "benign", "category": f"{tier}|{typ}",
                            "kind": "response", "status": 200,
                            "headers": [["Content-Type", "text/plain; charset=utf-8"]], "body": txt}
                           for i, txt, lab, typ, tier in rows))

# ── the suite's two response cases (bodies from mock-upstream/nginx.conf) ──
write("suite-responses.jsonl", [
    {"id": "adv/resp-xss-reflected", "source": "adversarial-suite", "context": "bump", "label": "attack",
     "category": "RESPONSE_XSS|resp-xss-reflected", "kind": "response", "status": 200,
     "headers": [["Content-Type", "text/html"]], "body": "<html><body><script>alert(1)</script></body></html>"},
    {"id": "adv/resp-secret-leak", "source": "adversarial-suite", "context": "bump", "label": "attack",
     "category": "RESPONSE_SECRET_LEAK|resp-secret-leak", "kind": "response", "status": 200,
     "headers": [["Content-Type", "text/plain"]],
     "body": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAmockkeymockkeymockkeymockkeymockkeymockkey\n-----END RSA PRIVATE KEY-----"},
])

# ── Tranco crawl over HTTP Range ──
REV = "37974646d7107b8789afb486461be81ba719a08a"
sib = {x["rfilename"]: x for x in json.load(urllib.request.urlopen(
    f"https://huggingface.co/api/datasets/phl-ldm/tranco_top_million/revision/{REV}?blobs=true"))["siblings"]}


def open_remote(name):
    path = f"millionrun_29ea75d9/enriched/{name}.parquet"
    rf = RangeFile(f"https://huggingface.co/datasets/phl-ldm/tranco_top_million/resolve/{REV}/{path}", sib[path]["size"])
    return rf, pq.ParquetFile(rf)


SKIP_REQ = {"host", "content-length", "transfer-encoding", "connection"}
rf, pf = open_remote("labeled_requests")
groups = [0, pf.num_row_groups // 3, 2 * pf.num_row_groups // 3, pf.num_row_groups - 1]
reqs, hosts = [], {}
for g in groups:
    tb = pf.read_row_group(g, columns=["url", "method", "headers", "resource_type", "current_page_url"])
    for url, method, hdrs, rtype, page in zip(*(tb.column(c).to_pylist() for c in ("url", "method", "headers", "resource_type", "current_page_url"))):
        # Chrome calls both a navigation and an iframe "document". A
        # navigation starts from about:blank; an iframe (an ad or a
        # cookie-sync frame) has the page that holds it.
        if rtype == "document":
            rtype = "document-top" if (page or "about:blank") == "about:blank" else "document-frame"
        if not url or not url.startswith(("http://", "https://")):
            continue
        host = urlsplit(url).hostname
        if host and host not in hosts:
            hosts[host] = url
        if not keep("tr/" + url, 125000):  # about 1 in 8
            continue
        h = header_pairs(hdrs, SKIP_REQ)
        reqs.append({"id": "tr/" + hashlib.sha256(url.encode()).hexdigest()[:16], "source": "tranco-requests",
                     "context": "bump", "label": "benign", "category": rtype or "other",
                     "method": method or "GET", "url": url, "headers": h})
for host in sorted(hosts):
    reqs.append({"id": "tr/host/" + host, "source": "tranco-requests", "context": "nobump", "label": "benign",
                 "category": "host", "method": "CONNECT", "url": host + ":443", "headers": [UA]})
write("tranco-requests.jsonl", reqs)
print("  tranco requests: row groups", groups, "fetched", rf.fetched, "bytes", flush=True)

rf, pf = open_remote("responses")
tb = pf.read_row_group(0, columns=["url", "status", "headers"])
resps = []
for url, status, hdrs in zip(*(tb.column(c).to_pylist() for c in ("url", "status", "headers"))):
    if not url or not keep("trr/" + url, 250000):
        continue
    h = header_pairs(hdrs)
    resps.append({"id": "trr/" + hashlib.sha256(url.encode()).hexdigest()[:16], "source": "tranco-responses",
                  "context": "bump", "label": "benign", "category": "response", "kind": "response",
                  "status": int(status or 200), "headers": h})
write("tranco-responses.jsonl", resps)
print("  tranco responses: fetched", rf.fetched, "bytes", flush=True)
sys.stdout.flush()
os._exit(0)  # pyarrow's threads abort the interpreter's normal shutdown with a custom file
