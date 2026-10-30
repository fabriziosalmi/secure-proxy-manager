#!/usr/bin/env python3
"""Evasion corpus: transformations of attack and benign requests.

Usage: mutate.py DATA_DIR OUT_DIR

1. adversarial-suite.jsonl: tests/adversarial/corpus.json as a wafeval
   corpus (expect block -> attack, pass/allow -> benign), host upstream.test.
2. mutations.jsonl: 50 attacks per class and 300 normal requests from
   SecureAI-SE/http-attack-requests (hash-sampled), each under every
   transform below. The category is "<transform>|<class>", so the report
   gives a TPR per transform and an FPR on the same transform applied to
   benign requests.

Transforms move or disguise the query values only; path, host and the
request shape stay.
"""
import base64, hashlib, json, os, sys
from urllib.parse import urlsplit, parse_qsl, quote

import pyarrow.parquet as pq

DATA, OUT = sys.argv[1], sys.argv[2]
REPO_CORPUS = sys.argv[3] if len(sys.argv) > 3 else None
os.makedirs(OUT, exist_ok=True)
UA = ["User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"]
ACC = ["Accept", "text/html,application/xhtml+xml"]


def enc(s):
    return quote(s, safe="")


def query(pairs):
    return "&".join(f"{enc(k)}={enc(v)}" for k, v in pairs)


def fullwidth(s):
    return "".join(chr(ord(c) + 0xFEE0) if c.isascii() and c.isalpha() else c for c in s)


def altcase(s):
    out, up = [], False
    for c in s:
        if c.isalpha():
            out.append(c.upper() if up else c.lower())
            up = not up
        else:
            out.append(c)
    return "".join(out)


def rec(url, method="GET", headers=None, body="", ctype=None):
    h = [UA, ACC] + (headers or [])
    if ctype:
        h.append(["Content-Type", ctype])
    return {"method": method, "url": url, "headers": h, "body": body}


def transforms(u):
    """Every transform of the request at URL u: (name, record)."""
    p = urlsplit(u)
    base = f"{p.scheme}://{p.netloc}{p.path}"
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if not pairs:
        return []
    yield "t00-identity", rec(f"{base}?{query(pairs)}")
    yield "t01-double-encoded", rec(f"{base}?" + "&".join(f"{enc(k)}={enc(enc(v))}" for k, v in pairs))
    yield "t02-alternating-case", rec(f"{base}?{query([(k, altcase(v)) for k, v in pairs])}")
    yield "t03-comments-for-spaces", rec(f"{base}?{query([(k, v.replace(' ', '/**/')) for k, v in pairs])}")
    yield "t04-fullwidth-letters", rec(f"{base}?{query([(k, fullwidth(v)) for k, v in pairs])}")
    yield "t05-form-body", rec(base, "POST", body=query(pairs), ctype="application/x-www-form-urlencoded")
    yield "t06-json-body", rec(base, "POST", body=json.dumps(dict(pairs)), ctype="application/json")
    bnd = "----wafeval" + hashlib.sha256(u.encode()).hexdigest()[:16]
    mp = "".join(f"--{bnd}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n" for k, v in pairs) + f"--{bnd}--\r\n"
    yield "t07-multipart-body", rec(base, "POST", body=mp, ctype=f"multipart/form-data; boundary={bnd}")
    yield "t08-parameter-pollution", rec(f"{base}?" + "&".join(f"{enc(k)}=a&{enc(k)}={enc(v)}" for k, v in pairs))
    yield "t09-cookie", rec(base, headers=[["Cookie", "; ".join(f"{k}={enc(v)}" for k, v in pairs)]])
    yield "t10-custom-header", rec(base, headers=[["X-Data", " ".join(v for _, v in pairs)]])
    yield "t11-base64-value", rec(f"{base}?{query([(k, base64.b64encode(v.encode()).decode()) for k, v in pairs])}")


def keep(key, per_million):
    h = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big")
    return h % 1_000_000 < per_million


CLASSES = ["normal", "sqli", "xss", "ssrf", "ssti", "lfi", "traversal"]
picked = {c: [] for c in CLASSES}
for split in ("train", "validation", "test"):
    t = pq.read_table(os.path.join(DATA, "SecureAI-SE__http-attack-requests", "data", f"{split}-00000-of-00001.parquet"))
    for req, lab in zip(t.column("request").to_pylist(), t.column("label").to_pylist()):
        c = CLASSES[lab]
        want = 300 if c == "normal" else 50
        if len(picked[c]) < want and keep("mut/" + req, 400000):
            picked[c].append(req)

n = {}
with open(os.path.join(OUT, "mutations.jsonl.tmp"), "w") as out:
    for c, reqs in picked.items():
        for i, u in enumerate(reqs):
            for name, r in transforms(u):
                r.update(id=f"mut/{c}/{i}/{name}", source="mutations", context="bump",
                         label="benign" if c == "normal" else "attack", category=f"{name}|{c}")
                out.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
                n[r["label"]] = n.get(r["label"], 0) + 1
os.replace(os.path.join(OUT, "mutations.jsonl.tmp"), os.path.join(OUT, "mutations.jsonl"))
print("mutations.jsonl", n, {c: len(v) for c, v in picked.items()})

if REPO_CORPUS:
    rows = json.load(open(REPO_CORPUS))
    with open(os.path.join(OUT, "adversarial-suite.jsonl"), "w") as out:
        for r in rows:
            # Response cases are judged on the response (convert_a.py,
            # suite-responses.jsonl); their request is clean by design.
            if r.get("vector") == "response":
                continue
            # The case's own headers replace the defaults of the same name:
            # the engine reads the first User-Agent, so a default ahead of
            # the case's would hide its payload.
            own = []
            for h in r.get("headers", []):
                k, _, v = h.partition(":")
                own.append([k.strip(), v.strip()])
            names = {k.lower() for k, _ in own}
            hdr = [h for h in (UA, ACC) if h[0].lower() not in names] + own
            if r.get("content_type"):
                hdr.append(["Content-Type", r["content_type"]])
            out.write(json.dumps({"id": "adv/" + r["id"], "source": "adversarial-suite", "context": "bump",
                                  "label": "attack" if r["expect"] == "block" else "benign",
                                  "category": r["category"] + "|" + r["id"], "method": r["method"],
                                  "url": "http://upstream.test" + r["path"], "headers": hdr,
                                  "body": r.get("body", "")}, sort_keys=True) + "\n")
    print("adversarial-suite.jsonl", len(rows))
