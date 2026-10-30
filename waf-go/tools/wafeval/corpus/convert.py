#!/usr/bin/env python3
"""Turn the datasets in datasets.manifest.json into wafeval corpus files.

Usage: convert.py DATA_DIR OUT_DIR

One JSON object per line, the schema wafeval reads:

  id        stable identifier: source, file, row
  source    the dataset
  label     "attack" or "benign"
  category  the dataset's own class (sqli, xss, dga:<family>, phishing, ...)
  context   "bump" (the WAF sees the request: plain HTTP or SSL-bump) or
            "nobump" (HTTPS without bump: the WAF sees only CONNECT host:443)
  method, url, headers ([[name, value], ...]), body

Sampling is by a hash of the record, never by a random generator, so the
same data gives the same corpus on every run. Nothing here leaves the
machine it runs on: the corpus is derived from the datasets and inherits
their licences.
"""
import hashlib, json, os, sys
from urllib.parse import urlsplit

import pyarrow.parquet as pq

DATA, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)


def keep(key, per_million):
    """Deterministic sample: keep a record when the hash of its key falls
    below per_million / 1e6."""
    h = int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big")
    return h % 1_000_000 < per_million


def ds(name, *parts):
    return os.path.join(DATA, name.replace("/", "__"), *parts)


class Writer:
    def __init__(self, name):
        self.path = os.path.join(OUT, name + ".jsonl")
        self.fh = open(self.path + ".tmp", "w")
        self.n = {}

    def add(self, **rec):
        rec.setdefault("headers", [])
        rec.setdefault("body", "")
        self.fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        k = (rec["context"], rec["label"])
        self.n[k] = self.n.get(k, 0) + 1

    def close(self):
        self.fh.close()
        os.replace(self.path + ".tmp", self.path)
        print(os.path.basename(self.path), {f"{c}/{l}": v for (c, l), v in sorted(self.n.items())}, flush=True)


def connect(host):
    """What the WAF receives for HTTPS without bump. A host that already
    names a port keeps it."""
    if host.rsplit(":", 1)[-1].isdigit():
        return {"context": "nobump", "method": "CONNECT", "url": host}
    return {"context": "nobump", "method": "CONNECT", "url": host + ":443"}


# ── SecureAI-SE/http-attack-requests: one injected query value per request ──
CLASSES = ["normal", "sqli", "xss", "ssrf", "ssti", "lfi", "traversal"]
w = Writer("http-attack-requests")
for split in ("train", "validation", "test"):
    t = pq.read_table(ds("SecureAI-SE/http-attack-requests", "data", f"{split}-00000-of-00001.parquet"))
    for i, (req, lab) in enumerate(zip(t.column("request").to_pylist(), t.column("label").to_pylist())):
        cls = CLASSES[lab]
        w.add(id=f"sair/{split}/{i}", source="SecureAI-SE/http-attack-requests",
              label="benign" if cls == "normal" else "attack", category=cls,
              context="bump", method="GET", url=req)
w.close()

# ── CSIC 2010: full raw requests. The host is localhost:8080, which the WAF
# skips as a LAN destination, so it is rewritten to a public name. ──
CSIC_HOST = "tienda.csic.example"
w = Writer("csic-2010")
for split in ("train", "validation", "test"):
    t = pq.read_table(ds("b1nch3f/csic-dataset", "data", f"{split}-00000-of-00001.parquet"))
    for i, (raw, lab) in enumerate(zip(t.column("request").to_pylist(), t.column("label").to_pylist())):
        head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
        lines = head.split("\n")
        try:
            method, url, _ = lines[0].split(" ", 2)
        except ValueError:
            continue
        url = url.replace("localhost:8080", CSIC_HOST)
        headers = []
        for ln in lines[1:]:
            if ":" not in ln:
                continue
            k, v = ln.split(":", 1)
            v = v.strip()
            if k.lower() == "host":
                v = CSIC_HOST
            if k.lower() == "content-length":
                continue
            headers.append([k.strip(), v])
        w.add(id=f"csic/{split}/{i}", source="b1nch3f/csic-dataset",
              label="benign" if lab == "Normal" else "attack", category="csic-anomalous" if lab != "Normal" else "normal",
              context="bump", method=method, url=url, headers=headers, body=body.strip("\n"))
w.close()

# ── pirocheto/phishing-url: the same URL in both contexts ──
w = Writer("phishing-url")
for split in ("train", "test"):
    t = pq.read_table(ds("pirocheto/phishing-url", "data", f"{split}.parquet"), columns=["url", "status"])
    for i, (url, st) in enumerate(zip(t.column("url").to_pylist(), t.column("status").to_pylist())):
        host = urlsplit(url).hostname
        if not host:
            continue
        lab = "attack" if st == "phishing" else "benign"
        cat = "phishing" if st == "phishing" else "legitimate"
        w.add(id=f"phish/{split}/{i}/bump", source="pirocheto/phishing-url", label=lab, category=cat,
              context="bump", method="GET", url=url)
        w.add(id=f"phish/{split}/{i}/nobump", source="pirocheto/phishing-url", label=lab, category=cat, **connect(host))
w.close()

# ── DRIFT T25: DGA domains by family, and benign domains. Sampled: about
# 20k benign, and at most 300 domains per DGA family. ──
w = Writer("drift-dga-t25")
pf = pq.ParquetFile(ds("snsec-net/dga-detection-drift26dsn", "raw_including_TLD", "T25_benign.parquet"))
n = 0
for rg in range(pf.num_row_groups):
    for dom in pf.read_row_group(rg, columns=["domain"]).column("domain").to_pylist():
        if keep("drift-benign/" + dom, 8600):  # about 20k of 2.34M
            w.add(id=f"drift/benign/{dom}", source="snsec-net/dga-detection-drift26dsn", label="benign",
                  category="benign", **connect(dom))
per_family = {}
pf = pq.ParquetFile(ds("snsec-net/dga-detection-drift26dsn", "raw_including_TLD", "T25_dga.parquet"))
for rg in range(pf.num_row_groups):
    t = pf.read_row_group(rg, columns=["domain", "family"])
    for dom, fam in zip(t.column("domain").to_pylist(), t.column("family").to_pylist()):
        if per_family.get(fam, 0) >= 300 or not keep("drift-dga/" + dom, 20000):
            continue
        per_family[fam] = per_family.get(fam, 0) + 1
        w.add(id=f"drift/{fam}/{dom}", source="snsec-net/dga-detection-drift26dsn", label="attack",
              category="dga:" + fam, **connect(dom))
w.close()
print("  DGA families:", len(per_family), flush=True)

# ── Fox-IT Cobalt Strike beacons: HTTP(S) beacons only (DNS beacons do not
# cross the proxy). nobump: the C2 host; bump: GET host/uri with the
# beacon's User-Agent and its decoded query parameters. ──
w = Writer("cobaltstrike-beacons")
seen_host, seen_req = set(), set()
pf = pq.ParquetFile(ds("fox-srt/cobaltstrike-beacon-corpus", "data", "beacons.parquet"))
for rg in range(pf.num_row_groups):
    t = pf.read_row_group(rg, columns=["config_json", "protocol"])
    for cfg, proto in zip(t.column("config_json").to_pylist(), t.column("protocol").to_pylist()):
        if not cfg or proto not in ("http", "https"):
            continue
        d = json.loads(cfg)
        s = d.get("settings") or {}
        parts = [p for p in str(s.get("SETTING_DOMAINS") or "").split(",") if p]
        ua = s.get("SETTING_USERAGENT") or ""
        params = []
        for item in s.get("SETTING_C2_REQUEST") or []:
            if isinstance(item, list) and len(item) == 2 and item[0] == "_PARAMETER":
                try:
                    params.append(bytes.fromhex(item[1]).decode("latin-1"))
                except ValueError:
                    pass
        pairs = []
        for field, uri in zip(parts[0::2], parts[1::2]):
            # A field can hold several hosts separated by spaces.
            for host in field.split():
                pairs.append((host.strip().lower(), uri))
        for host, uri in pairs:
            if not host or "/" in host:
                continue
            if host not in seen_host and len(seen_host) < 20000:
                seen_host.add(host)
                w.add(id=f"cs/host/{host}", source="fox-srt/cobaltstrike-beacon-corpus", label="attack",
                      category="c2-host", **connect(host))
            scheme = "https" if proto == "https" else "http"
            url = f"{scheme}://{host}{uri if uri.startswith('/') else '/' + uri}"
            if params:
                url += "?" + "&".join(params)
            key = (url, ua)
            if key not in seen_req and len(seen_req) < 20000:
                seen_req.add(key)
                hdr = [["User-Agent", ua]] if ua else []
                w.add(id="cs/req/" + hashlib.sha256((url + "\x00" + ua).encode()).hexdigest()[:16],
                      source="fox-srt/cobaltstrike-beacon-corpus", label="attack", category="c2-http",
                      context="bump", method="GET", url=url, headers=hdr)
w.close()
