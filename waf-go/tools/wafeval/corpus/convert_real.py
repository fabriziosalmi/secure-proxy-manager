#!/usr/bin/env python3
"""Turn a real installation's Squid access logs into a wafeval corpus.

Usage: convert_real.py OUT.jsonl access.log [access.log.0 ...]

Reads the 'spm' log format (generate_squid_conf.sh): timestamp, elapsed,
client, code/status, bytes, method, URL, user, hierarchy, type, WAF event
ID, access reason, WAF reason. Keeps only requests from clients outside the
Docker and loopback ranges: the local ones are the canary and the test
probes, which attack on purpose. Distinct (method, URL) pairs are kept once.

Every record is labelled benign: it is traffic a person or a service on the
network actually sent. That is an assumption, so the category records what
production decided (prod:allowed, prod:waf-block, prod:other-deny), and a
block in the report is a record to look at, not a counted false positive.

The access log holds no request headers or bodies, so the bump context here
is the URL only. Output stays on the machine it is written on.
"""
import ipaddress, json, sys

out_path, logs = sys.argv[1], sys.argv[2:]
LOCAL = [ipaddress.ip_network(n) for n in ("172.16.0.0/12", "127.0.0.0/8", "::1/128")]
seen, lines, kept, local = set(), 0, 0, 0
counts = {}
with open(out_path + ".tmp", "w") as out:
    for path in logs:
        for ln in open(path, errors="replace"):
            f = ln.split()
            if len(f) < 7:
                continue
            lines += 1
            try:
                ip = ipaddress.ip_address(f[2])
            except ValueError:
                continue
            if any(ip in n for n in LOCAL):
                local += 1
                continue
            method, url = f[5], f[6]
            if (method, url) in seen:
                continue
            seen.add((method, url))
            status = f[3].split("/")[-1]
            waf = f[12] if len(f) > 12 else "-"
            prod = "prod:waf-block" if waf == "waf" else ("prod:other-deny" if status in ("403", "407") else "prod:allowed")
            if method == "CONNECT":
                ctx = "nobump"
            elif url.startswith(("http://", "https://")):
                ctx = "bump"
            else:
                continue
            rec = {"id": f"real/{len(seen)}", "source": "real-traffic", "label": "benign", "category": prod,
                   "context": ctx, "method": method, "url": url, "headers": [], "body": ""}
            out.write(json.dumps(rec, sort_keys=True) + "\n")
            kept += 1
            counts[(ctx, prod)] = counts.get((ctx, prod), 0) + 1
import os
os.replace(out_path + ".tmp", out_path)
print(f"lines {lines}, local skipped {local}, distinct kept {kept}", {f"{c}/{p}": n for (c, p), n in sorted(counts.items())})
