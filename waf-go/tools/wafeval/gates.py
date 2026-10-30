#!/usr/bin/env python3
"""Phase A gates, judged from wafeval reports, not by eye.

Usage: gates.py REF.json HYBRID.json   (both runs over the same corpora)

REF is spm-observe (spm with DLP and FIN observe-only), HYBRID the
candidate. Prints every gate with PASS or FAIL and the cells behind a
failure; exits 1 if any gate fails.
"""
import json, sys

ref, hyb = (json.load(open(p)) for p in sys.argv[1:3])
fails = 0


def gate(name, ok, detail=""):
    global fails
    fails += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else (f"  ({detail})" if detail else "")))


def cells(r, key):
    return {(c["source"], c["context"], c.get("category", "")): c for c in r[key]}


H, R = cells(hyb, "summary"), cells(ref, "summary")
HC, RC = cells(hyb, "by_category"), cells(ref, "by_category")
records = {c["file"]: c["records"] for c in hyb["corpus"]}

# A1: responses are counted, none lost to the parser; the suite's two
# response cases are blocked.
resp_sources = [k for k in H if k[0] in ("prowlbench-download", "tranco-responses")]
perr = {k: H[k]["parse_errors"] for k in resp_sources}
counted = all(H[k]["tp"] + H[k]["fn"] + H[k]["fp"] + H[k]["tn"] > 0 for k in resp_sources)
suite_resp = [HC[k] for k in HC if k[0] == "adversarial-suite" and k[2].startswith("RESPONSE_")]
gate("A1 responses inspected, none lost to the parser", counted and not any(perr.values()) and len(resp_sources) == 2, f"parse errors {perr}")
gate("A1 the suite's response cases are blocked", len(suite_resp) == 2 and all(c["tp"] == 1 for c in suite_resp),
     f"{[(c['category'], c['tp'], c['fn']) for c in suite_resp]}")

# A2: no regression against the reference in any cell that has attacks.
reg = []
for k, rc in RC.items():
    if rc["tp"] + rc["fn"] == 0 or k not in HC:
        continue
    if HC[k]["tpr"] + 1e-9 < rc["tpr"]:
        reg.append(f"{k[0]}|{k[1]}|{k[2]}: hybrid {HC[k]['tpr']:.3f} < ref {rc['tpr']:.3f}")
gate("A2 no regression against spm-observe in any attack cell", not reg, "; ".join(sorted(reg)[:15]) + (f" (+{len(reg)-15} more)" if len(reg) > 15 else ""))

# A3: false-positive rate: 0.0005 for documents and
# uploads, 0.002 for subresources (images, pixels, scripts, fetches) of the
# real-browser crawl, where a false positive is a broken pixel, not a page.
SUBRESOURCE_LIMIT = 0.002
fp = []
for k, c in H.items():
    if c["fp"] + c["tn"] == 0:
        continue
    if k[0] == "tranco-requests" and k[1] == "bump":
        continue  # judged per resource type below
    limit = 0 if k[0] == "real-traffic" else 0.0005
    if c["fpr"] > limit:
        fp.append(f"{k[0]}|{k[1]}: FPR {c['fpr']:.4f} ({c['fp']} of {c['fp']+c['tn']})")
for k, c in HC.items():
    if k[0] != "tranco-requests" or k[1] != "bump" or c["fp"] + c["tn"] == 0:
        continue
    # A navigation (document-top) is a page; an iframe (document-frame, ad
    # and cookie-sync frames) is not, and is judged with the subresources.
    limit = 0.0005 if k[2] == "document-top" else SUBRESOURCE_LIMIT
    if c["fpr"] > limit:
        fp.append(f"tranco-requests|bump|{k[2]}: FPR {c['fpr']:.4f} ({c['fp']} of {c['fp']+c['tn']}, limit {limit})")
gate("A3 FPR <= 0.0005 (documents, uploads, every other source), <= 0.002 (subresources), 0 on the real traffic", not fp, "; ".join(fp))

# A4: a payload in a custom header is caught as well as the same payload
# in the cookie by the reference (spm reads the cookie, and read no other
# header but five fixed ones), category by category, in the mutations.
hdr = []
for k, rc in RC.items():
    if k[0] != "mutations" or not k[2].startswith("t09-cookie|") or rc["tp"] + rc["fn"] == 0:
        continue
    hk = (k[0], k[1], k[2].replace("t09-cookie|", "t10-custom-header|", 1))
    if hk not in HC:
        hdr.append(f"{hk[2]}: missing")
    elif HC[hk]["tpr"] + 1e-9 < rc["tpr"]:
        hdr.append(f"{hk[2]}: hybrid {HC[hk]['tpr']:.2f} < ref cookie {rc['tpr']:.2f}")
gate("A4 a payload in a custom header is caught as well as in the cookie", bool(RC) and not hdr, "; ".join(sorted(hdr)))

# A5: latency.
lat = hyb.get("latency", {})
b, n = lat.get("bump", {}).get("p50_us", 1e9), lat.get("nobump", {}).get("p50_us", 1e9)
gate("A5 p50 <= 2000 us bump, <= 60 us nobump", b <= 2000 and n <= 60, f"bump {b:.0f} us, nobump {n:.0f} us")

# A6: the adversarial suite, request side: every attack blocked but
# dlp-github-pat, which is observe-only by decision.
# dlp-github-pat and cloud-aws-akia are alerts by decision (DLP, FIN and
# CLOUD_SECRETS observe-only).
ALERTS = ("|dlp-github-pat", "|cloud-aws-akia")
miss = [k[2] for k, c in HC.items() if k[0] == "adversarial-suite" and c["fn"] and not k[2].endswith(ALERTS)]
gate("A6 adversarial suite: every attack blocked but the observe-only ones (alerts)", not miss, f"missed {miss}")

print(f"\n{fails} gate(s) failing")
sys.exit(1 if fails else 0)
