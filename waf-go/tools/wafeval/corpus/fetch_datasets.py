#!/usr/bin/env python3
"""Download the files in datasets.manifest.json into DEST, verifying size and
sha256 against the manifest. A file already present with the right digest is
kept; a mismatch is a failure, never a silent overwrite. Stdlib only."""
import hashlib, json, os, sys, urllib.request

manifest, dest = sys.argv[1], sys.argv[2]
files = json.load(open(manifest))["files"]
bad = 0
for f in files:
    path = os.path.join(dest, f["dataset"].replace("/", "__"), f["file"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() == f["sha256"]:
            print("KEEP", f["dataset"], f["file"], flush=True)
            continue
        print("STALE", path, "digest mismatch; refetching", flush=True)
    tmp = path + ".part"
    h = hashlib.sha256(); n = 0
    with urllib.request.urlopen(f["url"], timeout=60) as r, open(tmp, "wb") as out:
        for chunk in iter(lambda: r.read(1 << 20), b""):
            out.write(chunk); h.update(chunk); n += len(chunk)
    if n != f["size"] or h.hexdigest() != f["sha256"]:
        print("FAIL", f["dataset"], f["file"], "size", n, "expected", f["size"], "sha256", h.hexdigest(), flush=True)
        os.remove(tmp); bad += 1; continue
    os.replace(tmp, path)
    print("OK  ", f["dataset"], f["file"], n, flush=True)
print("done:", len(files) - bad, "verified,", bad, "failed", flush=True)
sys.exit(1 if bad else 0)
