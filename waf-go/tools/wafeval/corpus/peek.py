#!/usr/bin/env python3
"""Second-pass records of peeked CONNECTs, from the nobump records.

Usage: peek.py OUT.jsonl TRANCO.jsonl CORPUS.jsonl [CORPUS.jsonl ...]

With ssl_bump peek then splice, Squid sends each CONNECT to the WAF twice;
the second time with the server name the client's TLS handshake asked for
(X-SPM-SNI) and the handshake itself (X-SPM-Client-Hello). For every
CONNECT record (context nobump) of the given corpora this writes:

- context "peek": the same CONNECT, server name = its host. What a client
  that does not hide anything sends.
- context "peek-evasion", attacks only: a CONNECT to a benign host of
  TRANCO.jsonl with the attack's host as the server name. What a client
  sends to get past a check on the CONNECT line.

The handshake is the first bytes of a real TLS 1.3 ClientHello as Squid
7.7 writes them in base64; the WAF reads only that it starts a ClientHello.
The benign host is picked by a hash of the record id, so the output is the
same on every run.
"""
import hashlib, json, sys

HANDSHAKE = "FgMBBiABAAYcAwO9XG6NdLOty8Ug"


def host(rec):
    return rec["url"].rsplit(":", 1)[0]


def connects(path):
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("context") == "nobump" and rec.get("method") == "CONNECT":
                yield rec


def main():
    out, tranco, corpora = sys.argv[1], sys.argv[2], sys.argv[3:]
    benign = sorted({rec["url"] for rec in connects(tranco) if rec["label"] == "benign"})
    n = {"peek": 0, "peek-evasion": 0}
    with open(out, "w") as w:
        for path in [tranco] + corpora:
            for rec in connects(path):
                same = dict(rec, id=rec["id"] + "|peek", context="peek", sni=host(rec), handshake=HANDSHAKE)
                w.write(json.dumps(same) + "\n")
                n["peek"] += 1
                if rec["label"] != "attack":
                    continue
                i = int(hashlib.sha256(rec["id"].encode()).hexdigest(), 16) % len(benign)
                ev = dict(rec, id=rec["id"] + "|evasion", context="peek-evasion", url=benign[i],
                          headers=[["Host", benign[i]]], sni=host(rec), handshake=HANDSHAKE)
                w.write(json.dumps(ev) + "\n")
                n["peek-evasion"] += 1
    print(f"{out}: {n['peek']} peek, {n['peek-evasion']} peek-evasion, {len(benign)} benign hosts")


if __name__ == "__main__":
    main()
