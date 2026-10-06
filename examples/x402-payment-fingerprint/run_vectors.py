#!/usr/bin/env python3
"""Runs vectors.json against fingerprint.py: every expectation must match; copies of one payment_id must share one fingerprint; different
payment_ids must differ. Exit 0 only if all pass."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from fingerprint import fingerprint  # noqa: E402
doc = json.load(open(os.path.join(HERE, "vectors.json"))); bad = 0; fp = {}
for v in doc["vectors"]:
    held = v["held"]
    try:
        acc = held.get("accepted", held)
        out, val = fingerprint({"network": acc.get("network"), "asset": acc.get("asset"), "scheme": acc.get("scheme"),
                                 "authorization": held["payload"]["authorization"]})
    except (KeyError, TypeError, AttributeError):
        out, val = "malformed", "envelope_unreadable"
    exp = v["expect"]; ok = out == exp["outcome"] and val == exp.get("fingerprint", exp.get("condition"))
    bad += not ok; print(("ok  " if ok else "FAIL"), v["name"], out, val[:24] if out == "ok" else val)
    if out == "ok": fp.setdefault(v["payment_id"], set()).add(val)
pair_ok = all(len(s) == 1 for s in fp.values()) and len({next(iter(s)) for s in fp.values()}) == len(fp)
print("same payment -> one fingerprint, different payments -> different:", "ok" if pair_ok else "FAIL")
print("ALL PASS" if not bad and pair_ok else f"{bad} FAIL"); sys.exit(0 if not bad and pair_ok else 1)
