#!/usr/bin/env python3
"""Runs tools/acceptance_record_check.py over vectors.json. Compares result, the condition SET, and every other expected
member (disposition, key_step, policy_refusal). Stdlib only. Exit 0 iff all agree."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import acceptance_record_check as A

V = json.load(open(os.path.join(HERE, "vectors.json")))["vectors"]
bad = 0
for v in V:
    got, exp = A.check(v["case"]), v["expect"]
    ok = got["result"] == exp["result"] and set(got.get("conditions") or []) == set(exp["conditions"]) and \
        all(got.get(k) == x for k, x in exp.items() if k not in ("result", "conditions"))
    bad += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {v['id']:45s} {got['result']:15s} {sorted(got.get('conditions') or [])}")
print(f"{len(V) - bad}/{len(V)} agree")
sys.exit(1 if bad else 0)
