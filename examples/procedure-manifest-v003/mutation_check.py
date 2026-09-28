#!/usr/bin/env python3
"""Mutation check: switching off each rule C16-C21 in check.py must flip at least one vector, or that rule is untested."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import check as C
V = [json.load(open(os.path.join(HERE, "vectors", f))) for f in sorted(os.listdir(os.path.join(HERE, "vectors"))) if f.endswith(".json")]
def flips():
    return [p["name"] for p in V if (lambda r: r["run_verdict"] != p["expect"]["run_verdict"] or r["eligible"] != p["expect"]["eligible"])(C.evaluate(p))]
assert not flips(), "baseline must pass"
bad = 0
for rule in ("C16", "C17", "C18", "C19", "C20", "C21"):
    C.DISABLED.clear(); C.DISABLED.add(rule); f = flips(); bad += not f
    print(f"disable {rule}: {'caught by ' + ', '.join(f) if f else 'NOT CAUGHT'}")
C.DISABLED.clear()
print("ALL RULES LOAD-BEARING" if not bad else f"{bad} rule(s) untested"); sys.exit(1 if bad else 0)
