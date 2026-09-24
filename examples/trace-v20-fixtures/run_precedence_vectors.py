#!/usr/bin/env python3
"""Run precedence_vectors.json against tools/related_claims_check.py. Stdlib only.
    python3 examples/trace-v20-fixtures/run_precedence_vectors.py"""
import json, os, subprocess, sys
here = os.path.dirname(os.path.abspath(__file__))
checker = os.path.join(here, "..", "..", "tools", "related_claims_check.py")
spec = json.load(open(os.path.join(here, "precedence_vectors.json")))
bad = 0
for v in spec["vectors"]:
    args = [a if a == "-" else os.path.join(here, a) for a in v["args"]]
    rc = subprocess.run([sys.executable, checker, *args], capture_output=True).returncode
    ok = rc == v["expect_exit"]
    bad += not ok
    print(f"{'ok  ' if ok else 'BAD '} {v['id']:<34} exit={rc} expect={v['expect_exit']} ({v['expect']})")
sys.exit(1 if bad else 0)
