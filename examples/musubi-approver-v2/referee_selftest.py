#!/usr/bin/env python3
"""Offline self-test of batch_approval_v2.py the way a referee would run it: write vectors.json's fixtures WITHOUT their expect
fields to one batch file, run the command as a subprocess, compare every answer with expect. A missing case, an extra case, an
error or any difference counts against it. Also checks a malformed fixture comes back as {"error"} without ending the batch.
"""
import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
V = json.load(open(os.path.join(HERE, "vectors.json")))
cases = [{"name": v["id"], "contract": V["contracts"][v["contract"]], "approval": v.get("approval")} for v in V["vectors"]]
with tempfile.TemporaryDirectory() as d:
    i, o = os.path.join(d, "in.json"), os.path.join(d, "out.json")
    json.dump(cases + [{"name": "x-no-contract", "approval": None}], open(i, "w"))
    rc = subprocess.run([sys.executable, os.path.join(HERE, "batch_approval_v2.py"), i, o]).returncode
    got = json.load(open(o))
want = {v["id"]: {"result": v["expect"]["result"], "reason": v["expect"].get("reason")} for v in V["vectors"]}
agree = sum(got.get(k) == w for k, w in want.items())
for k, w in want.items():
    print(f"{'ok  ' if got.get(k) == w else 'NG  '} {k:44s} {got.get(k)}")
extra = set(got) - set(want) - {"x-no-contract"}
err_ok = "error" in got.get("x-no-contract", {})
print(f"{agree}/{len(want)} agree (referee-compared), exit {rc}, extra {sorted(extra) or 'none'}, malformed fixture -> error: {err_ok}")
sys.exit(0 if agree == len(want) and rc == 0 and not extra and err_ok else 1)
