#!/usr/bin/env python3
"""Show each precedence vector is load-bearing: apply a mutant to a temp copy of tools/related_claims_check.py and confirm the
vectors that SHOULD catch it go red and the others stay green (x402-foundation/tsc#4). Stdlib only.
    python3 examples/trace-v20-fixtures/run_mutants.py"""
import json, os, shutil, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
src = os.path.join(here, "..", "..", "tools", "related_claims_check.py")
spec = json.load(open(os.path.join(here, "precedence_vectors.json")))
MUTANTS = [
    ("absence outranks failure (precedence flipped)",
     "    if any(s == FAIL for s, _, _ in res):\n        return 1\n    return 2 if any(s == CANNOT for s, _, _ in res) else 0",
     "    if any(s == CANNOT for s, _, _ in res):\n        return 2\n    return 1 if any(s == FAIL for s, _, _ in res) else 0",
     {"mixed_forged_outer_inner_absent"}),
    ("complete-set declaration ignored",
     "        if COMPLETE:", "        if False:", {"absence_declared_complete"}),
]
bad = 0
for name, old, new, expect_red in MUTANTS:
    d = tempfile.mkdtemp()
    root = os.path.abspath(os.path.join(here, "..", ".."))
    shutil.copytree(root, os.path.join(d, "r"), ignore=shutil.ignore_patterns(".git"))   # the checker imports repo-root helpers
    p = os.path.join(d, "r", "tools", "related_claims_check.py")
    s = open(p).read()
    assert s.count(old) == 1, f"mutant anchor not found: {name}"
    open(p, "w").write(s.replace(old, new))
    red = set()
    for v in spec["vectors"]:
        args = [a if a == "-" or a.startswith("--") else os.path.join(here, a) for a in v["args"]]
        if subprocess.run([sys.executable, p, *args], capture_output=True).returncode != v["expect_exit"]:
            red.add(v["id"])
    ok = red == expect_red
    bad += not ok
    print(f"{'ok  ' if ok else 'BAD '} mutant: {name:<48} caught by {sorted(red)} (expected {sorted(expect_red)})")
    shutil.rmtree(d)
sys.exit(1 if bad else 0)
