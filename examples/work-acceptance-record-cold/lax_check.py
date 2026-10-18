"""Do the five vectors catch a lax verifier? Each lax checker skips one step of the README procedure."""
import copy
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import war_check as W  # noqa: E402

VDIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "upstream_vectors")
V = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(VDIR, "*.json")))]


def lax(skip):
    def run(inputs):
        out = W.check(inputs)
        if skip == "signature":
            out["signature_valid"] = True
            out["problem_codes"] = [c for c in out["problem_codes"] if c != "SIGNATURE_INVALID"]
        if skip == "criteria_hash":
            out["criteria_hash"] = "match"
            out["problem_codes"] = [c for c in out["problem_codes"] if c != "CRITERIA_HASH_MISMATCH"]
        if skip == "verdict_recompute":
            out["verdict_recomputed"] = out["verdict_stated"]
            out["problem_codes"] = [c for c in out["problem_codes"] if c != "VERDICT_MISMATCH"]
        if skip == "criteria_token_time":           # README step 4 as written: committed_at decides, the token is not read
            r = inputs["receipt"]["receipt"]
            ok = W._iso(r["criteria"]["committed_at"]) < W._iso(r["issued_utc"])
            out["criteria_committed_before_check"] = "yes" if ok else "no"
            out["problem_codes"] = [c for c in out["problem_codes"] if c not in ("COMMITTED_AT_MISMATCH", "CRITERIA_COMMITTED_AFTER_CHECK")] \
                + ([] if ok else ["CRITERIA_COMMITTED_AFTER_CHECK"])
        if skip == "receipt_timestamp":
            out["receipt_timestamp"] = "imprint_match" if out["receipt_timestamp"] != "none" else "none"
        return out
    return run


norm = lambda x: sorted(x) if isinstance(x, list) else x
for skip in ("signature", "criteria_hash", "verdict_recompute", "criteria_token_time", "receipt_timestamp"):
    caught = [v["description"][:40] for v in V
              if any(norm(lax(skip)(v["inputs"]).get(k)) != norm(v["expected"][k]) for k in v["expected"])]
    print(f"skips {skip:18s}: {'caught by ' + str(len(caught)) if caught else 'PASSES ALL ' + str(len(V)) + ' VECTORS'}")
