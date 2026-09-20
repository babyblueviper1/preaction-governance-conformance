#!/usr/bin/env python3
"""Check a related_decision_ref chain offline: python3 proof_chain_check.py OUTER_EVENT.json INNER_EVENT.json
Needs only `pip install invinoveritas-verify`. Deterministic; prints the field-by-field comparison."""
import json, re, subprocess, sys
outer, inner = (json.load(open(p)) for p in sys.argv[1:3])
def verify(path):
    r = json.loads(subprocess.run(["invinoveritas-verify", path], capture_output=True, text=True).stdout)
    return r["valid"], r["proof_payload"]
ov, op = verify(sys.argv[1]); iv, ip = verify(sys.argv[2])
claim = op["disclosed_summary"]                       # bound into outer decision_ref
checks = {
  "outer proof valid (id, schnorr, issuer)": ov,
  "inner proof valid (id, schnorr, issuer)": iv,
  "outer.related_decision_ref == inner.decision_ref": op.get("related_decision_ref") == ip["decision_ref"],
  "outer.context_provenance derived == bound_to_verified_decision_ref": (op["context_provenance"] == "bound_to_verified_decision_ref") == (op.get("related_decision_ref") is not None),
  "claim names inner decision_ref": ip["decision_ref"] in claim,
  "claim names inner event id": inner["id"] in claim,
  "claim artifact_hash == inner.artifact_hash": ip["artifact_hash"] in claim,
  "claim verdict == inner.verdict": ip["verdict"] in claim,
  "claim verified_at == inner.verified_at": str(ip["verified_at"]) in claim,
  "claim policy_version == inner.policy_version": ip["policy_version"] in claim,
}
for k, v in checks.items(): print(("PASS " if v else "FAIL ") + k)
sys.exit(0 if all(checks.values()) else 1)
