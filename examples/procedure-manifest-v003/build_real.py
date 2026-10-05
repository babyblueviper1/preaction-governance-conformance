#!/usr/bin/env python3
"""Real-object vectors: built from artifacts produced by live systems, not by build.py.
  real/live_review_2026-09-28_admission_240.json -- api.babyblueviper.com /review, 2026-09-28, admission_index 240: our requester-signed
      submission_commitment (BIP-340) and the provider's admission receipt bound to it by hash (receipt_hash chain).
  ../submission-commitment/events/valid_commitment.json -- the live commitment from t/29563 #16 (2026-09-21)."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
OUT = os.path.join(HERE, "vectors")
live = json.load(open(os.path.join(HERE, "real", "live_review_2026-09-28_admission_240.json")))
commit921 = json.load(open(os.path.join(HERE, "..", "submission-commitment", "events", "valid_commitment.json")))
def manifest(text):
    return {"spec": "procedure-manifest", "version": "0.0.3", "contract_id": "contract-pm003-real",
            "acquisition": {"provenance_profile": "invinoveritas-admission-chain-v1",
                            "claim_semantics": "hash-chained admission receipt (receipt_hash over admission_index, accepted_at, request_digest, prev_receipt_hash[, submission_commitment_ref]); periodic Merkle/OpenTimestamps checkpoints",
                            "retry_policy": {"allowed_after": ["ATTESTED_NO_RESULT"], "max_attempts": 1}},
            "requirements": [{"requirement_id": "R1", "judge_id": "J1", "request_text": text,
                              "required_scope": ["criteria:R1"]}]}
def put(name, desc, m, receipt, subs, expect):
    json.dump({"name": name, "description": desc, "real_object": True, "manifest": m, "admission_receipt": receipt,
               "submission_commitments": subs, "expect": expect}, open(os.path.join(OUT, name + ".json"), "w"), indent=1, sort_keys=True)
exact = live["artifact"]; other = exact.replace("model=pin:judge-weights-2026-09", "model=pin:judge-weights-2026-08")
assert other != exact
put("R-F3-real-receipt-wrong-request", "REAL live receipt (admission 240) against a manifest committing the same request with a different model pin: request binding false (C17).",
    manifest(other), live["admission_receipt"], [live["submission_commitment"]],
    {"run_verdict": "UNRESOLVED", "eligible": False, "state": "CLAIMED", "terms": {"exact_request_binding": "false", "authorized_execution": "cannot_establish"}})
put("R-P-real-receipt-exact-request", "REAL live receipt against the exact committed request: request binding TRUE. Still UNRESOLVED -- this profile has no pre-authorized run_id, so authorized_execution cannot be established (C16), and the draft says cannot_establish never acquires authority.",
    manifest(exact), live["admission_receipt"], [live["submission_commitment"]],
    {"run_verdict": "UNRESOLVED", "eligible": False, "state": "CLAIMED", "terms": {"exact_request_binding": "true", "authorized_execution": "cannot_establish"}})
put("R-F5-real-commitment-no-admission", "REAL requester-signed submission_commitment (2026-09-21, BIP-340) with no provider admission: preserved and verified as evidence, never admission (section 2, C18).",
    manifest(exact), None, [commit921],
    {"run_verdict": "UNRESOLVED", "eligible": False, "state": "AUTHORIZED", "terms": {"authorized_execution": "false"}})
print("built 3 real-object vectors")
