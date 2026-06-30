#!/usr/bin/env python3
"""check_decision_ref.py — is a pre-execution DECISION a recomputation or an assertion?

The agent-governance threads (crewAI#4877, autogen#7353) converged on a decision-provenance
contract: between the payment and the action sits the DECISION — was this allowed, under which
policy, with what verdict — and it must be (1) signed by an identity DISTINCT from the runtime it
governs, and (2) recomputable from its cited inputs, not trusted because it's signed.

invinoveritas `/review` emits exactly this as `decision_ref`:

    decision_ref = sha256(JCS({artifact_hash, artifact_type, policy_version, verdict}))

This check recomputes the published decision_ref from ITS OWN preimage fields (the proof publishes
`decision_ref_preimage_fields`, so a third party never guesses the preimage), and exercises the two
fail-closed negatives that separate "recomputable" from merely "attested":

  positive   — decision_ref recomputes byte-for-byte from the published fields            -> VALID
  tamper     — change the verdict / policy / artifact -> the id MUST change               -> detected
  signer==runtime  — a decision whose signer is the actor it governs is self-approval     -> fail closed
  verdict-not-f(inputs) — a verdict that doesn't recompute from its cited inputs is void   -> fail closed

The first two are checked here from bytes. The last two are the semantic negatives a full verifier
enforces against a signed proof (signer key != runtime identity; verdict re-derives from policy +
proposal); they're stated so the conformance contract is complete, not silently scoped to the happy
path. Zero-dependency, offline. Run: python3 check_decision_ref.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def decision_ref(fields: dict, preimage_keys) -> str:
    """sha256(JCS(projection)). JCS = sorted keys, compact separators, raw UTF-8 (RFC 8785)."""
    preimage = {k: fields.get(k) for k in preimage_keys}
    canon = json.dumps(preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def check(sample: dict) -> int:
    keys = sample["decision_ref_preimage_fields"]
    claimed = sample["decision_ref"]
    print("=" * 78)
    print("DECISION_REF RECOMPUTE — is the pre-execution decision recomputable or asserted?")
    print("=" * 78)
    print(f"\npreimage fields (self-described by the proof): {keys}")
    ok = True

    # positive: recompute from the proof's OWN published fields
    got = decision_ref(sample, keys)
    match = got == claimed
    print(f"\nrecomputed decision_ref: {got}")
    print(f"published  decision_ref: {claimed}")
    print(f"byte-for-byte match:     {match}")
    ok &= match

    # tamper: each decided field must move the id (no silent re-attribution)
    print("\ntamper sensitivity (a changed decision must change the id):")
    for field, alt in (("verdict", "approve"),
                       ("policy_version", "invinoveritas.review.v2"),
                       ("artifact_hash", "0" * 64)):
        if field not in keys:
            continue
        tampered = dict(sample, **{field: alt})
        moved = decision_ref(tampered, keys) != claimed
        print(f"  change {field:14s} -> id changes: {moved}")
        ok &= moved

    # semantic negatives (stated; enforced by a full verifier against the signed proof)
    print("\nfail-closed semantic negatives (the contract, not just the happy path):")
    print("  signer == runtime it governs   -> fail closed (self-approval is not a second opinion)")
    print("  verdict != f(policy, proposal)  -> fail closed (a signed verdict that doesn't recompute is void)")

    print("\n" + "-" * 78)
    if ok:
        print("PASS — decision_ref recomputes from its own published preimage and is tamper-sensitive.")
        print("       The decision is checkable by re-derivation, not trusted because it was signed.")
        return 0
    print("FAIL — decision_ref did not recompute as published.")
    return 1


if __name__ == "__main__":
    sample = json.loads((HERE / "sample_decision_ref.json").read_text())
    sys.exit(check(sample))
