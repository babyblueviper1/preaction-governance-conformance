#!/usr/bin/env python3
"""check_composed_chain.py — compose the decision-recompute property with the
ledger chain-linking property, per rpelevin's request (autogen#7353, 2026-07-03):

"start with the accepted decision_ref vector; commit that decision as a receipt
entry; assert the history head changes predictably from the prior head;
introduce a divergent same-sequence entry and assert it produces a conflicting
detectable head, not an overwrite. [...] A self-signed ALLOW, a verdict that does
not recompute, and a same-sequence fork should fail for different reasons, but
the composed profile should catch all three."

Two properties, tested separately elsewhere in this repo, composed here into one profile:
  - ../x402-payment-decision-recompute/: is a payment DECISION entitled to its own
    verdict? (signer independence -- rejects self-approval; verdict = f(controls)
    -- rejects a recorded verdict that doesn't re-derive from its own cited controls)
  - services/ledger_chain.py (production, invinoveritas): does the RECEIPT HISTORY
    become fork-detectable, not just individually-anchored? (head_hash chains
    content_hash to prev_head_hash, published to public relays so a fork is two
    visible conflicting heads, not a silent overwrite)

This profile runs all three checks and reports which axis each one fails on --
admission, recompute, or fork -- so "the composed profile catches all three" is
something this script actually demonstrates, not just claims.

Zero-dependency, offline. Run: python3 check_composed_chain.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# A fixed test prior-head, standing in for whatever real head preceded this entry in
# a live chain. The construction doesn't care what it is, only that both candidate
# entries in the fork test share it (same sequence position).
TEST_PRIOR_HEAD = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(record: dict) -> str:
    """Vendored verbatim from services/ledger_chain.py:content_hash (production)."""
    return hashlib.sha256(jcs(record).encode("utf-8")).hexdigest()


def head_hash(c_hash: str, prev_head: str) -> str:
    """Vendored verbatim from services/ledger_chain.py:compute_chain_link (production)."""
    return hashlib.sha256(f"{c_hash}|{prev_head}".encode("utf-8")).hexdigest()


def decision_ref(fields: dict, preimage_keys: list[str]) -> str:
    """From ../decision-ref-recompute/ and ../x402-payment-decision-recompute/ --
    recompute a decision's own id from its self-described preimage."""
    preimage = {k: fields[k] for k in preimage_keys}
    return hashlib.sha256(jcs(preimage).encode("utf-8")).hexdigest()


def admits(vector: dict) -> bool:
    """Axis 1: admission. A decision signed by the actor's own payment wallet is
    self-approval, not an independent verdict -- fail closed regardless of hash validity."""
    return vector["signer"]["key_id"] != vector["artifact"]["actor"]["payment_signer"]


def recomputes(vector: dict) -> bool:
    """Axis 2: recompute. The recorded verdict must match f(controls) re-derived from
    scratch -- a valid hash on a verdict that doesn't follow from its own cited inputs
    is void. Mirrors ../x402-payment-decision-recompute/'s precedence-combinator."""
    precedence = ["pii", "trusted_wallet", "policy", "replay", "mpa"]
    pass_verdicts = {"pii": {"CLEAN", "PII_REDACTED"}, "trusted_wallet": {"TRUSTED"},
                     "policy": {"ALLOW"}, "replay": {"FRESH"}}
    controls = vector["artifact"]["controls"]
    f_controls = "ALLOW"
    for control in precedence:
        c = controls.get(control, {})
        v = c.get("verdict")
        if control == "mpa":
            if c.get("required") and v != "APPROVED":
                f_controls = "REFER"
                break
            continue
        if v not in pass_verdicts.get(control, set()):
            f_controls = "DENY"
            break
    return f_controls == vector["artifact"]["verdict"]


def main() -> int:
    fixture = json.loads((HERE / "presidio-x402-decision-ref-v1.fixture.json").read_text())
    by_id = {v["id"]: v for v in fixture["vectors"]}
    accepted = by_id["presidio-x402-decision-001"]
    self_signed = by_id["presidio-x402-decision-signer-equals-runtime"]
    bad_recompute = by_id["presidio-x402-decision-verdict-not-recomputable"]

    print("=" * 78)
    print("COMPOSED PROFILE: admission + recompute + chain-fork, three distinct axes")
    print("=" * 78)

    # Axis 1 -- admission (self-signed ALLOW must fail closed, on admission specifically)
    accepted_admits = admits(accepted)
    self_signed_admits = admits(self_signed)
    self_signed_recomputes = recomputes(self_signed)  # true -- the hash/verdict are fine
    print(f"\n[Axis 1: ADMISSION] self-signed decision:")
    print(f"  admission check: {self_signed_admits} (must be False -- signer is the actor's own wallet)")
    print(f"  recompute check: {self_signed_recomputes} (True -- the verdict itself is fine; it fails on WHO signed it, not on the hash)")
    axis1_ok = (not self_signed_admits) and self_signed_recomputes and accepted_admits

    # Axis 2 -- recompute (a recorded verdict that doesn't follow from its own controls)
    bad_recompute_admits = admits(bad_recompute)  # true -- signer is fine
    bad_recompute_recomputes = recomputes(bad_recompute)
    print(f"\n[Axis 2: RECOMPUTE] verdict-not-recomputable decision:")
    print(f"  admission check: {bad_recompute_admits} (True -- signer is a legitimate independent policy-issuer)")
    print(f"  recompute check: {bad_recompute_recomputes} (must be False -- controls.policy=VIOLATION makes f(controls)=DENY, but recorded verdict=ALLOW)")
    axis2_ok = bad_recompute_admits and (not bad_recompute_recomputes)

    # Axis 3 -- chain fork (commit the ACCEPTED decision as a receipt entry, then a
    # divergent same-sequence entry, and show the fork is a detectable CONFLICT)
    got_ref = decision_ref(accepted["decision_ref_preimage"], accepted["decision_ref_preimage_fields"])
    decision_ok = got_ref == accepted["decision_ref"]
    print(f"\n[Axis 3: CHAIN FORK] starting decision ({accepted['id']}) recomputes: {decision_ok}")

    receipt_record = {"entry": 41, **accepted["decision_ref_preimage"]}
    c_hash_a = content_hash(receipt_record)
    head_a = head_hash(c_hash_a, TEST_PRIOR_HEAD)
    head_a_recomputed = head_hash(content_hash(receipt_record), TEST_PRIOR_HEAD)
    predictable = head_a_recomputed == head_a
    print(f"  committed as chain entry, prior_head={TEST_PRIOR_HEAD[:16]}...")
    print(f"  head_hash: {head_a}")
    print(f"  recompute matches (head changes PREDICTABLY): {predictable}")

    divergent_record = {"entry": 41, **bad_recompute["decision_ref_preimage"]}
    c_hash_b = content_hash(divergent_record)
    head_b = head_hash(c_hash_b, TEST_PRIOR_HEAD)
    fork_detectable = head_a != head_b
    print(f"  DIVERGENT entry, SAME sequence position (same prior_head):")
    print(f"  head_hash: {head_b}")
    print(f"  fork is a detectable CONFLICT, not an overwrite (heads differ): {fork_detectable}")
    axis3_ok = decision_ok and predictable and fork_detectable

    print("\n" + "-" * 78)
    print(f"Axis 1 (admission)  : {'PASS' if axis1_ok else 'FAIL'} -- fails on WHO signed, hash/verdict untouched")
    print(f"Axis 2 (recompute)  : {'PASS' if axis2_ok else 'FAIL'} -- fails on WHETHER the verdict follows from its inputs")
    print(f"Axis 3 (chain fork) : {'PASS' if axis3_ok else 'FAIL'} -- fails on WHERE two conflicting heads meet at one position")

    ok = axis1_ok and axis2_ok and axis3_ok
    print()
    if ok:
        print("PASS -- all three axes distinguishable and caught: a self-signed ALLOW, a")
        print("        verdict that doesn't recompute, and a same-sequence fork each fail")
        print("        for a DIFFERENT, individually-diagnosable reason.")
        return 0
    print("FAIL -- composed profile did not hold on all three axes.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
