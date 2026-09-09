#!/usr/bin/env python3
"""Full receipt adversarial matrix — huggingface/smolagents#2117
(Brodin2001's 2026-09-09 follow-up: how much enforcement comes from action
binding alone vs. the surrounding runtime/policy/replay/expiry context).

Extends action_binding_recompute.py (which only tested tool/args mutation)
to the FULL preimage invinoveritas's own /review endpoint actually binds:
tool, args, agent_id, policy_version, and a per-issuance nonce+consumption
record. Independently reimplemented from the deployed code's own
DECISION_REF_PREIMAGE_FIELDS list and services/proof_signing.py's
mark_decision_consumed()/is_decision_consumed() functions -- zero
dependencies, never imports invinoveritas or smolagents.

Covers 5 of Brodin2001's 7 adversarial cases with a real, runnable
mechanism. The other 2 are NOT attempted here, on purpose, and the reasons
are in the README:
  - expiry: invinoveritas deliberately ships no hard TTL (disclosed design
    choice, not a gap this script papers over) -- demonstrated below as an
    explicit non-coverage, not silently skipped.
  - alternate execution path bypassing the protected execution point: not a
    hash-comparison problem at all; needs inspection of the real calling
    framework's own call-routing guarantees, not a standalone fixture.
"""
import hashlib
import json
import time


def jcs(obj) -> bytes:
    """Minimal RFC 8785 JCS -- see action_binding_recompute.py's own
    docstring for the same disclosed scope limit (ASCII/int vectors only)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def receipt_preimage_hash(tool: str, args: dict, agent_id: str, policy_version: str) -> str:
    """Mirrors invinoveritas's real decision_ref preimage: binds WHAT (tool,
    args), WHO (agent_id), and UNDER WHICH RULES (policy_version) into one
    hash. The real endpoint hashes a larger preimage (source_class,
    verified_at, etc.) -- this keeps only the fields relevant to
    Brodin2001's matrix so the mechanism is legible, not the full real
    preimage byte-for-byte."""
    preimage = {
        "tool_hash": hashlib.sha256(tool.encode("utf-8")).hexdigest(),
        "args_hash": hashlib.sha256(jcs(args)).hexdigest(),
        "agent_id": agent_id,
        "policy_version": policy_version,
    }
    return hashlib.sha256(jcs(preimage)).hexdigest()


class ConsumptionLedger:
    """Real mechanism this mirrors: services/proof_signing.py's
    consumed_decisions table, PRIMARY KEY(decision_ref) -- the INSERT
    failing IS the atomic check-and-consume, no read-then-write race.
    Reproduced here with a plain set() since the property under test
    (first-consumer-wins, replay rejected) doesn't need real SQLite."""

    def __init__(self):
        self._consumed = set()

    def consume(self, receipt_hash: str) -> bool:
        if receipt_hash in self._consumed:
            return False  # already consumed -- real replay-rejection path
        self._consumed.add(receipt_hash)
        return True


def main() -> None:
    baseline = dict(tool="refund", args={"customer": "A", "amount": 100},
                     agent_id="support-agent-1", policy_version="v3")
    base_hash = receipt_preimage_hash(**baseline)
    print(f"authorized receipt hash: {base_hash}\n")

    # Case: authorized action, then policy changes.
    policy_changed = receipt_preimage_hash(**{**baseline, "policy_version": "v4"})
    assert policy_changed != base_hash, "FAIL: policy_version change did not alter the hash"
    print("[policy-change]   policy v3->v4, same tool/args/agent: hash DIFFERS "
          f"({policy_changed[:16]}... vs {base_hash[:16]}...) -- a verifier recomputing "
          "against the CURRENT policy_version rejects a receipt issued under a superseded one.")

    # Case: authorized action, then agent identity changes.
    identity_changed = receipt_preimage_hash(**{**baseline, "agent_id": "support-agent-2"})
    assert identity_changed != base_hash, "FAIL: agent_id change did not alter the hash"
    print("[identity-change] agent support-agent-1->support-agent-2, same tool/args/policy: "
          f"hash DIFFERS ({identity_changed[:16]}... vs {base_hash[:16]}...) -- covers AGENT "
          "identity specifically. 'Runtime identity' as a separate axis from agent_id is NOT "
          "distinguished today -- disclosed gap, not claimed coverage.")

    # Case: receipt replay.
    ledger = ConsumptionLedger()
    first = ledger.consume(base_hash)
    second = ledger.consume(base_hash)
    assert first is True and second is False, "FAIL: replay was not rejected on 2nd presentation"
    print(f"[replay]          1st consume() -> {first} (accepted), "
          f"2nd consume() of the SAME hash -> {second} (rejected) -- atomic "
          "check-and-consume, first presenter wins.")

    # Case: expiry -- explicit NON-coverage, demonstrated rather than asserted.
    issued_at = time.time() - (365 * 24 * 3600)  # simulate a receipt issued a year ago
    hash_at_issuance = receipt_preimage_hash(**baseline)
    hash_today = receipt_preimage_hash(**baseline)  # no time field in the preimage at all
    assert hash_at_issuance == hash_today, (
        "this equality IS the point: nothing in the preimage encodes issuance time, "
        "so a receipt from a year ago recomputes identically to one from right now")
    print(f"[expiry]          receipt issued {int(time.time() - issued_at)}s ago recomputes to "
          "the IDENTICAL hash as one issued right now -- invinoveritas ships no hard TTL BY "
          "DESIGN (nonce + consumption gives single-use, not time-boxing). If AgentGuard has "
          "a real expiry field, that is a genuine design difference, not a bug on either side.")

    # Cases already covered in action_binding_recompute.py: target/argument mutation.
    amount_mutated = receipt_preimage_hash(**{**baseline, "args": {"customer": "A", "amount": 1000}})
    target_mutated = receipt_preimage_hash(**{**baseline, "args": {"customer": "B", "amount": 100}})
    assert amount_mutated != base_hash and target_mutated != base_hash
    print("[mutation]        amount/target mutation: already covered, see "
          "action_binding_recompute.py in this same directory.\n")

    print("NOT attempted here: 'alternate execution path that bypasses the protected "
          "execution point' -- see this example's README for why that's not a hash-comparison "
          "problem at all.")


if __name__ == "__main__":
    main()
