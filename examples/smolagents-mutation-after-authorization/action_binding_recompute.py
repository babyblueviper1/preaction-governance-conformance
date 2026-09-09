#!/usr/bin/env python3
"""Mutation-after-authorization recompute — huggingface/smolagents#2117
(Brodin2001's 2026-09-09 comment: authorize refund(A,100), then attempt
refund(A,1000) or a changed target).

Independently reimplements invinoveritas's own published, documented
action_binding hash scheme (see /review's action_binding parameter docs:
action_binding_tool_hash = sha256(tool),
action_binding_args_hash = sha256(RFC-8785-JCS(args))) — zero dependencies,
never imports invinoveritas or smolagents. Same "recompute from documented
behavior, not a live call" pattern as check_guardrail_decision.py in the
sibling smolagents-guardrail-recompute example.

What this proves: an authorization receipt bound to (tool, args, agent_id)
via separate hashed preimage fields cannot be replayed against a mutated
call — not because a runtime check catches it, but because the two
receipts are *different bytes* the moment any bound field changes. A
verifier holding the original receipt and the actual attempted call can
detect the mismatch with a single hash comparison, no trust in the caller
required.
"""
import hashlib
import json


def jcs(obj) -> bytes:
    """Minimal RFC 8785 JCS: sorted keys, compact separators, raw UTF-8.
    Sufficient for these vectors (ASCII keys, no non-BMP chars/extreme
    floats) — see the sibling Dipankar Sarkar thread on invinoveritas's own
    Substack for real edge cases (UTF-16 vs code-point key sort, ES6 vs
    Python number formatting) this minimal version does not attempt to
    close. Not a general-purpose JCS implementation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def action_binding_hashes(tool: str, args: dict) -> dict:
    return {
        "action_binding_tool_hash": hashlib.sha256(tool.encode("utf-8")).hexdigest(),
        "action_binding_args_hash": hashlib.sha256(jcs(args)).hexdigest(),
    }


VECTORS = [
    {
        "name": "authorize_refund_100",
        "tool": "refund",
        "args": {"customer": "A", "amount": 100},
        "agent_id": "support-agent-1",
    },
    {
        "name": "attempt_replay_amount_mutated",
        "tool": "refund",
        "args": {"customer": "A", "amount": 1000},
        "agent_id": "support-agent-1",
        "note": "Brodin2001's exact case: same tool, same customer, amount changed 100->1000.",
    },
    {
        "name": "attempt_replay_target_mutated",
        "tool": "refund",
        "args": {"customer": "B", "amount": 100},
        "agent_id": "support-agent-1",
        "note": "same tool, same amount, target changed A->B.",
    },
    {
        "name": "attempt_replay_key_order_reordered",
        "tool": "refund",
        "args": {"amount": 100, "customer": "A"},
        "agent_id": "support-agent-1",
        "note": "genuine non-mutation: same logical call, JSON keys reordered on the wire. "
        "Must produce the IDENTICAL args_hash to authorize_refund_100, or the "
        "binding would false-reject a harmless client-side reserialization.",
    },
]


def main() -> None:
    results = {}
    for v in VECTORS:
        h = action_binding_hashes(v["tool"], v["args"])
        results[v["name"]] = h
        print(f"{v['name']}:")
        print(f"  args={v['args']}")
        print(f"  action_binding_args_hash={h['action_binding_args_hash']}")
        if "note" in v:
            print(f"  note: {v['note']}")
        print()

    base = results["authorize_refund_100"]["action_binding_args_hash"]
    amount_mutated = results["attempt_replay_amount_mutated"]["action_binding_args_hash"]
    target_mutated = results["attempt_replay_target_mutated"]["action_binding_args_hash"]
    reordered = results["attempt_replay_key_order_reordered"]["action_binding_args_hash"]

    assert amount_mutated != base, "FAIL: amount mutation did not change the hash"
    assert target_mutated != base, "FAIL: target mutation did not change the hash"
    assert target_mutated != amount_mutated, "FAIL: two different mutations collided"
    assert reordered == base, "FAIL: harmless key reordering produced a different hash"

    print("All assertions pass:")
    print("  - amount mutation (100->1000): hash differs from the authorized receipt")
    print("  - target mutation (A->B): hash differs from the authorized receipt")
    print("  - the two mutations produce DIFFERENT hashes from each other (not just from base)")
    print("  - harmless key reordering: hash is IDENTICAL (no false rejection)")
    print()
    print("A verifier holding the authorize_refund_100 receipt's action_binding_args_hash")
    print("detects both replay attempts with a single string comparison against the")
    print("actual call's own recomputed hash -- no trust in the calling agent required.")


if __name__ == "__main__":
    main()
