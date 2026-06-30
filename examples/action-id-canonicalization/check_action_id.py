#!/usr/bin/env python3
"""check_action_id.py — is a cross-implementation `action_id` claim a recomputation or an assertion?

crewAI#4877 / safal207 PR #63 converged three independent implementations on
`action_id = SHA-256(JCS(preimage))` as the canonical action identifier:
  - ibex-agent-verification (the ⟦#⛓✓⟧ reference chain),
  - AlgoVoi substrate (`action_ref`),
  - rgiskard Argentum trails.

"Three teams chose JCS" is a strong signal, but it is an *assertion* until someone recomputes it.
This check recomputes it, and separates the two claims people conflate:

  (A) CONSTRUCTION converges  — every team hashes JCS-canonical JSON, so key ORDER is irrelevant.
  (B) FIELD SET converges     — every team commits the SAME preimage, so the SAME logical action
                                yields the SAME id under all three builders.

(A) is true and provable. (B) is the one the alignment note actually gates on, and right now it is
FALSE: AlgoVoi commits `timestamp_ms` as an epoch-millis INTEGER, rgiskard commits `timestamp` as an
ISO-8601 STRING. Same action, different preimage, different id. So the teams converged on the
method, not the identifier — and a "shared conformance vector" can't mean "each team produces some
id," it must mean "one envelope -> one id under all three builders," which requires a single LOCKED
field set (PR #63's is the candidate).

This also operationalizes Correctover's deterministic-construction ask (crewAI#4877): the failure mode
is a non-deterministic preimage (e.g. a float, whose JCS form is implementation-specific). We fail
closed on that BY CONSTRUCTION — the restricted profile rejects floats before hashing.

  PASS  = construction is deterministic + order-independent + float-rejecting (provable here), AND
          the cross-builder divergence is exactly the declared field-set delta (no surprise drift).
Zero-dependency, offline. Run: python3 check_action_id.py
"""
from __future__ import annotations

import hashlib
import json
import sys


class NonCanonical(ValueError):
    """A value whose JCS form is implementation-specific — rejected before it can poison an id."""


def _assert_canonical(obj) -> None:
    """Restricted RFC-8785 profile: str / bool / int / None / nested only. Floats are refused —
    NaN, -0.0, and trailing-zero formatting are exactly the cross-implementation hazard safal207's
    PR #63 drew the boundary around. bool is a subclass of int and is allowed (JSON true/false)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise NonCanonical(f"non-string key: {k!r}")
            _assert_canonical(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _assert_canonical(v)
    elif isinstance(obj, float):
        raise NonCanonical("float in preimage — JCS number form is implementation-specific; fail closed")
    elif not isinstance(obj, (str, bool, int, type(None))):
        raise NonCanonical(f"unsupported type {type(obj).__name__}")


def action_id(preimage: dict) -> str:
    """action_id = SHA-256(JCS(preimage)). JCS = lexicographic key sort, compact separators, UTF-8.
    Deterministic and key-order independent by construction."""
    _assert_canonical(preimage)
    canon = json.dumps(preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


# One logical action, observed once. The three builders disagree only on how `timestamp` is committed.
ACTION = {
    "agent_id": "safeagent-prod",
    "action_type": "erc20_transfer",
    "scope": "f595c5b279ea38149afc8812acdb341c2c1714d874f61cd2cfde3f3de1c3853c",
    "iso": "2026-06-30T10:24:00.504Z",
    "ms": 1782815040504,
}

# Each builder's published preimage shape (field set + value types), per their reference impls.
BUILDERS = {
    "ibex/⟦#⛓✓⟧ (PR #63 locked set)":
        {"agent_id": ACTION["agent_id"], "action_type": ACTION["action_type"],
         "scope": ACTION["scope"], "timestamp": ACTION["iso"]},
    "AlgoVoi action_ref":
        {"agent_id": ACTION["agent_id"], "action_type": ACTION["action_type"],
         "scope": ACTION["scope"], "timestamp_ms": ACTION["ms"]},
    "rgiskard Argentum trail":
        {"action_type": ACTION["action_type"], "agent_id": ACTION["agent_id"],
         "scope": ACTION["scope"], "timestamp": ACTION["iso"]},
}


def check() -> int:
    print("=" * 78)
    print("ACTION_ID CANONICALIZATION — does the cross-implementation claim recompute?")
    print("=" * 78)
    ok = True

    # (A) CONSTRUCTION: deterministic + key-order independent (Correctover's determinism assertion).
    base = BUILDERS["ibex/⟦#⛓✓⟧ (PR #63 locked set)"]
    shuffled = dict(reversed(list(base.items())))
    det = action_id(base) == action_id(dict(base))
    order = action_id(base) == action_id(shuffled)
    print(f"\n(A) construction is deterministic (same input -> same id): {det}")
    print(f"(A) construction is key-order independent (JCS sorts keys):  {order}")
    ok &= det and order

    # Correctover's failure mode: a non-deterministic preimage must fail closed, not silently hash.
    try:
        action_id({**base, "amount": 12.5})
        print("(A) float preimage was accepted -> FAIL (should fail closed)")
        ok = False
    except NonCanonical:
        print("(A) float preimage fails closed (deterministic-construction guard):       True")

    # (B) FIELD SET: same action under each builder. Construction converges; preimage may not.
    print("\n(B) same logical action under each builder's published preimage:")
    ids = {}
    for name, pre in BUILDERS.items():
        aid = action_id(pre)
        ids[name] = aid
        print(f"    {name:34s} -> {aid[:23]}…")

    ibex = ids["ibex/⟦#⛓✓⟧ (PR #63 locked set)"]
    rgis = ids["rgiskard Argentum trail"]
    algo = ids["AlgoVoi action_ref"]
    # ibex and rgiskard share the field set (timestamp ISO string) -> MUST match by construction.
    same_fieldset = ibex == rgis
    # AlgoVoi uses timestamp_ms int -> MUST diverge. The divergence is the declared field-set delta.
    declared_divergence = algo != ibex
    print(f"\n    same field set (ibex == rgiskard, both `timestamp` ISO string): {same_fieldset}")
    print(f"    different field set (AlgoVoi `timestamp_ms` int diverges):     {declared_divergence}")
    ok &= same_fieldset and declared_divergence

    print("\n" + "-" * 78)
    if ok:
        print("PASS — construction converges and is deterministic; cross-builder divergence is")
        print("       EXACTLY the timestamp field-set delta, nothing hidden. The alignment note's")
        print("       honest status: converged on canonicalization, field set pending. The gate that")
        print("       flips it to normative = one envelope -> one id under all three locked builders.")
        return 0
    print("FAIL — a claim did not recompute as declared.")
    return 1


if __name__ == "__main__":
    sys.exit(check())
