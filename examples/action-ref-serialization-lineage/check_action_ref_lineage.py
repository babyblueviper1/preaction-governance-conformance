#!/usr/bin/env python3
"""check_action_ref_lineage.py — does the field set converging settle the id, or does serialization
still diverge underneath it?

crewAI#4877 (haroldmalikfrimpong-ops / AgentID, 2026-06-30) found that giskard09/argentum-core has
TWO documents both claiming to define `action_ref` for the same four-field action shape
(agent_id, action_type, scope, timestamp), and they commit different bytes:

  (A) docs/spec/guarantee-model.md — a narrower joint spec for a specific three-system stack
      (Mycelium x SafeAgent x DashClaw). Raw concatenation, `timestamp_ms` as an int64 big-endian:
        action_ref = SHA-256(agent_id || action_type || scope || int64_be(timestamp_ms))

  (B) the field-set haroldmalikfrimpong-ops cited as "the JCS lineage" — JCS over the same fields,
      but with `timestamp_ms` left as a JSON integer:
        action_ref = SHA-256(JCS({agent_id, action_type, scope, timestamp_ms:int}))

  (C) docs/spec/action-ref.md v1.1 — the versioned, actively-referenced spec the wider cross-builder
      thread (A2A#1734, ibex) is converging toward, with a linked reference implementation
      (plugins/agt_evidence_anchor/action_ref.py). JCS over `timestamp` as an RFC 3339 UTC string
      with 3-digit ms precision — and its own text explicitly disqualifies (B):
        "Implementations that hash the epoch-ms integer directly (without conversion) will produce
         a different digest and are not conformant with this spec."
        action_ref = SHA-256(JCS({agent_id, action_type, scope, timestamp:"...Z"}))

So "the field set converged" (A2A#1734 / ibex / crewAI all commit the same four logical fields) does
NOT mean the id converged — there are three different bytes for the same logical action, and (A) is
not even competing for the same spec slot as (B)/(C) (different normative document entirely).

This check recomputes all three independently, asserts they are pairwise distinct (the divergence is
real, not a typo), and asserts (C) is the one that matches the cited reference implementation's stated
output — so a future "argentum-core action_ref" claim can be graded against a name, not a vibe:
  - matches (A) -> wrong document (Mycelium/SafeAgent/DashClaw joint spec, not action-ref.md)
  - matches (B) -> wrong field type (epoch-ms int; non-conformant per the spec's own text)
  - matches (C) -> conformant to action-ref.md v1.1

Zero-dependency, offline. Run: python3 check_action_ref_lineage.py
"""
from __future__ import annotations

import datetime
import hashlib
import json
import sys

ENVELOPE = {
    "agent_id": "agent_demo_001",
    "action_type": "tool:transfer",
    "scope": "payments:send",
    "timestamp_ms": 1750000000000,
}


def construction_a_raw_concat(env: dict) -> str:
    """guarantee-model.md — Mycelium x SafeAgent x DashClaw joint spec. Raw bytes, no JSON at all."""
    raw = (
        env["agent_id"].encode("utf-8")
        + env["action_type"].encode("utf-8")
        + env["scope"].encode("utf-8")
        + env["timestamp_ms"].to_bytes(8, "big")
    )
    return hashlib.sha256(raw).hexdigest()


def _jcs(payload: dict) -> bytes:
    return json.dumps(
        dict(sorted(payload.items())), separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def construction_b_jcs_epoch_ms(env: dict) -> str:
    """The lineage haroldmalikfrimpong-ops cited as "JCS" — but leaves timestamp_ms as a raw int.
    action-ref.md v1.1 explicitly disqualifies this: not conformant."""
    payload = {
        "agent_id": env["agent_id"],
        "action_type": env["action_type"],
        "scope": env["scope"],
        "timestamp_ms": env["timestamp_ms"],
    }
    return hashlib.sha256(_jcs(payload)).hexdigest()


def construction_c_jcs_rfc3339(env: dict) -> str:
    """action-ref.md v1.1 — JCS over an RFC 3339 UTC string, 3-digit ms, mandatory Z. The normative
    form: the spec's own reference implementation (plugins/agt_evidence_anchor/action_ref.py) does
    exactly this conversion before hashing."""
    dt = datetime.datetime.fromtimestamp(env["timestamp_ms"] / 1000.0, tz=datetime.timezone.utc)
    ms = dt.microsecond // 1000
    ts = dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")
    payload = {
        "agent_id": env["agent_id"],
        "action_type": env["action_type"],
        "scope": env["scope"],
        "timestamp": ts,
    }
    return hashlib.sha256(_jcs(payload)).hexdigest()


# Independently re-derived 2026-06-30 against the live repo at giskard09/argentum-core; see README
# for the exact mainnet/recompute provenance. Locks this check to the historical claim under review.
EXPECTED = {
    "A": "b2d772c32e6bd3afa540a32f9a1530f1025ae7524b3c20d0ead06f029c3bce13",
    "B": "c469dafb88f2da717059751674924d15b0d227d95a26aad2d441f0ab08fd37b7",
    "C": "28f23902af6cf38da12987f3f90078945606e89fd9e6599c96421a4bab21e478",
}


def main() -> int:
    a = construction_a_raw_concat(ENVELOPE)
    b = construction_b_jcs_epoch_ms(ENVELOPE)
    c = construction_c_jcs_rfc3339(ENVELOPE)

    ok = True
    for label, got, want in (("A (raw-concat)", a, EXPECTED["A"]),
                              ("B (JCS+epoch-ms, non-conformant)", b, EXPECTED["B"]),
                              ("C (JCS+RFC3339, action-ref.md v1.1)", c, EXPECTED["C"])):
        match = got == want
        ok = ok and match
        print(f"  {label}: {got}  {'OK' if match else 'MISMATCH vs ' + want}")

    distinct = len({a, b, c}) == 3
    print(f"  pairwise distinct: {distinct}")
    ok = ok and distinct

    print()
    if ok:
        print("PASS — three named constructions, three different bytes, confirmed distinct.")
        print("       A claim that matches A or B is a named divergence (wrong doc / wrong field type),")
        print("       not a flat 'doesn't match'. A claim that matches C is conformant to action-ref.md v1.1.")
    else:
        print("FAIL — recompute drifted from the locked historical values. Re-derive before trusting this row.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
