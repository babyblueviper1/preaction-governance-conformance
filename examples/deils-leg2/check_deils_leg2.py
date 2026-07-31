#!/usr/bin/env python3
"""Offline, zero-dep conformance checker for DEILS "leg 2" -- Merlini's held-content-
behind-commitment design (trustless-ai group, pinned 2026-07-23, Telegram msg_id 1623/1632/
2111-2112). Recomputes the reveal-check predicate from vectors.json's bytes alone:

  reveal_check(commitment_hash, revealed_content) -> {content_bound, content_commitment_mismatch,
                                                       content_withheld}

Two-layer design being conformance-checked:
  - EXISTENCE (a commitment_hash + a monotonic ledger position) is mandatory-public and
    non-suppressible by construction -- a missing entry is a visible gap.
  - CONTENT is optional-private: held back until a reveal binds it to the already-published
    commitment. A mismatch on reveal is a POSITIVE evidence state (tampering, or a bad original
    commitment), not a "couldn't check" absence, and it is TERMINAL/fail-closed -- no verdict
    recompute happens over unbound content.

Reference implementation: invinoveritas POST /prove {"disclose": false} publishes
{commitment_hash, ledger_position, status:"content_withheld"}; POST /prove/{proof_id}/reveal
binds a later-submitted content payload to that commitment (routes/execution.py:prove_reveal).
Merlini's own independent second checker (built BLIND, before these vectors existed) lives at
trustless-ai/deils/conformance/deils-reveal-v0/reveal_check.py -- run it against this same
vectors.json to diff its verdicts against this checker's, chronicle-continuity-gate style.

    python3 check_deils_leg2.py        # exit 0 iff every case matches its expected_state
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def jcs(v) -> str:
    """RFC-8785-style JCS -- pure stdlib, same minimal form as examples/profile-resolution/jcs.py
    and examples/erc-8337-attestation-refs/check_attestation_refs.py. Recurses into nested
    dicts/lists so a deep key shuffle canonicalizes identically to its original ordering."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k])
                              for k in sorted(v.keys())) + "}"
    raise TypeError(f"non-canonicalizable type: {type(v).__name__}")


def commitment_hash_of(content: dict) -> str:
    return "sha256:" + hashlib.sha256(jcs(content).encode("utf-8")).hexdigest()


def reveal_check(commitment_hash: str, revealed_content) -> tuple[str, dict]:
    """The pure predicate under test. Returns (state, evidence)."""
    if revealed_content is None:
        return "content_withheld", {}
    recomputed = commitment_hash_of(revealed_content)
    if recomputed == commitment_hash:
        return "content_bound", {"commitment_hash": commitment_hash, "recomputed_hash": recomputed}
    return "content_commitment_mismatch", {
        "committed_hash": commitment_hash,
        "revealed_content": revealed_content,
        "recomputed_hash": recomputed,
    }


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    all_ok = True
    print(f"== {vectors['schema']} ==")
    for case in vectors["cases"]:
        commitment_hash = commitment_hash_of(case["committed_content"])
        state, evidence = reveal_check(commitment_hash, case.get("revealed_content"))
        ok = state == case["expected_state"]
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {case['case_id']}: got={state} expected={case['expected_state']}")
        if not ok:
            print(f"        commitment_hash={commitment_hash} evidence={evidence}")

    # Extra sensitivity check, not just echoing vectors.json's own pre-committed answers:
    # confirm the mismatch case's evidence bundle is actually populated (not silently empty).
    mismatch_case = next(c for c in vectors["cases"] if c["expected_state"] == "content_commitment_mismatch")
    ch = commitment_hash_of(mismatch_case["committed_content"])
    _, evidence = reveal_check(ch, mismatch_case["revealed_content"])
    evidence_populated = all(k in evidence for k in ("committed_hash", "revealed_content", "recomputed_hash"))
    evidence_disagrees = evidence.get("committed_hash") != evidence.get("recomputed_hash")
    sensitivity_ok = evidence_populated and evidence_disagrees
    all_ok = all_ok and sensitivity_ok
    print(f"[{'PASS' if sensitivity_ok else 'FAIL'}] mismatch evidence bundle is populated and disagrees "
          f"(not a silent/empty rejection): {sensitivity_ok}")

    # Escaped-wire-bytes trap (Pavlo, 2026-07-31): pins BOTH halves of the byte-domain ambiguity --
    # (a) hashing the served \uXXXX-escaped wire string directly (no re-parse) MUST NOT match the
    # commitment (proves the trap is real, not just a documentation footnote), and (b) parsing that
    # same wire string then re-canonicalizing via the shared jcs() MUST still bind (proves the
    # correct path handles it fine -- canonicalize, don't hash the served bytes).
    wire_case = next((c for c in vectors["cases"] if c.get("wire_byte_hash_must_not_match_commitment")), None)
    if wire_case is not None:
        wire_ch = commitment_hash_of(wire_case["committed_content"])
        wire_bytes = wire_case["wire_representation_ascii_escaped"]
        naive_byte_hash = "sha256:" + hashlib.sha256(wire_bytes.encode("utf-8")).hexdigest()
        naive_diverges = naive_byte_hash != wire_ch
        reparsed = json.loads(wire_bytes)
        reparsed_state, _ = reveal_check(wire_ch, reparsed)
        reparsed_binds = reparsed_state == "content_bound"
        wire_trap_ok = naive_diverges and reparsed_binds
        all_ok = all_ok and wire_trap_ok
        print(f"[{'PASS' if wire_trap_ok else 'FAIL'}] escaped-wire-bytes trap: naive byte-hash of "
              f"served \\uXXXX string diverges ({naive_diverges}) AND parse-then-recanonicalize still "
              f"binds ({reparsed_binds}): {wire_trap_ok}")

    print("\nall cases hold ✓" if all_ok else "\nCONFORMANCE CHECK FAILED ✗")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
