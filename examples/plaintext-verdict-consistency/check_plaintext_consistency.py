#!/usr/bin/env python3
"""check_plaintext_consistency.py — does "valid: True" actually mean the plaintext claim is true?

Found live (2026-07-01) in Correctover/correctover-crewai (commit 88bc71c6, `pip install
correctover-crewai==0.1.0`, verified against the real published package — not a hypothetical).
STANDARDS.md documents a portable proof package with two representations of the same claim sitting
side by side:

  {
    "expected_verdict": "partial",       <- plaintext, human-readable
    "expected_proof_hash": "650f22cb...", <- SHA-256 over (input + rules + per-dim results + verdict)
    ...
  }

`RecomputeEngine().verify_proof_package(pkg)` recomputes the verdict from the package's raw bytes and
returns `valid = (recomputed_hash == expected_proof_hash)` — a HASH-ONLY check
(recompute.py lines 155-174). It never compares `expected_verdict` (the plaintext field) against the
freshly recomputed verdict.

Consequence, reproduced here in miniature: tampering the CONTENT that determines the verdict changes
the hash and is caught (`valid: False`) — content tampering works as advertised. But tampering ONLY the
plaintext `expected_verdict` field, leaving `expected_proof_hash` untouched, produces `valid: True`,
because nothing ties the two representations together. A caller reading `valid: True` next to
`expected_verdict: "pass"` — the natural way to consume this package — can be shown a better verdict
than what the artifact actually recomputes to. Same failure class as `verdict != f(controls)` in the
presidio x402 fixture: a claim that hashes fine but doesn't recompute to what it says it does, one
layer sneakier here because the plaintext field *looks like* the ground truth next to a passing check.

This check is a minimal, faithful, zero-dependency reproduction of the pattern — not a live call to
their package (CI here stays offline; the finding was verified live separately, see README) — so it
stays reproducible even if the upstream package changes. It demonstrates: (1) the vulnerable
(hash-only) check passes when it shouldn't, (2) a corrected check that also asserts
`expected_verdict == recomputed_verdict` closes it.

Zero-dependency, offline. Run: python3 check_plaintext_consistency.py
"""
from __future__ import annotations

import hashlib
import json
import sys


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def recompute_verdict(content: dict) -> str:
    """Stand-in for the six-dimension verifier: deterministic function of content only."""
    return "partial" if content.get("flag_count", 0) > 0 else "pass"


def build_package(content: dict) -> dict:
    verdict = recompute_verdict(content)
    proof_hash = hashlib.sha256(canonical({"content": content, "verdict": verdict})).hexdigest()
    return {
        "content": content,
        "expected_verdict": verdict,          # plaintext claim
        "expected_proof_hash": proof_hash,     # hash claim
    }


def vulnerable_valid(pkg: dict) -> dict:
    """Faithful miniature of correctover-crewai's verify_proof_package: hash-only."""
    recomputed_verdict = recompute_verdict(pkg["content"])
    recomputed_hash = hashlib.sha256(
        canonical({"content": pkg["content"], "verdict": recomputed_verdict})
    ).hexdigest()
    return {
        "valid": recomputed_hash == pkg["expected_proof_hash"],
        "recomputed_verdict": recomputed_verdict,
        "expected_verdict": pkg["expected_verdict"],
    }


def fixed_valid(pkg: dict) -> dict:
    """The one-line fix: also assert the plaintext claim agrees with the recomputation."""
    r = vulnerable_valid(pkg)
    r["valid"] = r["valid"] and (r["recomputed_verdict"] == r["expected_verdict"])
    return r


def main() -> int:
    ok = True

    # 1. untampered — both checks should agree it's valid
    content = {"flag_count": 1, "note": "one flagged field"}
    pkg = build_package(content)
    v_result, f_result = vulnerable_valid(pkg), fixed_valid(pkg)
    print(f"[1] untampered:            vulnerable.valid={v_result['valid']}  fixed.valid={f_result['valid']}")
    ok = ok and v_result["valid"] is True and f_result["valid"] is True

    # 2. tamper the content — the hash changes, both checks should catch it
    tampered_content_pkg = dict(pkg, content={"flag_count": 0, "note": "one flagged field"})
    v2, f2 = vulnerable_valid(tampered_content_pkg), fixed_valid(tampered_content_pkg)
    print(f"[2] content tampered:      vulnerable.valid={v2['valid']}  fixed.valid={f2['valid']}  "
          f"(both should be False)")
    ok = ok and v2["valid"] is False and f2["valid"] is False

    # 3. tamper ONLY the plaintext expected_verdict — the hash is untouched
    tampered_plaintext_pkg = dict(pkg, expected_verdict="pass")  # claims better than it recomputes
    v3, f3 = vulnerable_valid(tampered_plaintext_pkg), fixed_valid(tampered_plaintext_pkg)
    print(f"[3] plaintext-only tamper: vulnerable.valid={v3['valid']}  fixed.valid={f3['valid']}  "
          f"(reproduces the finding: vulnerable=True is the bug, fixed=False is the fix)")
    ok = ok and v3["valid"] is True and f3["valid"] is False

    print()
    if ok:
        print("PASS — the pattern reproduces exactly as found live: a hash-only check reports valid=True")
        print("       for a package whose plaintext expected_verdict has been tampered independently of")
        print("       the hash. Asserting expected_verdict == recomputed_verdict closes it.")
    else:
        print("FAIL — reproduction did not match the expected shape; re-verify against the live package "
              "before trusting this row.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
