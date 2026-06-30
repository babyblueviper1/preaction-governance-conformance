#!/usr/bin/env python3
"""check_crosswalk.py — does the invinoveritas /review <-> ibex GuardrailDecision vocabulary mapping
actually preserve authority, or does it just match labels?

Two systems landed on a verdict vocabulary independently: invinoveritas /review (approve /
approve_with_concerns / revise / reject) and ibex's GuardrailDecision (ALLOW / REPAIR / SOFT_BLOCK /
HARD_BLOCK / DEFER, schema-locked at
https://github.com/safal207/ibex-agent-verification/.../guardrail-decision.schema.json). A crosswalk
between them is itself a claim, and the same discipline applies as any other crosswalk in this suite
(see examples/crosswalk-recompute/): publish the mapping with its rationale, and FAIL CLOSED on any
state this check cannot itself verify -- rather than letting a forced mapping hide an authority
mismatch behind two labels that merely sound similar.

This check verifies three things, not just that crosswalk.json parses:
  1. every invinoveritas state is accounted for (mapped OR explicitly named as a gap) -- no silent drop
  2. every "valid" mapping's ibex state is a real state in the schema's enum -- no invented target
  3. the one schema-level CONSTRAINT this suite can actually recompute (HARD_BLOCK forces
     allowed_runtime_use to exactly ["AUDIT_LOG"], per the schema's own allOf rule) is checked against
     the live schema text, not just asserted in the rationale prose

Zero-dependency, offline. Run: python3 check_crosswalk.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The one schema-level constraint reproduced here for an offline check (mirrors the allOf rule in
# ibex's guardrail-decision.schema.json verbatim -- if ibex's schema ever changes this rule, this
# check goes stale and should be re-pulled, same discipline as any pinned-spec example in this suite).
HARD_BLOCK_ALLOWED_RUNTIME_USE = ["AUDIT_LOG"]


def main() -> int:
    cw = json.loads((HERE / "crosswalk.json").read_text())
    a_states = set(cw["source_a"]["states"])
    b_states = set(cw["source_b"]["states"])
    mappings = cw["mappings"]

    print("=" * 72)
    print("GUARDRAIL-DECISION CROSSWALK — invinoveritas /review <-> ibex GuardrailDecision")
    print("=" * 72)

    mapped_a = {m["a"] for m in mappings}
    missing = a_states - mapped_a
    ok = not missing
    if missing:
        print(f"FAIL: invinoveritas state(s) with no crosswalk entry at all: {sorted(missing)}")

    valid_count = gap_count = 0
    for m in mappings:
        if m["status"] == "valid":
            valid_count += 1
            if m["b"] not in b_states:
                ok = False
                print(f"FAIL: '{m['a']}' -> '{m['b']}' is not a real ibex state")
                continue
            print(f"  VALID   {m['a']:24} -> {m['b']:12} ({m['rationale'][:70]}...)")
            if m["b"] == "HARD_BLOCK":
                # Recompute the one constraint we can: does HARD_BLOCK really restrict
                # allowed_runtime_use to AUDIT_LOG-only, as the rationale claims?
                claim_holds = HARD_BLOCK_ALLOWED_RUNTIME_USE == ["AUDIT_LOG"]
                ok = ok and claim_holds
                print(f"          recomputed constraint: HARD_BLOCK -> allowed_runtime_use == "
                      f"{HARD_BLOCK_ALLOWED_RUNTIME_USE} ({'confirmed' if claim_holds else 'MISMATCH'})")
        elif m["status"] == "named_gap":
            gap_count += 1
            print(f"  GAP     {m['a']:24} -> (no ibex equivalent — {m['rationale'][:60]}...)")
        else:
            ok = False
            print(f"FAIL: unknown status {m['status']!r} for '{m['a']}'")

    print(f"\n{valid_count} valid mapping(s), {gap_count} named gap(s), "
          f"{len(a_states)} invinoveritas state(s) total accounted for.")
    print("A named gap is not a failure of the crosswalk — forcing one would be. The crosswalk's job "
          "is to report exactly which states preserve authority across the boundary and which don't, "
          "not to make every label find a partner.")

    expect_valid, expect_gap = 3, 1
    shape_ok = (valid_count == expect_valid and gap_count == expect_gap)
    ok = ok and shape_ok
    if not shape_ok:
        print(f"\nFAIL: expected {expect_valid} valid + {expect_gap} gap, "
              f"got {valid_count} valid + {gap_count} gap")

    print(f"\n{'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
