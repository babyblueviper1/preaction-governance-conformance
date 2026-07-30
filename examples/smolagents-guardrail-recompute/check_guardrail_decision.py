#!/usr/bin/env python3
"""Offline, zero-dep conformance checker for smolagents' GuardrailProvider protocol
(huggingface/smolagents#2117 / PR #2126, open as of 2026-07-30).

Promised as a follow-up on #2117 (2026-07-06): "a small, language-agnostic JSON vector set
(tool_name, normalized args ... -> expected verdict/reasons) plus a zero-dependency checker
script, independent of #2126 landing or which GuardrailProvider implementation exists." This
is that fixture -- independently reimplemented from PR #2126's own documented behavior, never
importing smolagents itself, so a provider (theirs, ours, or a future one) has something concrete
to recompute against rather than the interface staying descriptive-only.

Recomputes AllowlistGuardrail / BlocklistGuardrail / CompositeGuardrail's before_tool_call
decisions against 10 pinned cases, including an adversarial substring-matching case that a naive
(non-exact-membership) reimplementation would get wrong.

    python3 check_guardrail_decision.py        # exit 0 iff every case matches its expected decision
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def guardrail_decision(guardrail: dict, tool_name: str) -> dict:
    """Independent reimplementation of PR #2126's AllowlistGuardrail / BlocklistGuardrail /
    CompositeGuardrail.before_tool_call, from the PR's own documented semantics:
      - AllowlistGuardrail: exact-name membership; 'final_answer' always permitted regardless.
      - BlocklistGuardrail: exact-name membership; denies listed, permits everything else.
      - CompositeGuardrail: evaluates providers IN ORDER; the first denial wins; if every
        provider allows (including an empty provider list), the composite allows.
    """
    kind = guardrail["kind"]
    if kind == "allowlist":
        allowed = set(guardrail["allowed_tools"]) | {"final_answer"}
        if tool_name in allowed:
            return {"allowed": True, "reason": ""}
        return {"allowed": False,
                "reason": f"Tool '{tool_name}' is not in the allowed tools list: {sorted(allowed)}"}
    if kind == "blocklist":
        blocked = set(guardrail["blocked_tools"])
        if tool_name in blocked:
            return {"allowed": False, "reason": f"Tool '{tool_name}' is blocked."}
        return {"allowed": True, "reason": ""}
    if kind == "composite":
        for provider in guardrail["providers"]:
            decision = guardrail_decision(provider, tool_name)
            if not decision["allowed"]:
                return decision
        return {"allowed": True, "reason": ""}
    raise ValueError(f"unknown guardrail kind: {kind!r}")


def main() -> int:
    vectors = json.loads((HERE / "vectors.json").read_text())
    all_ok = True
    print(f"== {vectors['schema']} ==")
    for case in vectors["cases"]:
        decision = guardrail_decision(case["guardrail"], case["tool_name"])
        expected = case["expected"]
        ok = decision["allowed"] == expected["allowed"]
        if ok and "reason_contains" in expected:
            ok = expected["reason_contains"] in decision["reason"]
        all_ok = all_ok and ok
        print(f"[{'PASS' if ok else 'FAIL'}] {case['case_id']}: "
              f"allowed={decision['allowed']} reason={decision['reason']!r}")
        if not ok:
            print(f"        expected={expected}")

    print("\nall cases hold ✓" if all_ok else "\nCONFORMANCE CHECK FAILED ✗")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
