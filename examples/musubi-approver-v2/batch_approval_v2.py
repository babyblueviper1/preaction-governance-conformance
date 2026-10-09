#!/usr/bin/env python3
"""Batch entrypoint for the a2a-approval-v2 checker, in the TSUNAGI batch-contract shape (horizon-shield tools/tsunagi):

    python3 batch_approval_v2.py IN OUT

    IN   a JSON array    [{"name": "<case>", "contract": {...}, "approval": {...} | null}, ...]
    OUT  a JSON object   {"<case>": {"result": "<result>", "reason": "<reason>" | null}, ...}
                         or {"<case>": {"error": "..."}} for a case that could not be evaluated

One answer per fixture, nothing else written. No expected value is read: the referee holds those and compares. approval null
means "no approval presented" and is answered with the contract's policy reading ("pinned" | "approval_self_asserted"), the same
rule verify_approval_v2.py applies. The logic is verify_approval_v2.py imported as is; this file only does I/O. Exit 0.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_approval_v2 import verify_approval_v2, policy_reading  # noqa: E402


def answer(case):
    c = case.get("contract")
    if not isinstance(c, dict):
        return {"error": "contract missing or not an object"}
    a = case.get("approval")
    result, reason = verify_approval_v2(c, a) if a is not None else (policy_reading(c), None)
    return {"result": result, "reason": reason}


def main(src, dst):
    cases = json.load(open(src, encoding="utf-8"))
    out = {}
    for case in cases:
        name = case.get("name") if isinstance(case, dict) else None
        if not isinstance(name, str):
            continue
        try:
            out[name] = answer(case)
        except Exception as e:  # one bad fixture does not end the batch
            out[name] = {"error": f"{type(e).__name__}: {e}"}
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, sort_keys=True, indent=1)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
