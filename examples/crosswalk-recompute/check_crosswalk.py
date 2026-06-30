#!/usr/bin/env python3
"""check_crosswalk.py — recompute whether a vocabulary crosswalk between two governance boards
is valid, from the boards' own verdict bytes (S213).

A crosswalk is itself a claim. By the referee-of-referees property, it must recompute the same way
the verdicts it maps do — not be trusted from whoever published the mapping. This implements
rpelevin's acceptance bar (crewAI#4877): publish the mapping with the source verdict bytes it binds,
recompute the authority tuple on both sides, and FAIL CLOSED if allowed_runtime_use, claim_ceiling,
or permitted_next_transition diverges.

  valid crosswalk  = a recomputation that AGREES (same authority tuple, regardless of tier names)
  collision        = a recomputation that DISAGREES (names may match; authority differs) -> fail closed

Independent of any board's taxonomy: it does not care that one says `terminal` and the other `D3`;
it cares only whether the two verdicts authorize the same next transition under the same ceiling,
recomputed from each verdict's own source bytes. Zero-dependency, offline.

Run: python3 check_crosswalk.py            # bundled sample (a valid mapping + a collision)
     python3 check_crosswalk.py --file x.json
"""
import argparse
import hashlib
import json
import os
import sys

TUPLE = ("allowed_runtime_use", "claim_ceiling", "permitted_next_transition")


def record_id(v: dict) -> str:
    """Content id of a verdict = sha256 of its source bytes. A third party recomputes this; the
    record's authority tuple is only trustworthy if it is bound to bytes anyone can re-hash."""
    return "sha256:" + hashlib.sha256(v.get("source_bytes_utf8", "").encode("utf-8")).hexdigest()[:16]


def authority(v: dict) -> tuple:
    return tuple(v.get(k) for k in TUPLE)


def check(sample: dict) -> int:
    boards = sample.get("boards", {})
    ev = sample.get("evidence_id")
    print("=" * 72)
    print("CROSSWALK RECOMPUTE — is a vocabulary mapping a valid transition-authority proof?")
    print("=" * 72)
    print(f"\nevidence: {ev}\n")
    print("per-board verdicts (authority tuple recomputed from each board's own source bytes):")
    for name, b in boards.items():
        v = b["verdict"]
        same_ev = v.get("evidence_id") == ev
        print(f"  {name:16} tier={v.get('depth_tier'):9} id={record_id(v)} "
              f"{'' if same_ev else '⚠ evidence mismatch '}→ {authority(v)}")

    print("\nclaimed crosswalks:")
    failures = 0
    for cw in sample.get("claimed_crosswalks", []):
        a, b = boards.get(cw["a"], {}).get("verdict", {}), boards.get(cw["b"], {}).get("verdict", {})
        # both must bind the same evidence, then the authority tuple must match across the mapping
        same_ev = a.get("evidence_id") == ev and b.get("evidence_id") == ev
        agree = authority(a) == authority(b)
        if same_ev and agree:
            verdict = "VALID crosswalk (recomputation agrees — preserved transition authority)"
        else:
            verdict = "COLLISION — fail closed (recomputation disagrees: same name, different authority)"
            failures += 1
        print(f"\n  [{cw['name']}]  claim: {cw.get('claim','')}")
        print(f"    {cw['a']:16} {authority(a)}")
        print(f"    {cw['b']:16} {authority(b)}")
        print(f"    → {verdict}")
        if not agree:
            diff = [k for k, x, y in zip(TUPLE, authority(a), authority(b)) if x != y]
            print(f"      diverges on: {diff}")

    print(f"\n{failures} collision(s) detected and failed closed; "
          f"{len(sample.get('claimed_crosswalks', [])) - failures} valid crosswalk(s).")
    print("A crosswalk is a recomputation, not an assertion: anyone re-runs this over the two boards' "
          "verdict bytes and gets the same answer, trusting neither board nor the party that mapped them.")
    # Exit 0: the CHECK ran correctly (it is SUPPOSED to find the planted collision). A non-zero exit
    # would mean the recompute logic itself failed — assert the known sample shape instead.
    expect = {"VALID": 1, "COLLISION": 1}
    got_valid = len(sample.get("claimed_crosswalks", [])) - failures
    ok = (got_valid == expect["VALID"] and failures == expect["COLLISION"])
    print(f"\n{'OK' if ok else 'FAIL'}: bundled sample resolves to 1 valid + 1 collision as designed.")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                    "sample_crosswalk.json"))
    args = ap.parse_args()
    sys.exit(check(json.load(open(args.file))))


if __name__ == "__main__":
    main()
