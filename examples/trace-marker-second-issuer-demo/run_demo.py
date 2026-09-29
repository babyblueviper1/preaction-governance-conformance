#!/usr/bin/env python3
"""Run the unchanged marker checkers over the demo issuer's records and assert every expected outcome. Stdlib only.
Exit 0 only if every PASS record passes, every mutant fails, and the cross-profile controls fail."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
VL = os.path.join(ROOT, "tools", "vantage_limitation_check.py")
RC = os.path.join(ROOT, "tools", "related_claims_check.py")
DEMO = os.path.join(HERE, "example-issuer.profile.json")
INV = os.path.join(ROOT, "profiles", "invinoveritas.json")
FIX = os.path.join(ROOT, "examples", "trace-v20-fixtures", "events")
R = lambda n: os.path.join(HERE, "records", n)  # noqa: E731

CASES = [  # (label, argv, expected exit)
    ("vantage: irreversible, exact note",          [VL, "--profile", DEMO, R("vl_pass_irreversible.json")], 0),
    ("vantage: reversible, no note",               [VL, "--profile", DEMO, R("vl_pass_reversible.json")], 0),
    ("vantage: note edited",                       [VL, "--profile", DEMO, R("vl_mut_edited_note.json")], 1),
    ("vantage: note on reversible type",           [VL, "--profile", DEMO, R("vl_mut_note_on_reversible.json")], 1),
    ("vantage: irreversible, note missing",        [VL, "--profile", DEMO, R("vl_mut_note_missing.json")], 1),
    ("vantage: note outside signed preimage",      [VL, "--profile", DEMO, R("vl_mut_note_outside_preimage.json")], 1),
    ("vantage: other class's note",                [VL, "--profile", DEMO, R("vl_mut_wrong_class_note.json")], 1),
    ("vantage: signed by a key not in profile",    [VL, "--profile", DEMO, R("vl_mut_other_key.json")], 1),
    ("vantage: kid claims issuer key, other signer", [VL, "--profile", DEMO, R("vl_mut_kid_claims_issuer_key.json")], 1),
    ("vantage: alg none",                          [VL, "--profile", DEMO, R("vl_mut_alg_none.json")], 1),
    ("vantage: payload swapped under signature",   [VL, "--profile", DEMO, R("vl_mut_payload_swapped.json")], 1),
    ("related: demo outer -> invinoveritas inner, matched",
     [RC, "--profile", DEMO, "--inner-profile", INV, R("rc_outer_matched.json"), os.path.join(FIX, "inner.json"), os.path.join(FIX, "claims_exact.json")], 0),
    ("related: outer records mismatched (false)",
     [RC, "--profile", DEMO, "--inner-profile", INV, R("rc_mut_outer_says_mismatched.json"), os.path.join(FIX, "inner.json"), os.path.join(FIX, "claims_exact.json")], 1),
    ("related: outer binds the wrong decision_ref",
     [RC, "--profile", DEMO, "--inner-profile", INV, R("rc_mut_outer_wrong_ref.json"), os.path.join(FIX, "inner.json"), os.path.join(FIX, "claims_exact.json")], 1),
    ("related: tampered invinoveritas inner",
     [RC, "--profile", DEMO, "--inner-profile", INV, R("rc_outer_matched.json"), os.path.join(FIX, "inner_tampered.json"), os.path.join(FIX, "claims_exact.json")], 1),
    # controls: the profile is what admits an issuer; the wrong profile rejects in both directions
    ("control: demo record under invinoveritas default", [VL, R("vl_pass_irreversible.json")], 1),
    ("control: invinoveritas record under demo profile", [VL, "--profile", DEMO, os.path.join(FIX, "v21_trade_irreversible.json")], 1),
    ("control: invinoveritas record, invinoveritas profile", [VL, "--profile", INV, os.path.join(FIX, "v21_trade_irreversible.json")], 0),
    # ACCEPTANCE.md: our own demo run reproduces but must NOT count as the independent issuer
    ("acceptance: demo run attestation is rejected (not independent)",
     [os.path.join(ROOT, "tools", "issuer_run_check.py"), os.path.join(HERE, "run_attestation.demo.json")], 1),
]


def main():
    bad = 0
    for label, argv, want in CASES:
        r = subprocess.run([sys.executable] + argv, capture_output=True, text=True)
        ok = r.returncode == want
        bad += not ok
        print(f"{'ok ' if ok else 'BAD'}  exit {r.returncode} (want {want})  {label}")
        if not ok or "-v" in sys.argv:
            print("     " + r.stdout.replace("\n", "\n     "))
    print(f"{len(CASES) - bad}/{len(CASES)} as expected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
