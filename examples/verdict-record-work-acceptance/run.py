"""Runs the reference checker of draft-wright-verdict-record on each case of this example.

    git clone https://github.com/diggertydog/verdict-record-test-vectors vr
    VRCHECK=vr python3 run.py            # needs the Python package `cryptography`

It hands vrcheck.py, per case: the verdict record's exact bytes, the evidence item, the policy (policy.json), the upper
time bound in cases.json, the trust anchors {"invinoveritas-checker-keys": <the case's key document>}, and as held
inputs the reference checker's test suite plus held_invinoveritas_work_acceptance.py (the format and rule of README.md).
Nothing a case expects is given to the checker. Writes results.json.
"""
import base64
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
VR = os.environ.get("VRCHECK") or sys.exit("set VRCHECK to a checkout of diggertydog/verdict-record-test-vectors")
sys.path.insert(0, os.path.abspath(VR))
import vrcheck  # noqa: E402

EXPECT = {"p1-pass": "released"}


def main():
    cases = json.load(open(os.path.join(HERE, "cases.json")))
    policy = json.load(open(os.path.join(HERE, cases["policy"])))
    held = vrcheck.load_held([vrcheck.TEST_SUITE, os.path.join(HERE, "held_invinoveritas_work_acceptance.py")])
    out, ok = [], True
    for c in cases["cases"]:
        rb = open(os.path.join(HERE, c["verdict_record"]), "rb").read()
        ib = open(os.path.join(HERE, c["evidence_item"]), "rb").read()
        anchors = {"invinoveritas-checker-keys": json.load(open(os.path.join(HERE, c["trust_anchors"])))}
        rep = vrcheck.run(rb, policy, cases["upper_time_bound"], {vrcheck.sha256hex(ib): {"bytes": ib}}, held, anchors)
        row = {"case": c["case"], "state": rep.get("state"), "steps": rep.get("steps"), "named": rep.get("named"),
               "why": rep.get("why") or rep.get("reasons")}
        want = EXPECT.get(c["case"], "not released")
        row["as_expected"] = (row["state"] == "released") == (want == "released")
        ok &= row["as_expected"]
        out.append(row)
        print("%-18s %-10s %s %s" % (c["case"], row["state"], json.dumps(row["steps"]), row["named"]))
    json.dump(out, open(os.path.join(HERE, "results.json"), "w"), indent=1)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
