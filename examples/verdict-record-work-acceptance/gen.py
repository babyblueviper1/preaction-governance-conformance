"""Writes the verdict records, the tampered item and the case table of this example (stdlib only).

    python3 gen.py

Inputs (committed): record.json -- the evidence item, the JCS bytes of {"receipt", "signature"} of the work-acceptance
record e62b9963... as https://api.babyblueviper.com/work-acceptance/record/<receipt_sha256> publishes it (member
"record", without its "timestamp" annotation); checker-keys.json -- the key document published at
https://api.babyblueviper.com/.well-known/invinoveritas-checker-keys.json.
"""
import base64
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = ("https://github.com/babyblueviper1/preaction-governance-conformance/blob/main/"
        "examples/verdict-record-work-acceptance/README.md")
FORMAT, RULE = BASE + "#format", BASE + "#rule"


def canonical(o):
    """draft-wright-verdict-record Section 2.1: members sorted, no whitespace, UTF-8."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def write(name, b):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(b)


def verdict_record(key, item_sha, result, claim):
    return canonical({
        "act_time": "2026-11-17T22:00:00.000000Z",
        "actor": {"id": "acceptance-rerun", "model": "none", "model_version": "0", "type": "system"},
        "body": {"claim": {"text": claim}},
        "check": {"inputs": {"results": {"evidence": 0, "pointer": "/receipt/results"}}, "result": result, "rule": RULE},
        "evidence": [{"format": FORMAT, "sha256": item_sha}],
        "key": key, "kind": "check-run", "supersedes": None, "v": "verdict-record/1", "version": 1,
        "writer": "relying-party.example"})


def main():
    item = open(os.path.join(HERE, "record.json"), "rb").read()
    rec = json.loads(item)
    rid = sha(canonical(rec["receipt"]))   # ASCII keys: Section 2.1 order equals JCS order
    claim = ("The delivery judged in work-acceptance receipt %s meets the acceptance criteria it committed (%s)."
             % (rid, rec["receipt"]["criteria"]["sha256"]))

    # Tampered item: one required criterion flipped to fail and the verdict made consistent with it, signature kept.
    bad = json.loads(item)
    bad["receipt"]["results"][0]["result"] = "fail"
    bad["receipt"]["verdict"] = "fail"
    bad_b = canonical(bad)
    write("record-tampered.json", bad_b)

    keys = json.load(open(os.path.join(HERE, "checker-keys.json")))
    nokey = dict(keys, keys=[])
    write("checker-keys-empty.json", canonical(nokey))

    policy = {"judgement_kinds": [], "formats": [FORMAT], "citation_depth": 1}
    write("policy.json", canonical(policy))

    cases = [
        ("p1-pass", sha(item), "pass", "record.json", "checker-keys.json",
         "the record verifies under the held key and its results give pass, as stated"),
        ("n1-stated-fail", sha(item), "fail", "record.json", "checker-keys.json",
         "the verdict record states fail; re-running the rule on the cited results gives pass"),
        ("n2-tampered-item", sha(bad_b), "fail", "record-tampered.json", "checker-keys.json",
         "a result was changed after signing: the item no longer meets the format's rules"),
        ("n3-key-not-held", sha(item), "pass", "record.json", "checker-keys-empty.json",
         "the checker holds no key for the record's key_id"),
    ]
    table = []
    for name, isha, result, item_file, keys_file, why in cases:
        b = verdict_record("wa-" + rid[:16] + "-" + name, isha, result, claim)
        write(name + ".verdict-record.json", b)
        table.append({"case": name, "verdict_record": name + ".verdict-record.json", "record_sha256": sha(b),
                      "evidence_item": item_file, "trust_anchors": keys_file, "what": why})
    write("cases.json", (json.dumps({"upper_time_bound": "2026-11-17T23:00:00.000000Z", "policy": "policy.json",
                                     "cases": table}, indent=1) + "\n").encode())
    print("receipt_sha256", rid, "| item", sha(item), "| tampered", sha(bad_b))


if __name__ == "__main__":
    main()
