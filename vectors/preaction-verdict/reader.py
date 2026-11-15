#!/usr/bin/env python3
"""Reference reader for the pre-action verdict vectors (READER-CONTRACT.md). Stdlib only.
usage: python3 reader.py [cases.json]      exit 0 = every case reaches its expected result"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340  # noqa: E402

SCHEMA = "invinoveritas.verdict_proof.v1"


def jcs(v):
    """RFC 8785 for the value types these records carry (objects, arrays, strings, integers, decimal fractions, true/false/null).
    Keys sort by UTF-16 code units; numbers use the shortest round-trip form, which Python's repr gives for these values."""
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k])
                              for k in sorted(v, key=lambda s: s.encode("utf-16-be"))) + "}"
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, bool) or v is None:
        return json.dumps(v)
    if isinstance(v, float):
        return repr(v) if v != int(v) else str(int(v))
    return json.dumps(v, ensure_ascii=False)


def event_id(ev):
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()


def read(ev, key_set, relying_party):
    """Returns ESTABLISHED or REFUSED:<step>. The first failing step decides."""
    if event_id(ev) != ev.get("id"):
        return "REFUSED:EVENT_ID"                                                    # step 1
    if not bip340.verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])):
        return "REFUSED:SIGNATURE"                                                   # step 2
    if ev["pubkey"] not in {k["pubkey"] for k in key_set["keys"]}:
        return "REFUSED:KEY_NOT_IN_SET"                                              # step 3
    if ["schema", SCHEMA] not in ev["tags"]:
        return "REFUSED:SCHEMA"                                                      # step 4
    c = json.loads(ev["content"])
    if c.get("verifier_pubkey") != ev["pubkey"]:
        return "REFUSED:KEY_BINDING"                                                 # step 5
    pre = {k: c.get(k) for k in c["decision_ref_preimage_fields"]}                   # absent -> null, never omitted
    if "sha256:" + hashlib.sha256(jcs(pre).encode()).hexdigest() != c.get("decision_ref"):
        return "REFUSED:DECISION_REF"                                                # step 6
    if relying_party["action_hash"] != c.get("artifact_hash"):
        return "REFUSED:ACTION_UNBOUND"                                              # step 7
    if not (c["freshness_beacon"]["block_time"] <= ev["created_at"] < relying_party["executed_at"]):
        return "REFUSED:NOT_PRE_ACTION"                                              # step 8
    return "ESTABLISHED"


def main(argv):
    path = argv[1] if len(argv) > 1 else os.path.join(HERE, "cases.json")
    cases = json.load(open(path))
    keys = {k: json.load(open(os.path.join(HERE, v))) for k, v in cases["key_sets"].items()}
    bad = 0
    for c in cases["cases"]:
        ev = json.load(open(os.path.join(HERE, c["record"])))
        got = read(ev, keys[c["key_set"]], c["relying_party"])
        ok = got == c["expect"]
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {c['id']:28} {got:26} expect {c['expect']}")
    print(f"{len(cases['cases']) - bad}/{len(cases['cases'])} cases match")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
