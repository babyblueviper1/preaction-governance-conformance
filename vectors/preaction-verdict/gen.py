#!/usr/bin/env python3
"""Build the negative records, cases.json and MANIFEST.json from the five real ledger verdicts in records/. Deterministic: run it twice
and the bytes are the same. The TEST-ONLY key is SHA-256("preaction-governance-conformance/test-only/" + label); it signs nothing real.
usage: python3 gen.py"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340  # noqa: E402
from reader import event_id  # noqa: E402

REC = os.path.join(HERE, "records")
TEST_SK = hashlib.sha256(b"preaction-governance-conformance/test-only/wrong-key").digest()
TEST_PK = bip340.pubkey(TEST_SK).hex()
POS = sorted(f for f in os.listdir(REC) if f.startswith("v0"))


def write(name, obj):
    with open(os.path.join(HERE, name), "w") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
        f.write("\n")


def resign(ev, content_obj=None):
    ev = copy.deepcopy(ev)
    if content_obj is not None:
        ev["content"] = json.dumps(content_obj, separators=(",", ":"), ensure_ascii=False)
    ev["pubkey"] = TEST_PK
    ev["id"] = event_id(ev)
    ev["sig"] = bip340.sign(bytes.fromhex(ev["id"]), TEST_SK).hex()
    return ev


def main():
    base = json.load(open(os.path.join(REC, POS[0])))
    c0 = json.loads(base["content"])
    # n01: one hex digit of the signature changed
    n01 = copy.deepcopy(base); n01["sig"] = n01["sig"][:-1] + ("0" if n01["sig"][-1] != "0" else "1")
    # n02: re-signed by a key outside the issuer key set (content still names the issuer's key)
    n02 = resign(base)
    # n03: content edited after signing (confidence), id and signature kept
    n03 = copy.deepcopy(base); n03["content"] = n03["content"].replace('"confidence":0.86', '"confidence":0.99', 1)
    assert n03["content"] != base["content"], "n03 edit did not apply"
    # n06: validly signed by a key the relying party also trusts, but the content claims the ISSUER's key
    n06 = resign(base)
    # n07: signed by the test key, content binds that key, decision_ref no longer matches its preimage
    c7 = dict(c0, verifier_pubkey=TEST_PK, decision_ref="sha256:" + "00" * 32)
    n07 = resign(base, c7)
    # n08: signed by the test key, content binds that key, but the schema tag is missing (a reader must not guess the record type)
    n08 = copy.deepcopy(base); n08["tags"] = [tg for tg in n08["tags"] if tg[:1] != ["schema"]]
    n08 = resign(n08, dict(c0, verifier_pubkey=TEST_PK))
    for name, ev in (("n08-schema-tag-missing", n08), ("n01-forged-signature", n01), ("n02-wrong-key", n02), ("n03-content-tampered", n03),
                     ("n06-key-binding", n06), ("n07-decision-ref-mismatch", n07)):
        write(f"records/{name}.json", ev)
    write("keys/test-only-key-set.json", {"keys": [{"pubkey": TEST_PK, "issuer": "TEST ONLY -- never trust in production",
                                                     "recipe": "seckey = SHA-256('preaction-governance-conformance/test-only/wrong-key')"}]})
    write("keys/issuer-plus-test-key-set.json", {"keys": json.load(open(os.path.join(HERE, "keys/issuer-key-set.json")))["keys"]
                                                 + json.load(open(os.path.join(HERE, "keys/test-only-key-set.json")))["keys"]})
    cases = []
    for f in POS:                                   # the five real verdicts, relying party consistent with them
        ev = json.load(open(os.path.join(REC, f))); c = json.loads(ev["content"])
        cases.append(dict(id=f[:-5], record=f"records/{f}", key_set="issuer",
                          relying_party=dict(action_hash=c["artifact_hash"], executed_at=ev["created_at"] + 3600), expect="ESTABLISHED"))
    rp = dict(action_hash=c0["artifact_hash"], executed_at=base["created_at"] + 3600)
    cases += [
        dict(id="n01-forged-signature", record="records/n01-forged-signature.json", key_set="issuer", relying_party=rp, expect="REFUSED:SIGNATURE"),
        dict(id="n02-wrong-key", record="records/n02-wrong-key.json", key_set="issuer", relying_party=rp, expect="REFUSED:KEY_NOT_IN_SET"),
        dict(id="n03-content-tampered", record="records/n03-content-tampered.json", key_set="issuer", relying_party=rp, expect="REFUSED:EVENT_ID"),
        dict(id="n04-action-unbound", record=f"records/{POS[0]}", key_set="issuer",
             relying_party=dict(rp, action_hash=hashlib.sha256(b"a different action").hexdigest()), expect="REFUSED:ACTION_UNBOUND"),
        dict(id="n05-after-the-fact", record=f"records/{POS[0]}", key_set="issuer",
             relying_party=dict(rp, executed_at=base["created_at"] - 60), expect="REFUSED:NOT_PRE_ACTION"),
        dict(id="n06-key-binding", record="records/n06-key-binding.json", key_set="issuer-plus-test", relying_party=rp, expect="REFUSED:KEY_BINDING"),
        dict(id="n07-decision-ref-mismatch", record="records/n07-decision-ref-mismatch.json", key_set="issuer-plus-test",
             relying_party=rp, expect="REFUSED:DECISION_REF"),
        dict(id="n08-schema-tag-missing", record="records/n08-schema-tag-missing.json", key_set="issuer-plus-test", relying_party=rp,
             expect="REFUSED:SCHEMA"),
    ]
    write("cases.json", {"suite": "preaction-verdict", "contract": "READER-CONTRACT.md",
                         "key_sets": {"issuer": "keys/issuer-key-set.json", "issuer-plus-test": "keys/issuer-plus-test-key-set.json"},
                         "cases": cases})
    files = sorted(os.path.relpath(os.path.join(dp, f), HERE) for dp, _, fs in os.walk(HERE) for f in fs
                   if f.endswith((".json", ".md", ".py")) and f != "MANIFEST.json" and "__pycache__" not in dp)
    write("MANIFEST.json", {"suite": "preaction-verdict", "files": {f: hashlib.sha256(open(os.path.join(HERE, f), "rb").read()).hexdigest() for f in files}})
    print(f"{len(cases)} cases, {len(files)} files in the manifest; test-only pubkey {TEST_PK}")


if __name__ == "__main__":
    main()
