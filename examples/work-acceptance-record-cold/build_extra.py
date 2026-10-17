"""Six proposed vectors (06-11) for the cases the upstream five do not reach. Expectations are OURS (proposed), each
derived from the README property it tests; three need re-signing and use OUR public test key (the upstream key is not
published). Keys are inputs in this format, so a re-signed vector is as valid a test as the upstream ones."""
import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import war_check as W  # noqa: E402

V1 = json.load(open(os.path.join(HERE, "upstream_vectors", "01-valid.json")))
SK = hashlib.sha256(b"war-cold-test-key/invinoveritas").digest()     # PUBLIC TEST KEY
KID = "invinoveritas-test-1"
KEYS = {"issuer": "invinoveritas (test vectors)", "keys": [
    {"alg": "Ed25519", "key_id": KID, "public_key_base64": base64.b64encode(W.ed.public_key(SK)).decode(), "status": "test"}]}


def resign(inputs, edit):
    i = copy.deepcopy(inputs)
    r = i["receipt"]["receipt"]
    edit(r)
    r["key_id"] = r["parties"]["checker"]["key_id"] = KID
    i["receipt"]["signature"] = {"alg": "Ed25519", "key_id": KID, "value": base64.b64encode(W.ed.sign(SK, W.jcs(r))).decode()}
    i["keys"] = KEYS
    i["receipt_tsr_base64"] = None
    return i


def swap_in_token(tok_b64, old: bytes, new: bytes):
    raw = base64.b64decode(tok_b64)
    assert raw.count(old) == 1 and len(old) == len(new)
    return base64.b64encode(raw.replace(old, new)).decode()


def vectors():
    out = []
    i = copy.deepcopy(V1["inputs"])
    i["receipt"]["receipt"]["results"][0]["finding"] = "Met, edited after signing."
    out.append(("06-receipt-edited-after-signing", i, "A finding edited after the checker signed: signature step 2 fails."))
    i = copy.deepcopy(V1["inputs"])
    i["criteria_file_base64"] = base64.b64encode(b'{"criteria":[],"title":"another document"}').decode()
    out.append(("07-criteria-file-swapped", i, "The supplied criteria document is not the one the receipt names (step 4)."))
    i = copy.deepcopy(V1["inputs"])
    i["receipt_tsr_base64"] = swap_in_token(i["receipt_tsr_base64"],
                                            bytes.fromhex(i["receipt"]["timestamp"]["digest_sha256"]),
                                            hashlib.sha256(b"a different receipt").digest())
    out.append(("08-receipt-token-over-another-receipt", i, "The receipt's timestamp token imprints another receipt (step 5)."))

    def stated_pass_but_incomplete(r):
        r["results"][1]["result"] = "not-evaluated"
    out.append(("09-stated-pass-recomputes-incomplete", resign(V1["inputs"], stated_pass_but_incomplete),
                "Signed verdict pass, but a required criterion is not-evaluated: step 6 recomputes incomplete."))

    def backdated(r):
        pass                                                   # receipt keeps committed_at 2026-03-01
    i = resign(V1["inputs"], backdated)
    i["criteria_tsr_base64"] = swap_in_token(i["criteria_tsr_base64"], b"20260301000000Z", b"20261201000000Z")
    out.append(("10-committed-at-contradicts-token", i,
                "committed_at says 2026-03-01; the token over the criteria hash says 2026-12-01, after the 2026-06-01 check. "
                "Property 2: the token is the commitment. A verifier that compares only committed_at (step 4 as written) says yes."))

    def required_fail(r):
        r["results"][0]["result"] = "fail"
        r["verdict"] = "fail"
    out.append(("11-required-criterion-fails", resign(V1["inputs"], required_fail),
                "A required criterion fails. The README does not say the verdict; we propose fail (and fail over incomplete)."))
    return [{"description": d, "inputs": i, "expected": {k: v for k, v in W.check(i).items() if not k.startswith("_")},
             "expected_is": "proposed by invinoveritas, not upstream"} | {"name": n} for n, i, d in out]


if __name__ == "__main__":
    os.makedirs(os.path.join(HERE, "proposed_vectors"), exist_ok=True)
    for v in vectors():
        with open(os.path.join(HERE, "proposed_vectors", v["name"] + ".json"), "w") as f:
            json.dump(v, f, indent=1, sort_keys=True)
            f.write("\n")
        print(v["name"], json.dumps(v["expected"]))
