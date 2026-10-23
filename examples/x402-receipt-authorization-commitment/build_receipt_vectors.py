#!/usr/bin/env python3
"""Regenerate receipt_vectors.json (deterministic; standard library only).

Every receipt is signed by a test key derived from a public label, with RFC 6979 nonces, so the
file is byte-for-byte reproducible. The settlement side is real: the candidate set is the
12-nonce Base Sepolia snapshot in candidates_snapshot.json, and the committed nonces are
settlements A and B from that snapshot.

  python3 build_receipt_vectors.py && python3 receipt_check.py
"""
import hashlib
import json
import os

import receipt_check as rc

HERE = os.path.dirname(os.path.abspath(__file__))
SNAP = json.load(open(os.path.join(HERE, "candidates_snapshot.json"), encoding="utf-8"))


def _key(label: str) -> int:
    return int.from_bytes(hashlib.sha256(("x402-receipt-vectors/" + label).encode()).digest(), "big")


def _salt(label: str) -> str:
    return "0x" + hashlib.sha256(("x402-rac-receipt-test-salt/" + label).encode()).hexdigest()


SIGNER = _key("test-signer/1")
OTHER_SIGNER = _key("test-signer/2")
SIGNER_ADDR = rc.address_of_key(SIGNER)
KID = "did:web:seller.example#receipt-key-1"
AUTH = {"eip712": [SIGNER_ADDR], "jws": {KID: SIGNER_ADDR}}

ASSET = SNAP["asset"]                      # USDC on Base Sepolia
OTHER_ASSET = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"  # USDC on Base mainnet
PAYER = SNAP["authorizer"]
OTHER_AUTHORIZER = "0x857b06519e91e3a54538791bdbb0e22373e36b66"
BY_BLOCK = {c["block"]: c for c in SNAP["candidates"]}
A, B = BY_BLOCK[48163177], BY_BLOCK[48163178]   # the two consecutive-block settlements
ABSENT_NONCE = "0x" + hashlib.sha256(b"x402-receipt-vectors/nonce-not-consumed").hexdigest()


def commit_to(nonce: str, salt: str, asset: str = ASSET, authorizer: str = PAYER, method: str = "eip3009") -> str:
    return rc.commitment(method, bytes.fromhex(asset[2:]), bytes.fromhex(authorizer[2:]),
                         bytes.fromhex(nonce[2:]), bytes.fromhex(salt[2:]))


def payload(version: int = 2, transaction: str = "", method: str = "eip3009", commitment: str = "", **extra) -> dict:
    p = {"version": version, "network": SNAP["network"], "resourceUrl": "https://seller.example/premium-data",
         "payer": PAYER, "issuedAt": 1792000000, "transaction": transaction}
    if version == 2:
        p["authorizationMethod"] = method
        p["authorizationCommitment"] = commitment
    p.update(extra)
    return p


def eip712(p: dict, key: int = SIGNER, types_version=None) -> dict:
    return {"format": "eip712", "payload": p, "signature": rc.sign_eip712(key, p, types_version or p["version"])}


def jws(p: dict, key: int = SIGNER) -> dict:
    return {"format": "jws", "signature": rc.sign_jws_es256k(key, p, KID)}


SA = _salt("A")
C_A = commit_to(A["nonce"], SA)
LINKED = {"receipt": "valid", "signer": SIGNER_ADDR}

V = []


def vec(id_, receipt, expect, held=None, candidates="snapshot", note="", proposed=False):
    v = {"id": id_, "kind": "receipt", "receipt": receipt, "authorized_signers": AUTH,
         "held": held if held is not None else {"salt": SA, "asset": ASSET},
         "candidates": candidates, "expect": expect}
    if note:
        v["note"] = note
    if proposed:
        v["proposed"] = True
    V.append(v)


def link_expect(result, **kw):
    e = dict(LINKED)
    e["link"] = dict(result=result, **kw)
    return e


# ---- linked and its neighbours (section 5.6.4)
vec("receipt-v2-linked", eip712(payload(commitment=C_A)),
    link_expect("linked", nonce=A["nonce"], transaction=A["tx"]),
    note="signed v2 receipt, salt and asset held, candidate set obtained (12 real nonces); exactly one opens: settlement A")
vec("receipt-v2-linked-transaction-agrees", eip712(payload(commitment=C_A, transaction=A["tx"])),
    link_expect("linked", nonce=A["nonce"], transaction=A["tx"]),
    note="transaction is set and names the same settlement the commitment opens to")
vec("receipt-v2-inconsistent", eip712(payload(commitment=C_A, transaction=B["tx"])),
    link_expect("inconsistent", nonce=A["nonce"], transaction=A["tx"]),
    note="the commitment opens to A while transaction names B (the next block): the signer asserts two settlements; MUST NOT link to either")
vec("receipt-v2-no-match-false-commitment", eip712(payload(commitment=commit_to(ABSENT_NONCE, SA))),
    link_expect("no_match", detail="matches=0"),
    note="the commitment is to a nonce the payer never consumed")
vec("receipt-v2-no-match-wrong-salt", eip712(payload(commitment=C_A)),
    link_expect("no_match", detail="matches=0"), held={"salt": _salt("B"), "asset": ASSET},
    note="a wrong salt is indistinguishable from a false commitment (hiding); no_match is about the salt and asset used")
vec("receipt-v2-no-match-wrong-asset", eip712(payload(commitment=C_A)),
    link_expect("no_match", detail="matches=0"), held={"salt": SA, "asset": OTHER_ASSET},
    note="asset held is mainnet USDC, the payment was on Base Sepolia USDC")
vec("receipt-v2-no-match-other-authorizer", eip712(payload(commitment=commit_to(A["nonce"], SA, authorizer=OTHER_AUTHORIZER))),
    link_expect("no_match", detail="matches=0"),
    held={"salt": SA, "asset": ASSET, "authorizer": OTHER_AUTHORIZER},
    note="commitment made with another authorizer; the held authorizer is ignored because step 1 takes it from the signed payer")
vec("receipt-v2-no-match-two-candidates", eip712(payload(commitment=C_A)),
    link_expect("no_match", detail="matches=2"),
    candidates=[{"nonce": A["nonce"], "tx": A["tx"]}, {"nonce": A["nonce"], "tx": B["tx"]}],
    note="the identifier appears twice in the candidate set (an identifier that can repeat): more than one match is no_match, fail closed")
vec("receipt-v2-no-match-empty-set", eip712(payload(commitment=C_A)),
    link_expect("no_match", detail="matches=0"), candidates=[],
    note="the query succeeded and returned no candidates: a finished check, contrast receipt-v2-incomplete-*")
vec("receipt-v2-incomplete-unobtainable", eip712(payload(commitment=C_A)),
    link_expect("incomplete", detail="candidate_set_unobtainable"),
    candidates={"status": "unobtainable", "note": "log query not answered"})
vec("receipt-v2-incomplete-rate-limited", eip712(payload(commitment=C_A)),
    link_expect("incomplete", detail="candidate_set_unobtainable"),
    candidates={"status": "unobtainable", "note": "rate-limited query that returned an empty list"},
    note="a failed or rate-limited query that returns [] is incomplete, never no_match; counts MUST NOT drop the receipt")

# ---- not_attempted
vec("receipt-v2-not-attempted-no-commitment", eip712(payload(method="", commitment="")),
    link_expect("not_attempted", detail="no_commitment"), note="version 2 with both fields empty")
vec("receipt-v1-not-attempted", eip712(payload(version=1)),
    link_expect("not_attempted", detail="no_commitment"), note="a version 1 receipt has no commitment fields")
vec("receipt-v2-not-attempted-salt-not-held", eip712(payload(commitment=C_A)),
    link_expect("not_attempted", detail="salt_not_held"), held={"asset": ASSET})
vec("receipt-v2-not-attempted-asset-not-held", eip712(payload(commitment=C_A)),
    link_expect("not_attempted", detail="asset_not_held"), held={"salt": SA},
    note="the receipt does not carry asset; receipt plus salt alone do not link")
vec("receipt-v2-not-attempted-unsupported-method",
    eip712(payload(method="permit2", commitment=commit_to(A["nonce"], SA, method="permit2"))),
    link_expect("not_attempted", detail="unsupported_method"),
    note="an authorizationMethod this verifier does not implement is not malformed (5.3, 5.6.4); requested on x402#3827")

# ---- malformed
vec("receipt-v2-malformed-method-only", eip712(payload(method="eip3009", commitment="")),
    link_expect("malformed", detail="one_of_method_and_commitment"), note="MUST NOT attempt a link")
vec("receipt-v2-malformed-commitment-only", eip712(payload(method="", commitment=C_A)),
    link_expect("malformed", detail="one_of_method_and_commitment"),
    note="the commitment would open to A if tried; a verifier MUST NOT try")

# ---- the receipt itself (section 5.5): no link result
p2 = payload(commitment=C_A)
vec("receipt-v2-signed-with-v1-types", eip712(p2, types_version=1),
    {"receipt": "rejected", "reason": "signer_not_authorized"},
    note="the signer hashed a version 2 payload with the version 1 types; a verifier selects types by payload.version, recovers a different address, and rejects. This is the compatibility property: a v2 receipt never verifies through v1 types")
v1 = eip712(payload(version=1))
upgraded = dict(v1, payload=payload(commitment=C_A))
vec("receipt-v1-signature-relabelled-v2", upgraded, {"receipt": "rejected", "reason": "signer_not_authorized"},
    note="a valid v1 signature with the payload rewritten to version 2 and a commitment added: the v2 digest differs, so the commitment cannot be smuggled under a v1 signature")
tampered = eip712(p2)
tampered = dict(tampered, payload=dict(p2, authorizationCommitment=commit_to(B["nonce"], SA)))
vec("receipt-v2-commitment-altered-after-signing", tampered, {"receipt": "rejected", "reason": "signer_not_authorized"},
    note="commitment swapped to one that opens to B; the signature no longer covers the payload")
vec("receipt-v2-signer-not-authorized", eip712(p2, key=OTHER_SIGNER), {"receipt": "rejected", "reason": "signer_not_authorized"},
    note="valid signature by a key not authorised for resourceUrl (4.5.1); the commitment would link if tried")
p3 = payload(commitment=C_A)
p3["version"] = 3
vec("receipt-unknown-version", {"format": "eip712", "payload": p3, "signature": rc.sign_eip712(SIGNER, payload(commitment=C_A), 2)},
    {"receipt": "rejected", "reason": "unsupported_version"}, note="only versions 1 and 2 are defined")

# ---- JWS (ES256K)
vec("receipt-jws-v2-linked", jws(payload(commitment=C_A)),
    link_expect("linked", nonce=A["nonce"], transaction=A["tx"]), note="JWS compact, ES256K, kid resolved by the fixture")
vec("receipt-jws-v2-malformed", jws({k: v for k, v in payload(commitment=C_A).items() if k != "authorizationMethod"}),
    link_expect("malformed", detail="one_of_method_and_commitment"),
    note="in JWS absent and empty are the same; the commitment is present without a method")
good = jws(payload(commitment=C_A))
h, b, s = good["signature"].split(".")
b2 = rc._b64u(json.dumps(payload(commitment=C_A, transaction=B["tx"]), separators=(",", ":")).encode())
vec("receipt-jws-payload-altered", {"format": "jws", "signature": h + "." + b2 + "." + s},
    {"receipt": "rejected", "reason": "signature_invalid"}, note="transaction added after signing")

# ---- cases the text does not settle: expected results proposed, for the author to accept or change
vec("receipt-v1-carrying-commitment-fields", eip712(payload(version=1, authorizationMethod="eip3009", authorizationCommitment=C_A)),
    link_expect("not_attempted", detail="no_commitment"), proposed=True,
    note="PROPOSED. A version 1 payload carrying the two fields: the v1 types do not cover them, so the signature verifies but does not sign them. Proposed: a verifier MUST NOT use unsigned fields, so not_attempted. A verifier that links here links on unsigned data")
vec("receipt-v2-commitment-not-32-byte-hex", eip712(payload(commitment="0x" + C_A[2:-2])),
    link_expect("malformed", detail="commitment_encoding"), proposed=True,
    note="PROPOSED. Method and commitment both non-empty but the commitment is 31 bytes. 5.3 defines malformed only for one field set; proposed: an undecodable commitment is also malformed rather than no_match, because no candidate could ever match it")
vec("receipt-v2-salt-inside-payload", eip712(payload(commitment=C_A, authorizationSalt=SA)),
    link_expect("not_attempted", detail="salt_not_held"), held={"asset": ASSET}, proposed=True,
    note="PROPOSED. The salt sits inside the payload, which 5.6.3 prohibits. EIP-712 types ignore it, so the signature still verifies. Proposed: the verifier does not take a salt from the receipt, so with no salt held otherwise the result is not_attempted")

doc = {
    "name": "x402-receipt-authorization-commitment/0 receipt-level vectors",
    "license": "CC0-1.0",
    "spec": "x402-foundation/x402#3827 at fe777a4e02f3b55e76a246f17bc3ddc616ba3a9c, specs/extensions/extension-offer-and-receipt.md sections 3, 5.2 to 5.6",
    "candidates_snapshot": "candidates_snapshot.json",
    "test_signer": {"address": SIGNER_ADDR, "derivation": "sha256('x402-receipt-vectors/test-signer/1') as a secp256k1 private key; test only"},
    "test_salts": "sha256('x402-rac-receipt-test-salt/<label>'); not valid production salts",
    "authorized_signers": "stands in for 4.5.1, which leaves the authorisation mechanism open",
    "vectors": V,
}
with open(os.path.join(HERE, "receipt_vectors.json"), "w", encoding="utf-8", newline="\n") as f:
    json.dump(doc, f, indent=1)
    f.write("\n")
print("wrote %d receipt vectors" % len(V))
