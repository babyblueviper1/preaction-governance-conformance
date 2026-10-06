#!/usr/bin/env python3
"""x402ev/1 receipt binding: vectors for x402-foundation/x402 PR #3682 (execution_evidence.md @ 6456f987).

The PR leaves two things open that two implementations must agree on byte for byte:
  (a) what evidenceRef hashes -- its example uses the same hex as delivery.contentDigest;
  (b) which bytes signer.signature covers -- "canonicalize the receipt body", but `info` also holds the signature itself and the
      `transparency` inclusion proof, which only exists after the receipt is logged.
This file shows the failure under reading (a) and pins one closing rule (PROPOSED, not adopted by anyone):

  body        = info minus {evidenceRef, signer.signature, transparency}
  evidenceRef = "x402ev/1:sha256:" + hex(sha256(JCS(body)))
  signature   = Ed25519 over JCS(body)
  body.payment.fingerprint = x402-payment-fingerprint/0 of the EIP-3009 authorization (tsc#4), so the delivery receipt joins the
              acceptance record and the buyer's / seller's records by one shared key, also before a txHash exists.
              A matching fingerprint correlates; it does NOT establish settlement (that stays the txHash check).

  python x402ev_binding.py            -> builds vectors.json and runs the checks (ALL PASS)
"""
import base64, copy, hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "x402-payment-fingerprint"))
from fingerprint import fingerprint, canonicalize as jcs          # noqa: E402  (RFC 8785, same as the fingerprint recipe)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey   # noqa: E402
from cryptography.hazmat.primitives import serialization          # noqa: E402

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))       # TEST key (seed 00 01 .. 1f), never use with real assets
PK = base64.urlsafe_b64encode(SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode().rstrip("=")
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
OUTSIDE = ("evidenceRef", "transparency")


def b64u(b): return base64.urlsafe_b64encode(b).decode().rstrip("=")
def unb64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def sha(b): return "sha256:" + hashlib.sha256(b).hexdigest()


def body_of(info):
    b = {k: copy.deepcopy(v) for k, v in info.items() if k not in OUTSIDE}
    b["signer"].pop("signature", None)
    return b


def seal(info):
    b = body_of(info)
    info = dict(info, evidenceRef="x402ev/1:" + sha(jcs(b)))
    info["signer"] = dict(info["signer"], signature="base64url:" + b64u(SK.sign(jcs(b))))
    return info


def check(info, response_bytes):
    """-> list of failed checks (empty = valid under the proposed rule)."""
    bad, b = [], body_of(info)
    if info.get("evidenceRef") != "x402ev/1:" + sha(jcs(b)):
        bad.append("evidenceRef")
    try:
        Ed25519PublicKey.from_public_bytes(unb64u(info["signer"]["publicKey"])).verify(unb64u(info["signer"]["signature"].split(":", 1)[1]), jcs(b))
    except Exception:
        bad.append("signature")
    if sha(response_bytes) != info["delivery"]["contentDigest"]:
        bad.append("contentDigest")
    p = info["payment"]
    if fingerprint(p["authorization_held"])[1] != p["fingerprint"]:
        bad.append("fingerprint")
    return bad


def payment(nonce_byte, tx):
    auth = {"from": "0x857b06519E91e3A54538791bDbb0E22373e36b66", "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C", "value": "10000",
            "validAfter": "0", "validBefore": "1790000000", "nonce": "0x" + nonce_byte * 32}
    held = {"scheme": "exact", "network": "eip155:8453", "asset": USDC, "authorization": auth}
    return {"network": "eip155:8453", "txHash": tx, "payer": auth["from"].lower(), "payee": auth["to"].lower(), "amount": "10000",
            "asset": USDC.lower(), "fingerprint": fingerprint(held)[1], "authorization_held": held}


def receipt(pay, body_bytes, nonce):
    info = {"scheme": "x402ev/1", "canonicalization": "RFC8785", "payment": pay,
            "request": {"method": "POST", "urlHash": sha(b"https://api.example.com/v1/price"), "payloadHash": sha(b'{"pair":"ETH-USD"}'),
                        "clientNonce": nonce, "timestamp": 1791024000},
            "delivery": {"statusCode": 200, "contentDigest": sha(body_bytes), "contentType": "application/json", "timestamp": 1791024001},
            "signer": {"keyType": "Ed25519", "publicKey": PK}}
    return seal(info)


def main():
    cached = b'{"pair":"ETH-USD","price":"4210.55"}'                 # the same cached answer served to two different paid calls
    r1 = receipt(payment("11", "0x" + "a1" * 32), cached, "c1c1c1c1c1c1c1c1")
    r2 = receipt(payment("22", "0x" + "b2" * 32), cached, "c2c2c2c2c2c2c2c2")
    fails = 0
    def t(name, ok):
        nonlocal fails; fails += not ok; print(("PASS " if ok else "FAIL ") + name)
    # reading (a): evidenceRef = contentDigest (the PR example's hex)
    naive1, naive2 = "x402ev/1:" + r1["delivery"]["contentDigest"], "x402ev/1:" + r2["delivery"]["contentDigest"]
    t("reading (a) evidenceRef = contentDigest: two distinct paid calls get the SAME evidenceRef (collision)", naive1 == naive2)
    t("proposed rule: the two paid calls get distinct evidenceRefs", r1["evidenceRef"] != r2["evidenceRef"])
    t("invariant (nutstrut, #3682): evidenceRef equality != contentDigest equality -- same delivered bytes, different evidence records",
      r1["delivery"]["contentDigest"] == r2["delivery"]["contentDigest"] and r1["evidenceRef"] != r2["evidenceRef"]
      and r1["evidenceRef"].split(":", 1)[1] != r1["delivery"]["contentDigest"])
    t("the excluded set is exactly {evidenceRef, signer.signature, transparency}: every other info field is in the signed body",
      set(body_of(r1)) == set(r1) - {"evidenceRef"} and set(body_of(r1)["signer"]) == set(r1["signer"]) - {"signature"})
    t("proposed rule: both receipts verify against the bytes the client holds", check(r1, cached) == [] and check(r2, cached) == [])
    logged = dict(r1, transparency={"logId": "https://scitt.example.org", "entryNumber": 94821, "inclusionProof": "base64url:AAAA"})
    t("adding the transparency inclusion proof after signing changes neither evidenceRef nor signature validity", check(logged, cached) == [])
    tampered = copy.deepcopy(r1); tampered["delivery"]["statusCode"] = 206
    t("a delivery field changed after signing -> evidenceRef + signature fail", set(check(tampered, cached)) >= {"evidenceRef", "signature"})
    t("different response bytes -> contentDigest fails", check(r1, b'{"pair":"ETH-USD","price":"0"}') == ["contentDigest"])
    t("payment.fingerprint is the tsc#4 x402-payment-fingerprint/0 of the held authorization (joins buyer/seller/acceptance records)",
      r1["payment"]["fingerprint"] == fingerprint(r1["payment"]["authorization_held"])[1] and r1["payment"]["fingerprint"] != r2["payment"]["fingerprint"])
    json.dump({"spec": "x402-foundation/x402 PR #3682 execution_evidence.md @ 6456f98735e20f743947f44b0f6eaef1bf2bb496",
               "rule": "PROPOSED: body = info minus {evidenceRef, signer.signature, transparency}; evidenceRef = x402ev/1:sha256(JCS(body)); "
                       "Ed25519 over JCS(body); payment.fingerprint = x402-payment-fingerprint/0",
               "test_key": "Ed25519 seed 000102..1f (test only)", "response_bytes": cached.decode(),
               "receipts": {"call_1": r1, "call_2": r2, "call_1_logged": logged},
               "naive_reading_a": {"call_1": naive1, "call_2": naive2}}, open(os.path.join(HERE, "vectors.json"), "w"), indent=1)
    print("ALL PASS" if not fails else f"{fails} FAIL")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
