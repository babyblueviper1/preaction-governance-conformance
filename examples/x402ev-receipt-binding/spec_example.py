#!/usr/bin/env python3
"""A fully concrete example receipt in the exact shape of x402-foundation/x402 PR #3682 (execution_evidence.md @ e7b7c607), for its
"Response Extension Object Shape" section: every value recomputes under the PR's own Receipt Body rule.
  - payment: the EIP-3009 authorization of x402-payment-fingerprint vector P1 (same-1-buyer-v1), so payment.fingerprint recomputes too
  - request/delivery digests: sha256 of the bytes shown in the comments below
  - signer: TEST Ed25519 key, seed 00 01 .. 1f (never use with real assets); txHash is an illustrative 32-byte value, not a real tx
  python spec_example.py  -> prints the info object and the recomputation (evidenceRef, signature verify, fingerprint)"""
import base64, copy, hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "..", "x402-payment-fingerprint"))
from fingerprint import fingerprint, canonicalize as jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
P1 = json.load(open(os.path.join(HERE, "..", "x402-payment-fingerprint", "vectors.json")))["vectors"][0]["held"]
auth = P1["payload"]["authorization"]
URL = b"https://api.example.com/v1/inference"
PAYLOAD = b'{"model":"example-7b","prompt":"Summarize x402 in one sentence."}'
RESPONSE = b'{"output":"x402 lets a server ask for a payment over HTTP 402 and settle it on-chain before serving the resource."}'
info = {"scheme": "x402ev/1", "canonicalization": "RFC8785",
        "payment": {"network": "eip155:8453", "txHash": "0x" + hashlib.sha256(b"illustrative tx").hexdigest(),
                    "payer": auth["from"].lower(), "payee": auth["to"].lower(), "amount": auth["value"],
                    "asset": P1["asset"].lower(),
                    "fingerprint": fingerprint({"network": P1["network"], "asset": P1["asset"], "scheme": P1["scheme"], "authorization": auth})[1]},
        "request": {"method": "POST", "urlHash": sha(URL), "payloadHash": sha(PAYLOAD), "clientNonce": "d9f8c4e2a1b073e5", "timestamp": 1791024000},
        "delivery": {"statusCode": 200, "contentDigest": sha(RESPONSE), "contentType": "application/json", "latencyMs": 42, "timestamp": 1791024001},
        "signer": {"keyType": "Ed25519", "publicKey": b64u(SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}}
body = copy.deepcopy(info)
info["evidenceRef"] = "x402ev/1:" + sha(jcs(body))
info["signer"]["signature"] = "base64url:" + b64u(SK.sign(jcs(body)))
out = {"evidenceRef": info["evidenceRef"], **{k: v for k, v in info.items() if k != "evidenceRef"}}
# recompute exactly as the PR's rule says
re_body = {k: copy.deepcopy(v) for k, v in out.items() if k not in ("evidenceRef", "transparency")}; re_body["signer"].pop("signature")
assert out["evidenceRef"] == "x402ev/1:" + sha(jcs(re_body))
pk = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(out["signer"]["publicKey"] + "=="))
pk.verify(base64.urlsafe_b64decode(out["signer"]["signature"].split(":", 1)[1] + "=="), jcs(re_body))
logged = dict(out, transparency={"logId": "https://scitt.example.org", "entryNumber": 94821, "inclusionProof": "base64url:AAAA"})
lb = {k: copy.deepcopy(v) for k, v in logged.items() if k not in ("evidenceRef", "transparency")}; lb["signer"].pop("signature")
assert jcs(lb) == jcs(re_body)
json.dump(out, open(os.path.join(HERE, "spec_example.json"), "w"), indent=2)
print(json.dumps(out, indent=2))
print("\nRECOMPUTES: evidenceRef ok, Ed25519 signature ok, unchanged with transparency attached, fingerprint = vector P1's")
