#!/usr/bin/env python3
"""CORRECT_DELIVERY evaluation records over x402ev/1 receipts (x402-foundation/x402 PR #3682's claim ceiling:
VALID_x402ev != CORRECT_DELIVERY). Builds two receipts in the spec's exact shape -- the spec's own example (`delivered`) and the same
paid call answered with an empty output (`empty`) -- and, for each, the record an independent evaluator judges:
  {scheme, evidenceRef, contentDigest, request {method, urlHash, payloadHash}, request_payload, response_body, question}
The record names the receipt by evidenceRef (the paid delivery event) and carries the bytes behind its digests, so a reader can recompute
both digests from the record and the evidenceRef from the receipt. Writes receipts.json + records_unsigned.json (deterministic)."""
import base64, copy, hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "..", "..", "x402-payment-fingerprint"))
from fingerprint import fingerprint, canonicalize as jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
P1 = json.load(open(os.path.join(HERE, "..", "..", "x402-payment-fingerprint", "vectors.json")))["vectors"][0]["held"]
auth = P1["payload"]["authorization"]
URL = b"https://api.example.com/v1/inference"
PAYLOAD = b'{"model":"example-7b","prompt":"Summarize x402 in one sentence."}'
RESPONSES = {"delivered": b'{"output":"x402 lets a server ask for a payment over HTTP 402 and settle it on-chain before serving the resource."}',
             "empty": b'{"output":""}'}

def receipt(resp, nonce):
    info = {"scheme": "x402ev/1", "canonicalization": "RFC8785",
            "payment": {"network": "eip155:8453", "txHash": "0x" + hashlib.sha256(b"illustrative tx").hexdigest(),
                        "payer": auth["from"].lower(), "payee": auth["to"].lower(), "amount": auth["value"], "asset": P1["asset"].lower(),
                        "fingerprint": fingerprint({"network": P1["network"], "asset": P1["asset"], "scheme": P1["scheme"], "authorization": auth})[1]},
            "request": {"method": "POST", "urlHash": sha(URL), "payloadHash": sha(PAYLOAD), "clientNonce": nonce, "timestamp": 1791024000},
            "delivery": {"statusCode": 200, "contentDigest": sha(resp), "contentType": "application/json", "latencyMs": 42, "timestamp": 1791024001},
            "signer": {"keyType": "Ed25519", "publicKey": b64u(SK.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}}
    body = copy.deepcopy(info)
    info["evidenceRef"] = "x402ev/1:" + sha(jcs(body)); info["signer"]["signature"] = "base64url:" + b64u(SK.sign(jcs(body)))
    return {"evidenceRef": info["evidenceRef"], **{k: v for k, v in info.items() if k != "evidenceRef"}}

receipts = {"delivered": receipt(RESPONSES["delivered"], "d9f8c4e2a1b073e5"), "empty": receipt(RESPONSES["empty"], "a17c3e9b5d0f2864")}
records = {}
for k, r in receipts.items():
    rec = {"scheme": "invinoveritas.delivery-evaluation/1", "evidenceRef": r["evidenceRef"], "contentDigest": r["delivery"]["contentDigest"],
           "request": {kk: r["request"][kk] for kk in ("method", "urlHash", "payloadHash")},
           "request_payload": PAYLOAD.decode(), "response_body": RESPONSES[k].decode(),
           "question": "Does this response deliver what the paid request asked for?"}
    records[k] = {"record": rec, "record_jcs": jcs(rec).decode(), "record_sha256": hashlib.sha256(jcs(rec)).hexdigest()}
json.dump(receipts, open(os.path.join(HERE, "receipts.json"), "w"), indent=2)
json.dump(records, open(os.path.join(HERE, "records_unsigned.json"), "w"), indent=2)
print({k: (v["record_sha256"][:16], receipts[k]["evidenceRef"][-16:]) for k, v in records.items()})
assert receipts["delivered"]["evidenceRef"].endswith("de717d35f610e9") or "de717d35" in receipts["delivered"]["evidenceRef"], receipts["delivered"]["evidenceRef"]
