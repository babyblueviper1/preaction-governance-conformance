#!/usr/bin/env python3
"""Offline check of CORRECT_DELIVERY evaluation records over x402ev/1 receipts (PR #3682). Trusts neither the presenter nor the evaluator's API.
  1 receipt : evidenceRef recomputes from the receipt body (PR #3682 Receipt Body rule) and the server's Ed25519 signature verifies
  2 subject : record.evidenceRef == receipt.evidenceRef; record.contentDigest == receipt.delivery.contentDigest == sha256(response_body);
              record.request.{method,urlHash,payloadHash} == receipt.request and payloadHash == sha256(request_payload)
  3 binding : sha256(JCS(record)) == the evaluation proof's signed artifact_hash
  4 proof   : NIP-01 id recomputes, BIP-340 signature verifies, pubkey == the evaluator's published key
  + 5 targeted mutations, each failing exactly the step it targets."""
import base64, copy, hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, "..", "..", "x402-payment-fingerprint"), os.path.join(HERE, "..", "..", "..")]
from fingerprint import canonicalize as jcs
from _bip340_nostr import schnorr_verify, nostr_event_id
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
EVALUATOR_KEY = "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7"   # invinoveritas, /.well-known/verifier-keys.json
sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
ub = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def check(receipt, ev):
    body = {k: copy.deepcopy(v) for k, v in receipt.items() if k not in ("evidenceRef", "transparency")}; body["signer"].pop("signature", None)
    if receipt["evidenceRef"] != "x402ev/1:" + sha(jcs(body)):
        return "1 receipt"
    try:
        Ed25519PublicKey.from_public_bytes(ub(receipt["signer"]["publicKey"])).verify(ub(receipt["signer"]["signature"].split(":", 1)[1]), jcs(body))
    except Exception:
        return "1 receipt"
    rec = ev["record"]
    if (rec["evidenceRef"] != receipt["evidenceRef"] or rec["contentDigest"] != receipt["delivery"]["contentDigest"]
            or sha(rec["response_body"].encode()) != rec["contentDigest"] or sha(rec["request_payload"].encode()) != rec["request"]["payloadHash"]
            or any(rec["request"][k] != receipt["request"][k] for k in ("method", "urlHash", "payloadHash"))):
        return "2 subject"
    pe = ev["proof"]; payload = json.loads(pe["content"])
    if hashlib.sha256(jcs(rec)).hexdigest() != payload.get("artifact_hash"):
        return "3 binding"
    if nostr_event_id(pe) != pe["id"] or pe["pubkey"] != EVALUATOR_KEY or not schnorr_verify(bytes.fromhex(pe["id"]), bytes.fromhex(pe["pubkey"]), bytes.fromhex(pe["sig"])):
        return "4 proof"
    return "OK:" + payload["verdict"]

def main():
    R = json.load(open(os.path.join(HERE, "receipts.json"))); E = json.load(open(os.path.join(HERE, "records_signed.json")))
    fails = 0
    def t(name, got, want):
        nonlocal fails; ok = got == want; fails += not ok; print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got {got}"))
    t("delivered: the spec's example receipt + its evaluation -> approve", check(R["delivered"], E["delivered"]), "OK:approve")
    t("empty: same paid request, empty output -> reject", check(R["empty"], E["empty"]), "OK:reject")
    m = copy.deepcopy(R["delivered"]); m["delivery"]["statusCode"] = 206
    t("receipt field changed after the server signed -> step 1", check(m, E["delivered"]), "1 receipt")
    t("the approve evaluation presented for the OTHER receipt -> step 2", check(R["empty"], E["delivered"]), "2 subject")
    m = copy.deepcopy(E["empty"]); m["record"]["response_body"] = E["delivered"]["record"]["response_body"]
    t("evaluation record swapped to the delivered bytes -> step 2", check(R["empty"], m), "2 subject")
    m = copy.deepcopy(E["empty"]); m["proof"] = E["delivered"]["proof"]
    t("the approve proof moved onto the empty record -> step 3", check(R["empty"], m), "3 binding")
    m = copy.deepcopy(E["empty"]); p = json.loads(m["proof"]["content"]); p["verdict"] = "approve"; m["proof"]["content"] = json.dumps(p)
    m["proof"]["content"] = json.dumps(dict(p, artifact_hash=json.loads(E["empty"]["proof"]["content"])["artifact_hash"]))
    t("signed reject edited to approve -> step 4", check(R["empty"], m), "4 proof")
    print("ALL PASS" if not fails else f"{fails} FAIL"); return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
