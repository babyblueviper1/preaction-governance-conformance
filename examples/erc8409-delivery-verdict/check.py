#!/usr/bin/env python3
"""Offline check: an invinoveritas delivery verdict ties back to an ERC-8409 quote. Trusts neither the presenter nor invinoveritas' API.

  1. quote:    recompute the EIP-712 quoteDigest from the envelope, recover the signer, require it == quote.issuer
  2. request:  keccak256(canonical request bytes) == quote.requestHash
  3. record:   deliveryRecord.quote.{quoteDigest, requestHash, ...} == the recomputed quote; sha256(response.body) == response.bodySha256
  4. binding:  sha256(JCS(deliveryRecord)) == the signed proof's artifact_hash (so the verdict cannot be moved to another quote or response)
  5. proof:    NIP-01 event id recomputes, BIP-340 schnorr signature verifies, pubkey == the published verifier key
  6. verdict:  the signed verdict == the receipt field's verdict
Negatives: each mutation below must fail exactly the step it targets.
Needs: eth-account (EIP-712), rfc8785 optional (falls back to sorted-key JSON, identical for this data).
"""
import copy, hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", ".."))
import q8409 as Q                                     # noqa: E402
from _bip340_nostr import schnorr_verify, nostr_event_id   # noqa: E402
from eth_utils import keccak                          # noqa: E402

try:
    import rfc8785
    def jcs(o): return rfc8785.dumps(o)
except ImportError:
    def jcs(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def check(v, case, response_bytes=None):
    """-> (ok, failed_step, detail). response_bytes: the bytes the checking party itself holds (default: the record's body)."""
    env, c = v["envelope"], v["cases"][case]
    q, rec, f = env["quote"], c["deliveryRecord"], c["receiptField"]["deliveryVerdict"]
    qd = Q.quote_digest(int(env["chainId"]), q)
    if Q.recover(int(env["chainId"]), q, env["signature"]).lower() != q["issuer"].lower():
        return False, "1 quote", "signature does not recover the issuer"
    if "0x" + keccak(v["canonicalRequest"].encode()).hex() != q["requestHash"] or jcs(rec["request"]).decode() != v["canonicalRequest"]:
        return False, "2 request", "request bytes do not hash to quote.requestHash"
    rq = rec["quote"]
    if (rq["quoteDigest"], rq["requestHash"], rq["quoteId"], rq["requestScheme"], rq["chainId"]) != (qd, q["requestHash"], q["quoteId"], q["requestScheme"], env["chainId"]) \
            or f["quoteDigest"] != qd:
        return False, "3 record", "delivery record / receipt field names a different quote"
    body = response_bytes if response_bytes is not None else rec["response"]["body"].encode()
    if hashlib.sha256(body).hexdigest() != rec["response"]["bodySha256"]:
        return False, "3 record", "response bytes do not match response.bodySha256"
    ev = f["proof"]; payload = json.loads(ev["content"])
    rh = hashlib.sha256(jcs(rec)).hexdigest()
    if rh != payload.get("artifact_hash") or rh != f["deliveryRecordSha256"]:
        return False, "4 binding", "signed artifact_hash != sha256(JCS(deliveryRecord))"
    if nostr_event_id(ev) != ev["id"] or ev["id"] != f["proofEventId"]:
        return False, "5 proof", "event id does not recompute"
    if ev["pubkey"] != v["verifier_pubkey"] or not schnorr_verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])):
        return False, "5 proof", "schnorr signature / key"
    if payload.get("verdict") != f["verdict"]:
        return False, "6 verdict", "receipt verdict differs from the signed verdict"
    return True, None, payload["verdict"]


def main():
    v = json.load(open(os.path.join(HERE, "vectors.json")))
    fails = 0
    def t(name, got, want):
        nonlocal fails
        ok = got == want; fails += not ok
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got {got} want {want}"))
    for case, c in v["cases"].items():
        ok, step, det = check(v, case)
        t(f"{case}: all six steps hold, signed verdict = {c['expected']['verdict']}", (ok, det), (True, c["expected"]["verdict"]))
    def mut(fn):
        w = copy.deepcopy(v); fn(w); return w
    t("quote amount changed after signing -> step 1", check(mut(lambda w: w["envelope"]["quote"].update(amount="1000001")), "delivered")[1], "1 quote")
    t("different request (days=6) -> step 2", check(mut(lambda w: w["cases"]["delivered"]["deliveryRecord"]["request"]["body"].update(days=6)), "delivered")[1], "2 request")
    t("disputing party holds different response bytes -> step 3", check(v, "paid_not_delivered", b'{"city":"Santiago","days":7,"forecast":[1]}')[1], "3 record")
    def swap(w):
        w["cases"]["paid_not_delivered"]["receiptField"]["deliveryVerdict"].update(
            {k: v["cases"]["delivered"]["receiptField"]["deliveryVerdict"][k] for k in ("verdict", "proofEventId", "proof", "deliveryRecordSha256")})
    t("the approve proof moved onto the not-delivered record -> step 4", check(mut(swap), "paid_not_delivered")[1], "4 binding")
    def forge(w):
        ev = w["cases"]["paid_not_delivered"]["receiptField"]["deliveryVerdict"]["proof"]
        p = json.loads(ev["content"]); p["verdict"] = "approve"; ev["content"] = json.dumps(p)
    t("signed verdict edited reject -> approve -> step 5", check(mut(forge), "paid_not_delivered")[1], "5 proof")
    t("receipt claims approve over a signed reject -> step 6",
      check(mut(lambda w: w["cases"]["paid_not_delivered"]["receiptField"]["deliveryVerdict"].update(verdict="approve")), "paid_not_delivered")[1], "6 verdict")
    print(f"{'ALL PASS' if not fails else str(fails) + ' FAIL'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
