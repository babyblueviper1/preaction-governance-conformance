#!/usr/bin/env python3
"""Build vectors.json for resolution-payment-pair-v0 (deterministic; stdlib only).

Two real cases come from fixtures/real.json: our own two Base mainnet USDC payments (EIP-3009 transferWithAuthorization), each
preceded by a signed invinoveritas review verdict over the same action arguments, with the receipts as read from Base.
Every other case is either SYNTHETIC (verdicts signed by a public TEST key derived from a fixed seed, receipts constructed, no
transaction exists) or a NEGATIVE (one field of a real case altered). Each case says which it is in "class".
"""
import copy, hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "tools")); sys.path.insert(0, ROOT)
from _rfc8785 import jcs                                                       # noqa: E402
from _bip340_nostr import _G, _N, _P, _point_mul, _tagged_hash, nostr_event_id  # noqa: E402

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
SEED = hashlib.sha256(b"resolution-payment-pair-v0 synthetic TEST key (public, never use for anything else)").digest()
SK = int.from_bytes(SEED, "big") % _N
PK = _point_mul(_G, SK)
TEST_PUBKEY = PK[0].to_bytes(32, "big").hex()
PAYER, PAYEE = "0x" + "11" * 20, "0x" + "22" * 20   # synthetic addresses, no key behind them


def sign_event(content: dict, created_at: int) -> dict:
    """BIP-340 sign a NIP-01 event with the TEST key (deterministic: aux = 32 zero bytes)."""
    ev = {"pubkey": TEST_PUBKEY, "created_at": created_at, "kind": 30078,
          "tags": [["t", "synthetic-test-vector"]], "content": json.dumps(content, sort_keys=True, separators=(",", ":"))}
    ev["id"] = nostr_event_id(ev)
    msg = bytes.fromhex(ev["id"]); d = SK if PK[1] % 2 == 0 else _N - SK
    t = (d ^ int.from_bytes(_tagged_hash("BIP0340/aux", b"\x00" * 32), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged_hash("BIP0340/nonce", t + bytes.fromhex(TEST_PUBKEY) + msg), "big") % _N
    R = _point_mul(_G, k0); k = k0 if R[1] % 2 == 0 else _N - k0
    rb = R[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged_hash("BIP0340/challenge", rb + bytes.fromhex(TEST_PUBKEY) + msg), "big") % _N
    ev["sig"] = (rb + ((k + e * d) % _N).to_bytes(32, "big")).hex()
    return ev


PRE_FIELDS = ["artifact_hash", "verdict", "verified_at", "action_binding_args_hash", "synthetic_test_vector"]


def synthetic(cid, verdict, nonce_rule, proceed_on, why):
    args = {"chain": "eip155:8453", "token": USDC, "from": PAYER, "to": PAYEE, "amount_atomic": "1000000"}
    if proceed_on is not None:
        args["proceed_on"] = proceed_on; args["accountable_party"] = "synthetic payer (test vector)"
    content = {"schema": "invinoveritas.verdict_proof.v1", "synthetic_test_vector": "SYNTHETIC: signed by a public TEST key, not issued by invinoveritas",
               "artifact_hash": hashlib.sha256(cid.encode()).hexdigest(), "verdict": verdict, "verified_at": 1791500000,
               "action_binding_args_hash": "sha256:" + hashlib.sha256(jcs(args).encode()).hexdigest(),
               "decision_ref_preimage_fields": PRE_FIELDS}
    content["decision_ref"] = "sha256:" + hashlib.sha256(jcs({k: content.get(k) for k in PRE_FIELDS}).encode()).hexdigest()
    ev = sign_event(content, 1791500000)
    nonce = "0x" + content["decision_ref"].split(":")[1] if nonce_rule == "decision_ref" else "0x" + hashlib.sha256(b"random " + cid.encode()).hexdigest()
    tx = "0x" + hashlib.sha256(b"tx " + cid.encode()).hexdigest()
    topic = lambda a: "0x" + "00" * 12 + a[2:].lower()
    receipt = {"transactionHash": tx, "status": "0x1", "blockNumber": "0x0", "blockHash": None, "block_timestamp": hex(1791500003),
               "logs": [{"address": USDC.lower(), "topics": [AUTH_USED, topic(PAYER), nonce], "data": "0x"},
                        {"address": USDC.lower(), "topics": [TRANSFER, topic(PAYER), topic(PAYEE)], "data": "0x" + "%064x" % 1000000}]}
    return {"id": cid, "class": "synthetic", "chain": "eip155:8453", "tx_hash": tx, "note": why,
            "verdict_event": ev, "args": args, "receipt": receipt}


def negative(base, cid, why, mutate):
    c = copy.deepcopy(base); c["id"] = cid; c["class"] = "negative (altered copy of " + base["id"] + ")"; c["note"] = why
    mutate(c); return c


def main():
    real = json.load(open(os.path.join(HERE, "fixtures", "real.json")))
    ex2, ex3 = real
    E = lambda o, *r: {"outcome": o, "reasons": sorted(r)}
    cases = [
        (ex2, E("UNRESOLVED", "payment_does_not_carry_verdict", "execution_policy_not_committed")),
        (ex3, E("UNRESOLVED", "execution_policy_not_committed")),
        (synthetic("s1-approve-carried-policy-permits", "approve_with_concerns", "decision_ref", ["approve", "approve_with_concerns"],
                   "exhibit 3's shape plus a declared execution policy inside the bound args"), E("AUTHORIZED")),
        (synthetic("s2-reject-carried-as-nonce", "reject", "decision_ref", ["approve", "approve_with_concerns"],
                   "a REJECT verdict whose decision_ref the payer used as the nonce anyway: the payment provably carried a verdict the declared policy does not let it execute on"),
         E("UNAUTHORIZED", "executed_on_verdict_outside_policy")),
        (synthetic("s3-random-nonce-policy-permits", "approve_with_concerns", "random", ["approve", "approve_with_concerns"],
                   "exhibit 2's shape plus a declared policy: the policy edge is committed, the binding edge is not"),
         E("UNRESOLVED", "payment_does_not_carry_verdict")),
        (negative(ex3, "n1-args-amount-altered", "the bound args claim a different amount than the verdict signed",
                  lambda c: c["args"].__setitem__("amount_atomic", "2000000")), E("UNRESOLVED", "verdict_does_not_cover_payment")),
        (negative(ex3, "n2-verdict-content-altered", "one byte of the signed verdict changed (verdict upgraded to approve)",
                  lambda c: c["verdict_event"].__setitem__("content", c["verdict_event"]["content"].replace('"approve_with_concerns"', '"approve"', 1))),
         E("UNRESOLVED", "verdict_does_not_cover_payment")),
        (negative(ex3, "n3-policy-added-after-verdict", "proceed_on written into exhibit 3's args after the verdict: the rule no longer predates the payment",
                  lambda c: c["args"].update(proceed_on=["approve", "approve_with_concerns"], accountable_party="added after the fact")),
         E("UNRESOLVED", "verdict_does_not_cover_payment")),
        (negative(ex3, "n4-verdict-signed-by-another-key", "exhibit 3's verdict content re-signed by a different key (the synthetic TEST key)",
                  lambda c: c.__setitem__("verdict_event", sign_event(json.loads(c["verdict_event"]["content"]), c["verdict_event"]["created_at"]))),
         E("UNRESOLVED", "verdict_does_not_cover_payment")),
        (negative(ex3, "n5-receipt-unavailable", "the receipt could not be obtained (RPC down, wrong chain, not mined)",
                  lambda c: c.__setitem__("receipt", None)), E("UNRESOLVED", "evidence_unavailable")),
    ]
    vectors = {"name": "resolution-payment-pair-v0",
               "claim": "payment P executed under the authority of verdict V",
               "discussion": "https://ethereum-magicians.org/t/29846",
               "synthetic_test_pubkey": TEST_PUBKEY, "real_issuer_pubkey": "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7",
               "cases": [dict(c, expect=e) for c, e in cases]}
    with open(os.path.join(HERE, "vectors.json"), "w") as f:
        json.dump(vectors, f, indent=1, ensure_ascii=False); f.write("\n")
    print(f"wrote {len(cases)} cases")


if __name__ == "__main__":
    main()
