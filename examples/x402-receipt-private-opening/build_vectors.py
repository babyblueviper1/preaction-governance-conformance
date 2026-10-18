"""Regenerate vectors.json for x402-receipt-private-opening/1 (deterministic: fixed test key, fixed checked_at).

Real data: settlement A of the sibling kit (Base Sepolia USDC, payer 0x87f3...6ee1, tx 0x1345479a..., block 48163177),
whose receipt logs carry AuthorizationUsed(payer, nonce A) at logIndex 180 and Transfer(payer -> 0x2888...ec26, 1000)
at 181 in the same transaction. The other 11 consumed nonces come from the sibling kit's candidates_snapshot.json.
The verifier key is a PUBLIC TEST KEY from a fixed seed: never use it for anything else.
"""
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import statement as S  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.join(HERE, "..", "x402-receipt-authorization-commitment")
SECRET = hashlib.sha256(b"x402-private-opening-test-verifier/0").digest()
OTHER = hashlib.sha256(b"x402-private-opening-untrusted-verifier/0").digest()

kit = json.load(open(os.path.join(KIT, "vectors.json")))
snap = json.load(open(os.path.join(KIT, "candidates_snapshot.json")))
cA = next(v for v in kit["vectors"] if v["id"] == "commit-A")
cB = next(v for v in kit["vectors"] if v["id"] == "commit-B")
ASSET, PAYER, NONCE_A = cA["asset"], cA["authorizer"], cA["nonce"]
TX_A = "0x1345479a7c529962b1c71138d961b834547ab4e27e43a535f88e148e24f2de88"
PAYTO_A = "0x2888f36548a900b9b08d584524e1f73bc563ec26"
CHAIN = {"source": snap["source"] + "; settlement A transfers from eth_getTransactionReceipt (sepolia.base.org)",
         "nonces": {c["nonce"]: {"tx": c["tx"], "status": 1, "transfers": None} for c in snap["candidates"]}}  # None = not read
CHAIN["nonces"][NONCE_A] = {"tx": TX_A, "status": 1, "transfers": [{"to": PAYTO_A, "amount": "1000", "log_index": 181}]}
# The head the snapshot was read through (Base Sepolia block 48164856, timestamp 2026-10-15T21:00:00Z = the snapshot time)
# and settlement A's own block (48163177), both from sepolia.base.org. The statement binds the HEAD, never the settlement block.
READ_AT = {"number": 48164856, "hash": "0x75f13f1403ee4cdc44a76ef58ea52ba23677dfc43a1acceef1b6ee021b06bb98"}
SETTLE_BLOCK = {"number": 48163177, "hash": "0xbb8c63ebfad08e91405d09391a734eb2c23dc0abd047217350748de348f46016"}
CHAIN["canonical"] = {str(READ_AT["number"]): READ_AT["hash"]}
REORGED = {"number": READ_AT["number"], "hash": "0x" + hashlib.sha256(b"x402-private-opening-test-orphaned-block").hexdigest()}

RECEIPT = {"payer": PAYER, "resourceUrl": "https://seller.example/api/resource", "network": "eip155:84532",
           "issuedAt": 1776000000, "authorizationMethod": "eip3009", "authorizationCommitment": cA["expect"]["commitment"]}
OPEN_A = {"salt": cA["salt"], "asset": ASSET}
OPEN_WRONG = {"salt": cB["salt"], "asset": ASSET}   # the salt of settlement B: opens to nothing for commitment A
AGENT, AGENT2 = "eip155:84532:erc8004:agent/7", "eip155:84532:erc8004:agent/9"
WALLETS, UNBOUND = [PAYTO_A], ["0x1111111111111111111111111111111111111111"]
RATER_OTHER = "0x2222222222222222222222222222222222222222"
T0 = "2026-10-17T01:00:00Z"


def vectors():
    out = []
    for vid, rater, opening, wallets, want, why in (
        ("assess-opens", PAYER, OPEN_A, WALLETS, "opens_to_settlement", "commitment opens to settlement A; payer is the rater; payTo is the agent's wallet"),
        ("assess-rater-not-payer", RATER_OTHER, OPEN_A, WALLETS, "payer_is_not_rater", "a rater cannot ground with someone else's payment (sec 5.5: the authorizer is the receipt's signed payer)"),
        ("assess-wrong-salt", PAYER, OPEN_WRONG, WALLETS, "no_settlement", "settlement B's salt opens commitment A to none of the payer's 12 nonces"),
        ("assess-payto-unbound", PAYER, OPEN_A, UNBOUND, "payto_not_bound_to_agent", "a real settlement, but it paid a wallet the rated agent does not hold"),
    ):
        out.append({"id": vid, "kind": "assess", "receipt": RECEIPT, "opening": opening, "rater": rater,
                    "agent_wallets": wallets, "expect": {"result": want}, "why": why})

    out.append({"id": "assess-chain-unavailable", "kind": "assess", "receipt": RECEIPT, "opening": OPEN_A, "rater": PAYER,
                "agent_wallets": WALLETS, "chain": {"available": False, "error": "rate limited"}, "expect": {"result": "incomplete_check"},
                "why": "the log query failed: an incomplete check, never no_settlement (x402#3827 sec 5.6.4); it counts toward nothing"})
    s0 = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT, ASSET, T0, 0, S.ZERO, SECRET, READ_AT)
    out.append({"id": "statement-no-leak", "kind": "privacy", "statement": s0, "secrets": [NONCE_A, TX_A, OPEN_A["salt"], SETTLE_BLOCK["hash"]],
                "expect": {"leaks": []}, "why": "the signed statement names the receipt, rater, agent, result and the head it read through, never the nonce, tx, salt or settlement block"})
    out.append({"id": "challenge-upheld", "kind": "challenge", "statement": s0, "receipt": RECEIPT, "public_opening": OPEN_A,
                "agent_wallets": WALLETS, "expect": {"result": "upheld"}, "why": "the rater later publishes the salt; anyone recomputes the same finding"})
    liar = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT2, ASSET, T0, 0, S.ZERO, SECRET, READ_AT)
    out.append({"id": "challenge-refuted", "kind": "challenge", "statement": liar, "receipt": RECEIPT, "public_opening": OPEN_A,
                "agent_wallets": UNBOUND, "expect": {"result": "refuted"},
                "why": "the verifier signed opens_to_settlement for an agent whose wallets the payment never reached; the public opening shows it"})
    other_receipt = {**RECEIPT, "issuedAt": RECEIPT["issuedAt"] + 1}
    out.append({"id": "challenge-not-bound", "kind": "challenge", "statement": s0, "receipt": other_receipt, "public_opening": OPEN_A,
                "agent_wallets": WALLETS, "expect": {"result": "not_bound"},
                "why": "a statement cannot be replayed onto another receipt: it binds sha256 of the receipt it opened"})

    stale = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT, ASSET, T0, 0, S.ZERO, SECRET, REORGED)
    out.append({"id": "challenge-reorged", "kind": "challenge", "statement": stale, "receipt": RECEIPT, "public_opening": OPEN_A,
                "agent_wallets": WALLETS, "expect": {"result": "reorged"},
                "why": "the block the verifier read through is no longer canonical: a reorg, re-checked, never counted as a wrong answer"})

    s1 = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT, ASSET, "2026-10-17T01:05:00Z", 1,
                          hashlib.sha256(S.canon(s0)).hexdigest(), SECRET, READ_AT)
    s2 = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT2, ASSET, "2026-10-17T01:10:00Z", 2,
                          hashlib.sha256(S.canon(s1)).hexdigest(), SECRET, READ_AT)
    log = [s0, s1, s2]
    out.append({"id": "log-intact", "kind": "log", "statements": log, "expect": {"ok": True}, "why": "seq 0..2, each prev = sha256(previous)"})
    tampered = copy.deepcopy(log)
    tampered[1]["result"] = "no_settlement"
    out.append({"id": "log-tampered", "kind": "log", "statements": tampered, "expect": {"ok": False},
                "why": "a past statement edited after the fact breaks its own signature and the next prev"})
    untrusted = S.make_statement(RECEIPT, "opens_to_settlement", RATER_OTHER, AGENT, ASSET, T0, 0, S.ZERO, OTHER, READ_AT)
    # a /0 statement (no read_at) from the trusted verifier, for a third agent: signed, but not counted under /1
    v0 = {k: v for k, v in S.make_statement(RECEIPT, "opens_to_settlement", PAYER, "eip155:84532:erc8004:agent/11", ASSET, T0, 0,
                                             S.ZERO, SECRET, READ_AT).items() if k not in ("read_at", "signature")}
    v0["type"] = "x402-receipt-private-opening/0"
    v0["signature"] = S._b64u(S.ed.sign(SECRET, S.canon(v0)))
    out.append({"id": "pairs", "kind": "count", "statements": log + [untrusted, v0], "trusted": [s0["verifier"]],
                "expect": {"pairs": sorted([[PAYER.lower(), AGENT], [PAYER.lower(), AGENT2]])},
                "why": "three ratings by one rater over two agents count as 2 (rater, agent) pairs; a statement from an unnamed verifier counts as none, and neither does a /0 statement with no read_at"})
    return {"name": S.TYPE, "license": "CC0-1.0", "verifier_test_key": s0["verifier"], "chain": CHAIN, "vectors": out}


if __name__ == "__main__":
    with open(os.path.join(HERE, "vectors.json"), "w") as f:
        json.dump(vectors(), f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote vectors.json")
