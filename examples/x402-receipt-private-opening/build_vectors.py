"""Regenerate vectors.json for x402-receipt-private-opening/0 (deterministic: fixed test key, fixed checked_at).

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
    s0 = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT, ASSET, T0, 0, S.ZERO, SECRET)
    out.append({"id": "statement-no-leak", "kind": "privacy", "statement": s0, "secrets": [NONCE_A, TX_A, OPEN_A["salt"]],
                "expect": {"leaks": []}, "why": "the signed statement names the receipt, rater, agent and result, never the nonce, tx or salt"})
    out.append({"id": "challenge-upheld", "kind": "challenge", "statement": s0, "receipt": RECEIPT, "public_opening": OPEN_A,
                "agent_wallets": WALLETS, "expect": {"result": "upheld"}, "why": "the rater later publishes the salt; anyone recomputes the same finding"})
    liar = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT2, ASSET, T0, 0, S.ZERO, SECRET)
    out.append({"id": "challenge-refuted", "kind": "challenge", "statement": liar, "receipt": RECEIPT, "public_opening": OPEN_A,
                "agent_wallets": UNBOUND, "expect": {"result": "refuted"},
                "why": "the verifier signed opens_to_settlement for an agent whose wallets the payment never reached; the public opening shows it"})
    other_receipt = {**RECEIPT, "issuedAt": RECEIPT["issuedAt"] + 1}
    out.append({"id": "challenge-not-bound", "kind": "challenge", "statement": s0, "receipt": other_receipt, "public_opening": OPEN_A,
                "agent_wallets": WALLETS, "expect": {"result": "not_bound"},
                "why": "a statement cannot be replayed onto another receipt: it binds sha256 of the receipt it opened"})

    s1 = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT, ASSET, "2026-10-17T01:05:00Z", 1,
                          hashlib.sha256(S.canon(s0)).hexdigest(), SECRET)
    s2 = S.make_statement(RECEIPT, "opens_to_settlement", PAYER, AGENT2, ASSET, "2026-10-17T01:10:00Z", 2,
                          hashlib.sha256(S.canon(s1)).hexdigest(), SECRET)
    log = [s0, s1, s2]
    out.append({"id": "log-intact", "kind": "log", "statements": log, "expect": {"ok": True}, "why": "seq 0..2, each prev = sha256(previous)"})
    tampered = copy.deepcopy(log)
    tampered[1]["result"] = "no_settlement"
    out.append({"id": "log-tampered", "kind": "log", "statements": tampered, "expect": {"ok": False},
                "why": "a past statement edited after the fact breaks its own signature and the next prev"})
    untrusted = S.make_statement(RECEIPT, "opens_to_settlement", RATER_OTHER, AGENT, ASSET, T0, 0, S.ZERO, OTHER)
    out.append({"id": "pairs", "kind": "count", "statements": log + [untrusted], "trusted": [s0["verifier"]],
                "expect": {"pairs": sorted([[PAYER.lower(), AGENT], [PAYER.lower(), AGENT2]])},
                "why": "three ratings by one rater over two agents count as 2 (rater, agent) pairs; a statement from an unnamed verifier counts as none"})
    return {"name": S.TYPE, "license": "CC0-1.0", "verifier_test_key": s0["verifier"], "chain": CHAIN, "vectors": out}


if __name__ == "__main__":
    with open(os.path.join(HERE, "vectors.json"), "w") as f:
        json.dump(vectors(), f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote vectors.json")
