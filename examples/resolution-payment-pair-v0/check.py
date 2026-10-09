#!/usr/bin/env python3
"""Cold checker for resolution-payment-pair-v0. Imports nothing from build.py. Stdlib only.

Claim evaluated per case: "payment P executed under the authority of verdict V". Three edges, each checked from bytes:
  covers    V is a valid signed verdict (NIP-01 id + BIP-340 signature under the expected issuer key, decision_ref recomputes over
            its declared preimage) whose action_binding_args_hash = sha256(JCS(args)), and the receipt shows a successful USDC
            Transfer(args.from -> args.to, args.amount_atomic) authorized by args.from.        Missing: verdict_does_not_cover_payment
  carried   the receipt's AuthorizationUsed nonce equals V's decision_ref, so the authorization could not exist before V.
                                                                                               Missing: payment_does_not_carry_verdict
  policy    the bound args declare which verdicts permit execution (proceed_on), so the rule predates the payment.
                                                                                               Missing: execution_policy_not_committed
Outcome: AUTHORIZED if all three hold and V's verdict is in proceed_on; UNAUTHORIZED if V is carried and the declared policy
excludes V's verdict; otherwise UNRESOLVED with every missing edge named. No receipt at all: UNRESOLVED evidence_unavailable,
a different kind from the missing-edge reasons (more fetching can fix it; nothing fetched can fix a missing edge).

    python3 check.py              offline, against the pinned receipts
    python3 check.py --live       also re-read the two real receipts and their blocks from a public Base RPC first
    python3 check.py --mutants    five wrong checkers; each must be caught by at least one case
"""
import hashlib, json, os, sys, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
sys.path.insert(0, os.path.join(ROOT, "tools")); sys.path.insert(0, ROOT)
from _rfc8785 import jcs                     # noqa: E402
from _bip340_nostr import verify_proof       # noqa: E402

AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"
TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
RPCS = ["https://mainnet.base.org", "https://base.publicnode.com", "https://1rpc.io/base"]
addr = lambda t: "0x" + t[-40:].lower()


def evaluate(case, V, mutant=None):
    rc, args, ev = case["receipt"], case["args"], case["verdict_event"]
    if rc is None:
        return {"outcome": "UNAUTHORIZED", "reasons": ["evidence_unavailable"]} if mutant == "M4_unavailable_is_rejection" \
            else {"outcome": "UNRESOLVED", "reasons": ["evidence_unavailable"]}
    key = V["synthetic_test_pubkey"] if case["class"] == "synthetic" else V["real_issuer_pubkey"]
    proof_ok = mutant == "M3_skip_proof_check" or verify_proof(ev, expect_pubkey=key).get("valid") is True
    try:
        c = json.loads(ev["content"])
    except Exception:
        c = {}
    dref = c.get("decision_ref") or ""
    pre = {k: c.get(k) for k in (c.get("decision_ref_preimage_fields") or [])}
    dref_ok = bool(pre) and dref == "sha256:" + hashlib.sha256(jcs(pre).encode("utf-8")).hexdigest()
    args_ok = mutant == "M5_trust_args_without_hash" or c.get("action_binding_args_hash") == "sha256:" + hashlib.sha256(jcs(args).encode("utf-8")).hexdigest()
    token = str(args.get("token", "")).lower()
    logs = [l for l in rc.get("logs", []) if l["address"].lower() == token]
    auth = [l for l in logs if l["topics"][0].lower() == AUTH_USED and len(l["topics"]) > 2]
    xfer = [l for l in logs if l["topics"][0].lower() == TRANSFER and len(l["topics"]) > 2]
    tx_ok = int(rc.get("status", "0x0"), 16) == 1
    authz_ok = any(addr(l["topics"][1]) == str(args.get("from", "")).lower() for l in auth)
    xfer_ok = any(addr(l["topics"][1]) == str(args.get("from", "")).lower() and addr(l["topics"][2]) == str(args.get("to", "")).lower()
                  and int(l["data"], 16) == int(args.get("amount_atomic", -1)) for l in xfer)
    if not (proof_ok and dref_ok and args_ok and tx_ok and authz_ok and xfer_ok):
        return {"outcome": "UNRESOLVED", "reasons": ["verdict_does_not_cover_payment"]}
    if mutant == "M1_temporal_order_as_binding":
        carried = int(c.get("verified_at", 1 << 62)) <= int(rc["block_timestamp"], 16)
    else:
        carried = dref.startswith("sha256:") and any(l["topics"][2].lower() == "0x" + dref.split(":", 1)[1].lower() for l in auth)
    proceed_on = args.get("proceed_on") if isinstance(args.get("proceed_on"), list) else None
    if mutant == "M2_binding_alone_authorizes":
        proceed_on = proceed_on or [c.get("verdict")]
    if carried and proceed_on is not None and c.get("verdict") not in proceed_on:
        return {"outcome": "UNAUTHORIZED", "reasons": ["executed_on_verdict_outside_policy"]}
    reasons = ([] if carried else ["payment_does_not_carry_verdict"]) + ([] if proceed_on is not None else ["execution_policy_not_committed"])
    return {"outcome": "UNRESOLVED" if reasons else "AUTHORIZED", "reasons": sorted(reasons)}


def rpc(method, params):
    last = None
    for u in RPCS:
        try:
            req = urllib.request.Request(u, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                         headers={"content-type": "application/json", "User-Agent": "resolution-payment-pair-v0"})
            r = json.load(urllib.request.urlopen(req, timeout=20))
            if r.get("result") is not None:
                return r["result"]
        except Exception as e:
            last = e
    raise RuntimeError(f"no RPC answered {method}: {last}")


def live_reread(case):
    rc = rpc("eth_getTransactionReceipt", [case["tx_hash"]])
    blk = rpc("eth_getBlockByNumber", [rc["blockNumber"], False])
    got = {"transactionHash": rc["transactionHash"], "status": rc["status"], "blockNumber": rc["blockNumber"], "blockHash": rc["blockHash"],
           "block_timestamp": blk["timestamp"], "logs": [{"address": l["address"], "topics": l["topics"], "data": l["data"]} for l in rc["logs"]]}
    return got, blk["hash"] == rc["blockHash"]


def main():
    V = json.load(open(os.path.join(HERE, "vectors.json")))
    rc_ = 0
    if "--live" in sys.argv:
        for c in V["cases"]:
            if c["class"] != "real":
                continue
            got, hash_ok = live_reread(c)
            same = got == c["receipt"] and hash_ok
            rc_ |= 0 if same else 1
            print(f"{'ok  ' if same else 'FAIL'} live re-read {c['tx_hash'][:12]}... block {int(got['blockNumber'], 16)}: receipt and block hash equal the pinned fixture")
            c["receipt"] = got
    ok = 0
    for c in V["cases"]:
        got = evaluate(c, V); good = got == c["expect"]; ok += good
        print(f"{'ok  ' if good else 'FAIL'} {c['id']:36s} [{c['class'].split(' ')[0]:9s}] {got['outcome']:12s} {','.join(got['reasons'])}")
    print(f"{ok}/{len(V['cases'])} cases match"); rc_ |= 0 if ok == len(V["cases"]) else 1
    if "--mutants" in sys.argv:
        killed = 0
        for mu in ("M1_temporal_order_as_binding", "M2_binding_alone_authorizes", "M3_skip_proof_check", "M4_unavailable_is_rejection",
                   "M5_trust_args_without_hash"):
            by = [c["id"] for c in V["cases"] if evaluate(c, V, mu) != c["expect"]]
            killed += bool(by); print(f"{'KILLED' if by else 'SURVIVED'} {mu:32s} by {', '.join(by) or '-'}")
        print(f"{killed}/5 mutants killed"); rc_ |= 0 if killed == 5 else 1
    sys.exit(rc_)


if __name__ == "__main__":
    main()
