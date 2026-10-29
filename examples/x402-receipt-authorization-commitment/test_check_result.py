"""Offline tests for check_result.py / verify_check_result.py (no network): python3 test_check_result.py"""
import copy
import json

import check_result as cr
import verify_check_result as v

ok = [0, 0]


def check(name, cond):
    ok[0 if cond else 1] += 1
    print(("PASS " if cond else "FAIL ") + name)


ev = json.load(open("check_results/receipt-live-base-sepolia.result.json"))
check("published result verifies under our key", v.verify_event(ev, v.OUR_KEY) == [])
t = copy.deepcopy(ev); t["content"] = t["content"].replace('"result":"linked"', '"result":"no_match"')
check("content changed after signing -> event_id_mismatch (and the old signature no longer covers it)", "event_id_mismatch" in v.verify_event(t, v.OUR_KEY))
check("another issuer stated -> not_the_stated_issuer", "not_the_stated_issuer" in v.verify_event(ev, "11" * 32))
t = copy.deepcopy(ev); t["sig"] = t["sig"][:-2] + ("00" if t["sig"][-2:] != "00" else "01")
check("signature byte flipped -> signature_invalid", "signature_invalid" in v.verify_event(t, v.OUR_KEY))

held = json.load(open("live_receipts/receipt-live-base-sepolia.json"))
real = (cr._rpc, cr.candidates_to)
cr._rpc = lambda m, p: "0x1" if m == "eth_blockNumber" else ({"hash": "0x" + "ab" * 32} if m == "eth_getBlockByNumber" else "0x1")
cr.candidates_to = lambda asset, payer, block: None          # the log query failed or was rate-limited
out = cr.run(held)
check("candidate set unobtainable -> incomplete with the block named, never no_match",
      out["result"] == "incomplete" and out["read_at"]["block_number"] == 1 and out["candidates"] is None)
cr.candidates_to = lambda asset, payer, block: []           # the query succeeded and returned nothing
check("empty candidate set -> no_match (a finished check)", cr.run(held)["result"] == "no_match")
def boom(m, p):
    raise OSError("rate limited")
cr._rpc = boom
out = cr.run(held)
check("chain head unobtainable -> incomplete, no block claimed", out["result"] == "incomplete" and "read_at" not in out)
pub = json.loads(ev["content"])
cr._rpc = lambda m, p: "0x1" if m in ("eth_blockNumber", "eth_call") else {"hash": "0x" + "ab" * 32}
cr.candidates_to = lambda asset, payer, block: [{"nonce": pub["nonce"], "tx": pub["settlement_tx"], "block": 1}]
hidden, shown = cr.run(held), cr.run(held, disclose=True)
check("linked without --disclose names neither the nonce nor the settlement; with --disclose it names both",
      hidden["result"] == "linked" and "nonce" not in hidden and "settlement_tx" not in hidden
      and shown["nonce"] == pub["nonce"] and shown["settlement_tx"] == pub["settlement_tx"])
cr._rpc, cr.candidates_to = real
print(f"{ok[0]}/{ok[0] + ok[1]} pass")
raise SystemExit(1 if ok[1] else 0)
