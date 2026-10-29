"""A check result pinned to a block: the receipt-to-settlement check as a record a later reader can date.

    python3 check_result.py RECEIPT.json [--disclose]      -> prints the unsigned check-result content (JSON)

Asked for by Michael Blake (Everyday AI) for payment-measurement methodology: a later reader must be able to tell "matched at
block N" from "never checked", and a check that could not run must say so instead of reading as "no match".

The check is the one `receipt_check.py --live` runs (section 5.6.4 of x402#3827), with every chain read pinned to ONE block:

  1. read the chain head N (and its hash) first;
  2. pull every AuthorizationUsed(payer, *) log on the asset from block 0 to N (never "latest");
  3. find the one nonce the commitment opens to (`link`);
  4. read authorizationState(payer, nonce) at block N.

The record states the block and the result: `linked`, `no_match`, `incomplete` (a read failed or was rate-limited: never a
`no_match`), or the receipt-level results `not_attempted` / `malformed` / `inconsistent`. Without `--disclose` the record
names the commitment, not the nonce or the settlement: the link stays private until the holder chooses to show it, exactly as
the receipt field intends. With `--disclose` it adds both (for receipts whose salt is already public).

The content is signed as a NIP-01 event (kind 30078, BIP-340) under the checker's published key; `verify_check_result.py`
checks the signature and, with `--recheck`, re-runs the check up to the stated block. Standard library only.
"""
import hashlib
import json
import sys
import time
import urllib.request

import receipt_check as rc

RPC = "https://sepolia.base.org"
LOGS = "https://base-sepolia.blockscout.com/api"
CHAIN = "eip155:84532"
AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"  # AuthorizationUsed(address,bytes32)
AUTH_STATE = "0xe94a0102"  # authorizationState(address,bytes32)
UA = {"user-agent": "x402-rac-check-result/0", "content-type": "application/json"}
TYPE, VERSION = "x402-receipt-check-result", "0"


def canonical(obj) -> str:
    """JCS (RFC 8785) for the value types used here (strings, integers, booleans, null, lists, objects; no floats)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _get(url):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30))


def _rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    out = json.load(urllib.request.urlopen(urllib.request.Request(RPC, body, UA), timeout=30))
    if "error" in out:
        raise RuntimeError(out["error"].get("message", "rpc error"))
    return out["result"]


def candidates_to(asset: str, payer: str, block: int):
    """Every AuthorizationUsed(payer, *) on the asset up to `block`, as [{"nonce", "tx", "block"}], or None if unobtainable."""
    t1 = "0x" + "0" * 24 + payer[2:].lower()
    try:
        resp = _get(f"{LOGS}?module=logs&action=getLogs&fromBlock=0&toBlock={block}&address={asset}"
                    f"&topic0={AUTH_USED}&topic1={t1}&topic0_1_opr=and")
    except Exception:
        return None
    if resp.get("status") == "1" and isinstance(resp.get("result"), list):
        logs = resp["result"]
    elif resp.get("status") == "0" and resp.get("message") == "No logs found":
        logs = []
    else:
        return None
    return [{"nonce": l["topics"][2], "tx": l["transactionHash"], "block": int(l["blockNumber"], 16)} for l in logs]


def run(held: dict, disclose: bool = False, at_block: int = None) -> dict:
    """The check-result content for one held receipt ({receipt, authorizationSalt, asset}). `at_block` re-runs at a stated block."""
    r = held["receipt"]
    p = r["payload"]
    raw = bytes.fromhex(r["signature"][2:])
    sig = (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64] - 27 if raw[64] >= 27 else raw[64])
    signer = rc.recover_address(rc.eip712_digest(p, p["version"]), *sig) if p.get("version") in rc.RECEIPT_FIELDS else None
    rec = rc.check_receipt(r, {"eip712": [signer] if signer else []})
    out = {"type": TYPE, "version": VERSION, "chain": CHAIN, "asset": (held.get("asset") or "").lower(),
           "authorizer": (p.get("payer") or "").lower(), "receipt_sha256": hashlib.sha256(canonical(r).encode()).hexdigest(),
           "receipt_signer": signer, "receipt": rec["receipt"],
           "authorizationCommitment": (p.get("authorizationCommitment") or "").lower(),
           "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if rec["receipt"] != "valid":
        out.update(result="not_attempted", detail="receipt_" + rec["receipt"]); return out
    try:
        n = at_block if at_block is not None else int(_rpc("eth_blockNumber", []), 16)
        blk = _rpc("eth_getBlockByNumber", [hex(n), False])
        out["read_at"] = {"block_number": n, "block_hash": blk["hash"]}
    except Exception as e:
        out.update(result="incomplete", detail=f"chain_head_unobtainable ({type(e).__name__})"); return out
    cands = candidates_to(out["asset"], out["authorizer"], n)
    out["candidates"] = None if cands is None else len(cands)
    lk = rc.link(p, held.get("authorizationSalt"), held.get("asset"), cands)
    out["result"] = lk["result"]
    if "detail" in lk:
        out["detail"] = lk["detail"]
    if lk["result"] in ("linked", "inconsistent"):
        nonce = lk["nonce"]
        t1 = "0x" + "0" * 24 + out["authorizer"][2:]
        try:
            st = _rpc("eth_call", [{"to": out["asset"], "data": AUTH_STATE + t1[2:] + nonce[2:]}, hex(n)])
            out["authorizationState"] = int(st, 16) == 1
        except Exception as e:
            out["authorizationState"] = None
            out.update(result="incomplete", detail=f"authorization_state_unobtainable_at_block ({type(e).__name__})")
        if disclose:
            out["nonce"], out["settlement_tx"] = nonce, lk["transaction"]
    return out


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(__doc__); return 2
    held = json.load(open(a[0], encoding="utf-8"))
    out = run(held, disclose="--disclose" in a)
    print(canonical(out))
    return {"linked": 0, "no_match": 1}.get(out["result"], 2)


if __name__ == "__main__":
    sys.exit(main())
