"""Holder-side check against the live chain, not the snapshot.

    python3 check_live.py <commitment> <salt> [asset] [authorizer]

Defaults to Base Sepolia USDC and the payer in candidates_snapshot.json. Pulls every AuthorizationUsed(authorizer, *)
log (Blockscout, one query), finds the one nonce the commitment opens to, then confirms authorizationState(authorizer,
nonce) == true on the token over plain JSON-RPC. No keys, no dependencies beyond the standard library.

Exit 0 = linked, 1 = does not link (the candidate set was obtained and nothing matched), 2 = INCOMPLETE CHECK (the
candidate set or the state could not be obtained: a failed or rate-limited query is never read as "does not link";
x402#3827 sec 5.6.4, from holistis's live-emitter run).
"""
import json
import sys
import urllib.request

from commitment import link

RPC = "https://sepolia.base.org"
LOGS = "https://base-sepolia.blockscout.com/api"
AUTH_USED = "0x98de503528ee59b575ef0c0a2576a82497bfc029a5685b209e9ec333479b10a5"  # AuthorizationUsed(address,bytes32)
AUTH_STATE = "0xe94a0102"  # authorizationState(address,bytes32)
UA = {"user-agent": "x402-rac-check/0", "content-type": "application/json"}


def _get(url):
    return json.load(urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30))


def _rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    return json.load(urllib.request.urlopen(urllib.request.Request(RPC, body, UA), timeout=30))["result"]


def main():
    commitment, salt = sys.argv[1], sys.argv[2]
    asset = sys.argv[3] if len(sys.argv) > 3 else "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
    payer = sys.argv[4] if len(sys.argv) > 4 else "0x87f344b6ec48a936373d774d3de8649deeb66ee1"
    t1 = "0x" + "0" * 24 + payer[2:].lower()
    try:
        resp = _get(f"{LOGS}?module=logs&action=getLogs&fromBlock=0&toBlock=latest&address={asset}"
                    f"&topic0={AUTH_USED}&topic1={t1}&topic0_1_opr=and")
    except Exception as e:  # network error, HTTP error, bad JSON
        print(f"INCOMPLETE CHECK: candidate set unavailable ({type(e).__name__}: {e})")
        sys.exit(2)
    if resp.get("status") == "1" and isinstance(resp.get("result"), list):
        logs = resp["result"]
    elif resp.get("status") == "0" and resp.get("message") == "No logs found":
        logs = []                       # a real, empty candidate set
    else:                               # rate limit or any other error reported in-band
        print(f"INCOMPLETE CHECK: candidate set unavailable ({resp.get('message')!r})")
        sys.exit(2)
    nonces = {l["topics"][2]: l["transactionHash"] for l in logs}
    print(f"{len(nonces)} nonces consumed by {payer} on {asset}")
    r = link(commitment, salt, "eip3009", asset, payer, list(nonces))
    if r["result"] != "linked":
        print(r)
        sys.exit(1)
    n = r["nonce"]
    try:
        state = _rpc("eth_call", [{"to": asset, "data": AUTH_STATE + t1[2:] + n[2:]}, "latest"])
    except Exception as e:
        print(f"linked: nonce {n} (settlement tx {nonces[n]}), but INCOMPLETE CHECK: authorizationState unavailable ({e})")
        sys.exit(2)
    used = int(state, 16) == 1
    print(f"linked: nonce {n}\n  settlement tx {nonces[n]}\n  authorizationState = {used}")
    sys.exit(0 if used else 1)


if __name__ == "__main__":
    main()
