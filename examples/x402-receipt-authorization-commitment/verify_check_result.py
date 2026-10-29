"""Verify a signed x402 receipt check result, and optionally re-run it up to the block it names.

    python3 verify_check_result.py RESULT.event.json [--issuer PUBKEY] [--recheck HELD_RECEIPT.json]

1. The event: NIP-01 id = sha256 of [0, pubkey, created_at, kind, tags, content] (compact JSON), BIP-340 signature over the id
   (bip340.py, standard library), pubkey equal to --issuer (default: invinoveritas's published proof key).
2. The content: type x402-receipt-check-result, version 0, and what it states -- the block it was read against, the result
   (linked / no_match / incomplete / not_attempted / malformed / inconsistent) and, if disclosed, the nonce and settlement.
3. --recheck: re-runs the same check from the held receipt (receipt + salt + asset), with the log query pinned to the SAME block
   (logs are immutable, so the candidate set up to block N is reproducible later). The public RPC keeps no old state, so the
   authorization state is read at the stated block when the node can, and otherwise at the latest block: once an EIP-3009
   authorization is used it stays used, so "used now" plus a consuming log at or before block N confirms "used at block N".
   Exit 0 = signature valid (and, with --recheck, the re-run agrees); 1 = invalid or disagrees.
"""
import hashlib
import json
import sys

import bip340
import check_result as cr

OUR_KEY = "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7"


def event_id(ev: dict) -> str:
    ser = json.dumps([0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]], separators=(",", ":"),
                     ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()


def verify_event(ev: dict, issuer: str) -> list:
    errs = []
    if event_id(ev) != ev.get("id"):
        errs.append("event_id_mismatch")
    try:
        ok = bip340.verify(bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["id"]), bytes.fromhex(ev["sig"]))
    except Exception:
        ok = False
    if not ok:
        errs.append("signature_invalid")
    if ev.get("pubkey") != issuer:
        errs.append("not_the_stated_issuer")
    try:
        c = json.loads(ev["content"])
        if c.get("type") != cr.TYPE or c.get("version") != cr.VERSION:
            errs.append("not_a_check_result")
    except ValueError:
        errs.append("content_not_json")
    return errs


def main() -> int:
    a = sys.argv[1:]
    if not a:
        print(__doc__); return 2
    ev = json.load(open(a[0], encoding="utf-8"))
    issuer = a[a.index("--issuer") + 1] if "--issuer" in a else OUR_KEY
    errs = verify_event(ev, issuer)
    if errs:
        print("INVALID:", ", ".join(errs)); return 1
    c = json.loads(ev["content"])
    at = c.get("read_at") or {}
    print(f"signature valid (issuer {issuer[:8]}...{issuer[-4:]}); result {c['result']!r} read at block "
          f"{at.get('block_number')} ({(at.get('block_hash') or '')[:12]}...), checked_at {c.get('checked_at')}"
          + (f"; settlement {c['settlement_tx']}" if c.get("settlement_tx") else ""))
    if "--recheck" not in a:
        return 0
    held = json.load(open(a[a.index("--recheck") + 1], encoding="utf-8"))
    if at.get("block_number") is None:
        print("recheck: the result names no block (it was incomplete before reading the chain); nothing to reproduce")
        return 0
    again = cr.run(held, disclose="nonce" in c, at_block=at["block_number"])
    if again.get("detail", "").startswith("authorization_state_unobtainable_at_block"):
        # no old state on this node: read the state now (monotone once used) and keep the pinned candidate set
        n = again.get("nonce") or cr.rc.link(held["receipt"]["payload"], held.get("authorizationSalt"), held.get("asset"),
                                             cr.candidates_to(c["asset"], c["authorizer"], at["block_number"])).get("nonce")
        t1 = "0x" + "0" * 24 + c["authorizer"][2:]
        st = cr._rpc("eth_call", [{"to": c["asset"], "data": cr.AUTH_STATE + t1[2:] + n[2:]}, "latest"])
        again.update(result="linked", authorizationState=int(st, 16) == 1)
        again.pop("detail", None)
        print("recheck: state read at latest (this node keeps no state at the stated block; EIP-3009 authorizations stay used)")
    keys = ["result", "candidates", "receipt_sha256", "authorizationCommitment"] + (["nonce", "settlement_tx"] if "nonce" in c else [])
    diff = [k for k in keys if again.get(k) != c.get(k)]
    if (again.get("read_at") or {}).get("block_hash") != at.get("block_hash"):
        diff.append("block_hash")
    if diff:
        print("recheck DISAGREES on:", ", ".join(diff)); return 1
    print(f"recheck agrees at block {at['block_number']}: {again['result']}, {again.get('candidates')} candidates"
          + (f", authorizationState {again.get('authorizationState')}" if "authorizationState" in again else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
