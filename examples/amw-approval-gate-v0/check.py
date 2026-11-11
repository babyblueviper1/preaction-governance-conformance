#!/usr/bin/env python3
"""check.py -- offline check of a signed invinoveritas verdict for an irreversible tool call (approval-gate fixture, v0).

What an approval gate needs before dispatching an irreversible call, from the bytes alone (no network, no call to us):
  1. the verdict event is authentic: NIP-01 event id recomputes, BIP-340 Schnorr signature verifies;
  2. it was signed by the checker key the gate pins (EXPECTED_PUBKEY below, also published at
     https://api.babyblueviper.com/.well-known/ and in this repo's fixtures/trust_policy.json);
  3. it is bound to THIS exact call: sha256 of the call's canonical bytes == the signed artifact_hash
     (same arguments => same digest => same verdict on a retry);
  4. the decision: approve -> ALLOW, anything else (reject, or any failed check) -> BLOCK.
The digest the gate should write on its receipt is the verdict event id.

usage: python3 check.py approve.json reject.json        (each verdict against the call it was issued for)
       python3 check.py approve.json --call call.json  (a verdict against the call the agent is actually about to make)   (stdlib + the repo's vendored _bip340_nostr.py)"""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _bip340_nostr import nostr_event_id, schnorr_verify

EXPECTED_PUBKEY = "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7"


def check(fixture: dict, call_canonical: str) -> tuple[str, list]:
    ev = fixture["proof"]["event"]; why = []
    if nostr_event_id(ev) != ev["id"]:
        why.append("event id does not recompute")
    if not schnorr_verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])):
        why.append("BIP-340 signature does not verify")
    if ev["pubkey"] != EXPECTED_PUBKEY:
        why.append("signed by a key the gate does not pin")
    payload = json.loads(ev["content"])
    if payload.get("artifact_hash") != hashlib.sha256(call_canonical.encode()).hexdigest():
        why.append("verdict is not bound to this call (artifact_hash mismatch)")
    decision = "ALLOW" if not why and payload.get("verdict") == "approve" else "BLOCK"
    return decision, why or [f"verdict={payload.get('verdict')}"]


if __name__ == "__main__":
    argv = sys.argv[1:]; override = None
    if "--call" in argv:
        i = argv.index("--call"); override = argv[i + 1]; argv = argv[:i] + argv[i + 2:]
    args = argv
    for p in args:
        fx = json.load(open(p))
        call = json.dumps(json.load(open(override)), sort_keys=True, separators=(",", ":"), ensure_ascii=False) if override else fx["artifact_canonical"]
        d, why = check(fx, call)
        print(f"{Path(p).name}: {d}  ({'; '.join(why)})  receipt digest = {fx['proof']['event']['id']}")
