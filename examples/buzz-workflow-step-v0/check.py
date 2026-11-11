#!/usr/bin/env python3
"""check.py -- offline check for a Buzz workflow step (block/buzz#4179 fixture, v0).

Order matters (StevenMih, buzz#4179): verify the signed approval and bind it to the exact proposed release BEFORE reading anything else.
  1. approval event: NIP-01 id recomputes, BIP-340 signature verifies (approver key = the event's pubkey; a real gate pins it);
  2. the approval names THIS release: its approves_release_sha256 == sha256(proposed release canonical bytes);
  3. our receipt: id + BIP-340 signature verify, signer == the pinned checker key;
  4. our receipt is bound to exactly that approval and that release: its signed artifact_hash == sha256(canonical {approval_event_id, release_sha256}).
Prints RELEASE (all hold and our verdict is approve) or HOLD with the first failing check.
usage: python3 check.py positive.json negative_release_not_approved.json      (stdlib + the repo's vendored _bip340_nostr.py)"""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _bip340_nostr import nostr_event_id, schnorr_verify

CHECKER_PUBKEY = "6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7"
sha = lambda s: hashlib.sha256(s.encode()).hexdigest()
canon = lambda o: json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def authentic(ev):
    return nostr_event_id(ev) == ev["id"] and schnorr_verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"]))


def check(fx):
    ap = fx["approval_event"]; rel_sha = sha(fx["proposed_release_canonical"])
    if not authentic(ap):
        return "HOLD", "approval event signature/id invalid"
    if json.loads(ap["content"]).get("approves_release_sha256") != rel_sha:
        return "HOLD", "approval does not name this release (approves a different digest)"
    rc = fx["receipt"]["event"]
    if not authentic(rc) or rc["pubkey"] != CHECKER_PUBKEY:
        return "HOLD", "checker receipt invalid or not signed by the pinned key"
    pl = json.loads(rc["content"])
    if pl.get("artifact_hash") != sha(canon({"approval_event_id": ap["id"], "release_sha256": rel_sha})):
        return "HOLD", "receipt not bound to this approval + release"
    return ("RELEASE" if pl.get("verdict") == "approve" else "HOLD"), f"checker verdict={pl.get('verdict')}"


if __name__ == "__main__":
    for p in sys.argv[1:]:
        d, why = check(json.load(open(p)))
        print(f"{Path(p).name}: {d}  ({why})")
