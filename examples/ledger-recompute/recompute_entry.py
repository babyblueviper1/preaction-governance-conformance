#!/usr/bin/env python3
"""recompute_entry — the per-entry "this ledger entry re-derives to sound" recipe.

Recompute-kit leg. Given a captured /ledger entry vector (the RAW signed Nostr event a public
relay served, plus the entry's ledger metadata), this re-derives whether the entry is *sound*
ENTIRELY from the bytes — no network, no pip install, nothing trusted but code you can read and
the published key you can pin yourself.

A per-entry verdict is **sound** iff all four hold, each recomputed here:

  (a) id_integrity      nostr_event_id(event) == event.id == ledger.event_id
                        (the event bytes are internally consistent and are the id the ledger claims)
  (b) signature_valid   BIP-340 schnorr over the recomputed id verifies against event.pubkey,
                        AND event.pubkey == the PUBLISHED verifier key
                        (invinoveritas issued it, untampered — checkable without trusting us)
  (c) artifact_binding  content parses and carries {artifact_hash, verdict, verifier_pubkey},
                        and content.verifier_pubkey == event.pubkey == published key
                        (the verdict binds to a specific artifact and is self-describing)
  (d) commitment_anchor ledger.commitment_proof.ots_anchor.digest == the recomputed event id
                        (the Bitcoin-PoW OpenTimestamps anchor stamps THIS id — the
                         committed-before-outcome leg; full `ots verify` is the binary/online step)

This is the FIRST LEG of the per-entry "ledger entry re-derives to sound" composite, and the unit
the ERC-8275 reputation axis aggregates: reputation is recomputable, not stored, ONLY because every
entry independently re-derives to sound from public bytes (see README — 8275 reading). Outcome
settlement is a separate, later leg.

Crypto is the audited pure-stdlib code in invinoveritas_verify.py (vendored verbatim — diff it
against `pip install invinoveritas-verify`). Zero dependencies, offline, byte-stable.

Usage:
    python recompute_entry.py            # human-readable, exit 0 iff all sound + tamper rejected
    python recompute_entry.py --json     # machine-readable
"""
from __future__ import annotations

import copy
import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from invinoveritas_verify import nostr_event_id, schnorr_verify, PUBLISHED_PUBKEY  # noqa: E402

VECTORS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")


def assess(vec: dict, expected_pubkey: str = PUBLISHED_PUBKEY) -> dict:
    """Re-derive soundness for one entry vector. Returns the four checks + sound bool."""
    ev = vec["event"]
    meta = vec.get("ledger_meta", {})
    checks: dict = {}

    # (a) id integrity — recompute the NIP-01 id from the bytes; must match both the event's own
    #     claimed id and the id the ledger published.
    recomputed_id = nostr_event_id(ev)
    checks["id_integrity"] = (
        recomputed_id == str(ev.get("id", "")).lower()
        and recomputed_id == str(meta.get("event_id", "")).lower()
    )

    # (b) signature valid against the PUBLISHED key (independence: pin the key yourself).
    sig_ok = False
    try:
        sig_ok = schnorr_verify(
            bytes.fromhex(recomputed_id), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"])
        )
    except Exception:
        sig_ok = False
    checks["signature_valid"] = bool(sig_ok) and ev.get("pubkey", "").lower() == expected_pubkey.lower()

    # (c) content binding — the entry's content is self-consistent and bound. The ledger carries
    #     two content schemas, both legitimately bindable; recompute the right one:
    #       - verdict_proof.v1 ({artifact_hash, verdict, verifier_pubkey, ...}): the verdict binds
    #         to a specific artifact and is self-describing (verifier_pubkey == signer == published).
    #       - ledger record post ({record, record_sha256}): the post commits to its record via
    #         record_sha256 == sha256(json compact, sorted keys) — recompute it from the record.
    binding_ok = False
    content_kind = "unknown"
    try:
        content = json.loads(ev["content"])
        if "artifact_hash" in content:
            content_kind = "verdict_proof"
            binding_ok = (
                isinstance(content.get("artifact_hash"), str)
                and len(content["artifact_hash"]) == 64
                and isinstance(content.get("verdict"), str)
                and content.get("verifier_pubkey", "").lower() == ev.get("pubkey", "").lower()
                and ev.get("pubkey", "").lower() == expected_pubkey.lower()
            )
        elif "record_sha256" in content:
            content_kind = "ledger_record"
            recomputed = hashlib.sha256(
                json.dumps(content["record"], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            binding_ok = recomputed == str(content.get("record_sha256", "")).lower()
    except Exception:
        binding_ok = False
    checks["content_binding"] = binding_ok

    # (d) commitment anchor — the OTS digest stamps THIS recomputed id.
    ots = (meta.get("commitment_proof") or {}).get("ots_anchor") or {}
    checks["commitment_anchor"] = str(ots.get("digest", "")).lower() == recomputed_id

    sound = all(checks.values())
    return {
        "ledger_entry": vec.get("ledger_entry"),
        "recomputed_event_id": recomputed_id,
        "content_kind": content_kind,
        "checks": checks,
        "sound": sound,
    }


def main() -> int:
    as_json = "--json" in sys.argv
    files = sorted(glob.glob(os.path.join(VECTORS_DIR, "entry_*.json")))
    if not files:
        print("no vectors found", file=sys.stderr)
        return 2

    results = []
    for f in files:
        results.append(assess(json.load(open(f, encoding="utf-8"))))

    all_sound = all(r["sound"] for r in results)

    # Negative control: tamper one byte of the first vector's content and require it to FAIL.
    # This makes "green by assertion" impossible — the recipe demonstrably rejects a tampered entry.
    tampered = copy.deepcopy(json.load(open(files[0], encoding="utf-8")))
    tampered["event"]["content"] = tampered["event"]["content"].replace("a", "b", 1)
    tamper_assess = assess(tampered)
    tamper_rejected = not tamper_assess["sound"]

    overall = all_sound and tamper_rejected

    if as_json:
        print(json.dumps(
            {"entries": results, "all_sound": all_sound,
             "tamper_negative_rejected": tamper_rejected, "overall_pass": overall},
            indent=2))
    else:
        print("recompute_entry — per-entry 're-derives to sound' (offline, zero-dep)\n")
        print(f"  published verifier key: {PUBLISHED_PUBKEY}\n")
        for r in results:
            mark = "SOUND " if r["sound"] else "UNSOUND"
            print(f"  [{mark}] entry {r['ledger_entry']:>2}  ({r['content_kind']})  id={r['recomputed_event_id'][:16]}…")
            for k, v in r["checks"].items():
                print(f"           {'ok ' if v else 'FAIL'}  {k}")
        print(f"\n  negative control (tampered entry must be rejected): "
              f"{'ok — rejected' if tamper_rejected else 'FAIL — accepted a tampered entry!'}")
        print(f"\n  => {'PASS' if overall else 'FAIL'}  "
              f"({sum(r['sound'] for r in results)}/{len(results)} sound, tamper {'rejected' if tamper_rejected else 'ACCEPTED'})")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
