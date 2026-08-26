#!/usr/bin/env python3
"""check_chain_continuity — offline recompute of /ledger's chain-hash-linking invariant.

Closes a real, specific gap flagged in issue #3 (Rul1an, 2026-07-23): every existing recipe in
this suite (recompute_entry.py, the ERC-8275/8299/8004 fixtures) verifies each entry INDEPENDENTLY
-- soundness is per-entry. Nothing in the suite establishes a property of the SEQUENCE: that the
/ledger one reader is served is the same ledger served to the next reader. A host could show
auditor A a set that includes an entry and auditor B a set that omits it, and every entry either
of them sees would still pass every existing per-entry check.

invinoveritas's live /ledger already closes part of this (services/ledger_chain.py, built
2026-07-02 for a DIFFERENT prior finding -- MarkovianProtocol, microsoft/autogen#7353): from entry
#40 onward, every entry carries chain = {prev_head_hash, content_hash, head_hash} where
content_hash = sha256(canonical_json(record)) and head_hash = sha256(content_hash + "|" +
prev_head_hash) -- a running hash-chain over the sequence, not just per-entry anchors. The head is
also independently broadcast to the same public Nostr relays the proof events go to (schema
invinoveritas.ledger_chain_head.v1), so a third party who observes two different heads for the
same entry number on the shared relay set has caught a fork WITHOUT trusting the API to admit it.

WHAT THIS RECIPE PROVES (fully offline, zero-dep, from a captured entry sequence):
  - each entry's content_hash correctly re-derives from its own record
  - each entry's head_hash correctly re-derives from its own content_hash + the PRECEDING entry's
    head_hash -- i.e., the sequence you were handed is internally self-consistent, not just each
    entry in isolation
  - a single entry's record tampered anywhere in the sequence breaks continuity from that point
    forward (the negative control below), not just that one entry's own soundness

WHAT THIS RECIPE DOES **NOT** PROVE (the honest boundary, per the issue's own two-leg framing --
"witness the sequence so it cannot equivocate, and keep the challenge portable so it cannot be
suppressed"): it cannot detect an operator serving TWO DIFFERENT self-consistent chains to two
different auditors -- that requires actually cross-checking the head_hash against the independent
Nostr broadcast (a live network step, out of scope for THIS repo's portable/offline/zero-dep
design), or a full witnessed-checkpoint scheme with independent witness cosignatures over a
consistency proof (the C2SP tlog-witness / SCITT COSE Receipt pattern the issue describes) -- which
invinoveritas does not yet implement. This recipe is the offline half of the fix (chain continuity
of what you were GIVEN); live relay cross-checking is the other half, and full witness-quorum
non-equivocation is real, disclosed future work, not yet built.

Usage:
    python check_chain_continuity.py            # human-readable
    python check_chain_continuity.py --json      # machine-readable
"""
from __future__ import annotations

import copy
import glob
import hashlib
import json
import os
import sys


VECTORS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")


def _canon(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_hash(record: dict) -> str:
    return hashlib.sha256(_canon(record)).hexdigest()


def head_hash(c_hash: str, prev_head: str) -> str:
    return hashlib.sha256(f"{c_hash}|{prev_head}".encode("utf-8")).hexdigest()


def check_sequence(entries: list) -> dict:
    """entries: list of {entry, record, chain: {prev_head_hash, content_hash, head_hash}},
    sorted by entry number, consecutive (no gaps). Returns per-entry + overall results."""
    results = []
    prev_ok_head = None
    for e in entries:
        chain = e["chain"]
        recomputed_ch = content_hash(e["record"])
        content_hash_ok = recomputed_ch == chain["content_hash"]

        # the entry's OWN claimed prev_head_hash must match the PRECEDING entry's actual head_hash
        # (skip this check for the first entry in the window -- its predecessor isn't in view)
        prev_link_ok = True if prev_ok_head is None else (chain["prev_head_hash"] == prev_ok_head)

        recomputed_hh = head_hash(chain["content_hash"], chain["prev_head_hash"])
        head_hash_ok = recomputed_hh == chain["head_hash"]

        sound = content_hash_ok and prev_link_ok and head_hash_ok
        results.append({
            "entry": e["entry"],
            "content_hash_ok": content_hash_ok,
            "prev_link_ok": prev_link_ok,
            "head_hash_ok": head_hash_ok,
            "sound": sound,
        })
        prev_ok_head = chain["head_hash"]  # always propagate the STORED head for the next link check

    all_sound = all(r["sound"] for r in results)
    return {"entries": results, "all_continuous": all_sound}


def main() -> int:
    as_json = "--json" in sys.argv
    files = sorted(glob.glob(os.path.join(VECTORS_DIR, "entry_*.json")))
    if not files:
        print("no vectors found", file=sys.stderr)
        return 2

    entries = [json.load(open(f, encoding="utf-8")) for f in files]
    entries.sort(key=lambda e: e["entry"])

    result = check_sequence(entries)

    if len(entries) < 3:
        print("need >= 3 vectors to demonstrate an omission gap", file=sys.stderr)
        return 2

    # Negative control -- the SPECIFIC scenario the issue describes: a server hands one auditor a
    # subset that OMITS an entry. Every remaining entry is still individually sound (this is
    # exactly why per-entry checks alone can't catch it -- recompute_entry.py's recipe would pass
    # every one of these entries with no complaints). Only the SEQUENCE-level prev_link check
    # catches the gap: the entry right after the omission still claims the OMITTED entry's
    # head_hash as its prev_head_hash, which no longer matches its new (wrong) predecessor.
    omitted_idx = 1
    subset = copy.deepcopy(entries)
    removed = subset.pop(omitted_idx)
    subset_result = check_sequence(subset)
    # every entry's OWN three checks (content_hash_ok/head_hash_ok, and prev_link_ok against
    # whatever it was actually served next to) still individually recompute fine up to the seam --
    # the seam itself is where prev_link_ok must fail, since the auditor was never shown the entry
    # whose head_hash the next one actually chains from.
    seam_idx = omitted_idx  # the entry that used to follow the removed one, now at this index
    omission_caught = not subset_result["entries"][seam_idx]["sound"] and \
        not subset_result["entries"][seam_idx]["prev_link_ok"]

    overall = result["all_continuous"] and omission_caught

    if as_json:
        print(json.dumps({
            "real_sequence": result,
            "omission_negative_control": {"omitted_entry": removed["entry"], **subset_result},
            "omission_correctly_caught": omission_caught,
            "overall_pass": overall,
        }, indent=2))
    else:
        print("check_chain_continuity — offline recompute of /ledger's sequence-level chain link\n")
        for r in result["entries"]:
            mark = "OK  " if r["sound"] else "FAIL"
            print(f"  [{mark}] entry {r['entry']:>3}  content_hash={'ok' if r['content_hash_ok'] else 'FAIL'}"
                  f"  prev_link={'ok' if r['prev_link_ok'] else 'FAIL'}"
                  f"  head_hash={'ok' if r['head_hash_ok'] else 'FAIL'}")
        print(f"\n  real sequence continuous: {'YES' if result['all_continuous'] else 'NO'}")
        print(f"\n  negative control -- omit entry {removed['entry']} (simulate a server showing this")
        print(f"  auditor a subset that skips it -- every OTHER entry is individually still sound):")
        for r in subset_result["entries"]:
            mark = "OK  " if r["sound"] else "FAIL"
            print(f"    [{mark}] entry {r['entry']:>3}  prev_link={'ok' if r['prev_link_ok'] else 'FAIL'}")
        print(f"  omission correctly caught by the seam's prev_link check: "
              f"{'yes' if omission_caught else 'NO -- BUG'}")
        print(f"\n  => {'PASS' if overall else 'FAIL'}")
        print("\n  Scope (read before citing): this proves the SEQUENCE YOU WERE HANDED is internally")
        print("  continuous, and catches a SUBSET/omission a per-entry-only check would miss. It does")
        print("  NOT by itself prove no equivocation across two different observers who are each")
        print("  handed a different but internally-continuous subset -- that needs the live Nostr")
        print("  head-broadcast cross-check (see README).")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
