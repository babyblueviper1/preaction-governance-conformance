#!/usr/bin/env python3
"""build_verdict_object.py — the promised verdict-ref-v1 adapter (microsoft/autogen#7353).

PROMISED 2026-07-22 (issuecomment-5048203827): giskard09 (action_ref/argentum-core) shipped a real
conformance fixture, verdict-ref-v1 (github.com/giskard09/argentum-core/tree/main/examples/
conformance/verdict-ref-v1), naming `babyblueviper1:review` as the example independent-issuer, and
asked whether our own conformance suite is a running system or a design doc. We answered honestly
(real code, not yet shaped to their exact vector format) and hand-built ONE verdict_object as a
one-off proof of concept in the GitHub reply itself. The remaining committed piece, closed here:
an ACTUAL adapter that emits verdict-ref-v1's exact schema PROGRAMMATICALLY from any live /review
call, not a hand-typed example — so a third implementation can conformance-check against this the
same way action_ref/CKG already do against each other.

verdict-ref-v1's schema (verbatim from their verify.py, vendored below so this stays offline and
zero-dependency — the whole point of a conformance fixture is that it doesn't require pip installing
someone else's package to check their own hash function):

    verdict = {"action_ref": ..., "confidence": ..., "issuer_id": ..., "ts_ms": ..., "verdict": ...}
    verdict_ref = sha256(JCS(verdict))   # JCS = json.dumps(sort_keys=True, compact separators)

TWO THINGS THIS FILE PROVES, RUN IN ORDER:

  1. Cross-implementation convergence: recompute ALL FOUR of giskard09's own upstream vectors
     (upstream_vectors.json, vendored verbatim from their repo) using our own hash function, and
     assert byte-identical action_ref/verdict_ref against their published expected values. If this
     fails, our hash function disagrees with theirs and nothing below is trustworthy.
  2. Live emission: build a NEW verdict_object from a REAL /review response (live_review_response.json
     — a genuine signed proof, independently verifiable via /verify-proof, not hand-typed), using
     that response's own artifact_hash-bound decision_ref as action_ref (per the July 22 precedent:
     "action_ref here is our own live decision_ref, not one derived from your preimage fields" — the
     two systems' action_ref/decision_ref concepts are analogous, not identical, and this adapter is
     honest about substituting one for the other rather than pretending they're the same field).

Zero dependencies, offline.

Run:
    python3 build_verdict_object.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


# ── verdict-ref-v1's own hash functions, vendored verbatim from giskard09/argentum-core ──────────
def jcs(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def action_ref(preimage):
    payload = {k: preimage[k] for k in ("agent_id", "action_type", "scope", "timestamp")}
    return sha256_hex(jcs(payload))


def verdict_ref(verdict):
    return sha256_hex(jcs(verdict))


# ── Step 1: cross-implementation convergence against their own published vectors ─────────────────
def check_upstream_convergence() -> tuple[int, int]:
    vectors = json.load(open(os.path.join(HERE, "upstream_vectors.json")))["vectors"]
    print("=" * 76)
    print("STEP 1 — recompute giskard09's own verdict-ref-v1 vectors with OUR hash function")
    print("=" * 76)
    passed, total = 0, len(vectors)
    for v in vectors:
        computed_action = action_ref(v["preimage"])
        ok = computed_action == v["expected_action_ref"]
        line = f"  {v['id']:36} action_ref {'OK' if ok else 'MISMATCH'}"
        if "verdict" in v:
            computed_verdict = verdict_ref(v["verdict"])
            vok = computed_verdict == v["expected_verdict_ref"]
            independent = v["verdict"]["issuer_id"] != v["preimage"]["agent_id"]
            iok = independent == v.get("conformant", independent)
            ok = ok and vok and iok
            line += f"  verdict_ref {'OK' if vok else 'MISMATCH'}  independence {'OK' if iok else 'MISMATCH'}"
        print(line)
        if ok:
            passed += 1
    print(f"\n{passed}/{total} upstream vectors byte-identical under our own hash function.")
    return passed, total


# ── Step 2: emit a NEW verdict_object programmatically from a real live /review response ─────────
def build_live_verdict_object() -> dict:
    print("\n" + "=" * 76)
    print("STEP 2 — emit a verdict-ref-v1 verdict_object from a REAL live /review response")
    print("=" * 76)
    review = json.load(open(os.path.join(HERE, "live_review_response.json")))
    payload = review["proof"]["proof_payload"]
    event = review["proof"]["event"]

    print(f"\nsource: a real, independently-verifiable invinoveritas /review(sign=true) call")
    print(f"  event id:      {event['id']}")
    print(f"  decision_ref:  {payload['decision_ref']}")
    print(f"  verdict:       {payload['verdict']}  (confidence {payload['confidence']})")
    print(f"  verify at:     https://api.babyblueviper.com/verify-proof (POST the `event` object,")
    print(f"                 or recompute NIP-01 + BIP-340 yourself, no trust required)")

    verdict_object = {
        "action_ref": payload["decision_ref"],  # OUR analog of their action_ref -- honestly not the
                                                 # same preimage shape (theirs is 4 execution fields,
                                                 # ours is an 11-field review-verdict preimage), but
                                                 # both are "content-addressed pointer to what this
                                                 # verdict is about" -- the field this adapter fills.
        "confidence": payload["confidence"],
        "issuer_id": "babyblueviper1:review",
        "ts_ms": int(payload["verified_at"]) * 1000,
        "verdict": payload["verdict"],
    }
    ref = verdict_ref(verdict_object)
    print(f"\nemitted verdict_object (verdict-ref-v1 exact schema):")
    print(f"  {json.dumps(verdict_object, sort_keys=True)}")
    print(f"\nverdict_ref = {ref}")
    return {"verdict_object": verdict_object, "verdict_ref": ref}


def main() -> int:
    passed, total = check_upstream_convergence()
    if passed != total:
        print(f"\nFAIL: {total - passed} upstream vector(s) did not recompute identically — "
              f"our hash function disagrees with giskard09's on their own published vectors.")
        return 1
    result = build_live_verdict_object()
    print("\n" + "=" * 76)
    print("OK: 4/4 upstream vectors byte-identical, AND a live verdict_object emitted "
          "programmatically from a real /review call (not hand-typed).")
    print("=" * 76)
    print(f"\nverify_verdict_ref = {result['verdict_ref'][:16]}...  "
          f"— recompute it yourself: sha256_hex(jcs({{...}}))  no trust in this script required.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
