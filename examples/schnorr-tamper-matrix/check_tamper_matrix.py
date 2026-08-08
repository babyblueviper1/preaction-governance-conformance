#!/usr/bin/env python3
"""check_tamper_matrix.py — the schnorr/NIP-01 recompute leg of a cross-scheme verdict handshake.

Built jointly with helmymekaoui-web (ethereum-magicians t/29275, "ERC-8370: Inheritable Agent
Mandates"). He built an independent BIP-340/NIP-01 verifier from scratch, self-checked it against
the 19 official BIP-340 test vectors, then ran it cold against two real invinoveritas /ledger
verdicts -- and, to prove the checker actually rejects bad input rather than rubber-stamping,
tampered each verdict four ways and confirmed all four were caught. This is that exact tamper
matrix, reusable, run here against a third real verdict (ledger entry 237, mandate_gate_verdict.json
-- a real signed verdict with `intended_verifier` bound to his own MandateGate contract, Base
Sepolia 0x6882d039e266e5357d82cf3c7215b7639f5c24ea).

THE HONEST SCOPE, STATED PLAINLY (this is the point, not a caveat):
This fixture verifies the SCHNORR/NIP-01 side only -- that the verdict is authentically ours,
untampered, and bound to the declared verifier. It does NOT verify anything about his gate's
ECDSA/secp256k1 side, and does not claim to. The two schemes (schnorr over a sha256(JSON[...])
NIP-01 preimage vs. ECDSA over a keccak/EIP-191 digest) are genuinely different, and an actual
cross-scheme adapter (an off-chain relay that re-presents this event in the shape his gate already
checks, or an on-chain schnorr-via-ecrecover-trick verifier) is real, separate, unbuilt work -- not
something this file quietly papers over by only testing the half that already works. See the
README's "What this does NOT close" section.

Zero dependencies, offline. Crypto is the vendored pure-stdlib BIP-340 reference implementation
(invinoveritas_verify.py, identical to the copy at the repo root -- diff them if you don't trust
that claim).

Run:
    python3 check_tamper_matrix.py            # bundled real verdict (ledger entry 237)
    python3 check_tamper_matrix.py --file x.json
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from invinoveritas_verify import nostr_event_id, schnorr_verify, verify_proof, PUBLISHED_PUBKEY  # noqa: E402

# A second, unrelated real invinoveritas key -- used for the pubkey-swap negative vector. Any
# syntactically valid 32-byte hex works for that specific test (it only needs to NOT be
# PUBLISHED_PUBKEY); this is our OWN actual key from an earlier proof rotation, not a random string,
# so the vector stays "a real key, just the wrong one" rather than "obviously malformed input".
_ALTERNATE_REAL_PUBKEY = "f959e057b99f26ad77e2dcd4be98eafa8c04237b7a49edaeb9b5c5c347c210bc"

VECTORS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FILE = os.path.join(VECTORS_DIR, "mandate_gate_verdict.json")


def _tamper_content(event: dict) -> dict:
    """helmymekaoui-web's vector 1: 'confidence changed in content'. Generalized here to any JSON
    field inside content, since a real verdict's payload shape varies by artifact_type -- the point
    is any semantic change to the signed content, not the specific field name.

    2026-08-08, caught by our own /review on this exact file: the original version's confidence
    mutation (round(1.0 - x, 2)) was a no-op fixed point at x=0.5, and even when it did change the
    number, nothing GUARANTEED the mutation actually altered the field -- a self-inverse transform
    is the wrong shape for a tamper vector. Fixed: always append an unconditional marker key, which
    changes content's bytes regardless of what the original payload happened to contain."""
    ev = copy.deepcopy(event)
    payload = json.loads(ev["content"])
    payload["_tampered_marker"] = "check_tamper_matrix.py content-tamper vector, unconditional"
    ev["content"] = json.dumps(payload)
    return ev


def _tamper_timestamp(event: dict) -> dict:
    """Vector 2: 'created_at shifted 1s'."""
    ev = copy.deepcopy(event)
    ev["created_at"] = int(ev["created_at"]) + 1
    return ev


def _tamper_signature_bit(event: dict) -> dict:
    """Vector 3: '1 bit flipped in the signature'. The id stays correct (the signature is not in
    its own preimage) -- this is the vector that isolates whether schnorr verification is actually
    being checked, or whether id_integrity alone is silently treated as sufficient."""
    ev = copy.deepcopy(event)
    sig_bytes = bytearray(bytes.fromhex(ev["sig"]))
    sig_bytes[0] ^= 0x01
    ev["sig"] = sig_bytes.hex()
    return ev


def _tamper_pubkey_swap(event: dict) -> dict:
    """Vector 4: 'pubkey swapped for another valid key'. The meaningful version of this attack
    swaps the pubkey AND recomputes id to match it (pubkey is part of the NIP-01 preimage, so
    id_integrity would trivially catch a swap-without-recompute -- that's not the interesting
    case). With id recomputed, id_integrity passes cleanly; the real question is whether
    signature_valid still fails, since the original signature was produced by the OLD key's
    private half and cannot validate against a DIFFERENT pubkey without forging a schnorr sig
    (computationally infeasible without that key's private half) -- a real key, just not the one
    that actually signed this content."""
    ev = copy.deepcopy(event)
    ev["pubkey"] = _ALTERNATE_REAL_PUBKEY
    ev["id"] = nostr_event_id(ev)  # recompute so id_integrity passes; sig alone must catch this
    return ev


TAMPER_VECTORS = [
    ("content changed", _tamper_content, "id"),         # id_integrity must fail (content is in the preimage)
    ("created_at shifted 1s", _tamper_timestamp, "id"),  # id_integrity must fail (created_at is in the preimage)
    ("1 bit flipped in signature", _tamper_signature_bit, "sig"),  # id OK, schnorr must fail
    ("pubkey swapped, id recomputed to match", _tamper_pubkey_swap, "sig"),  # id OK, schnorr must fail
]


def run(event: dict) -> int:
    print("=" * 76)
    print("SCHNORR/NIP-01 TAMPER MATRIX — one real verdict, four adversarial mutations")
    print("=" * 76)
    print(f"\nverdict event id: {event.get('id')}")
    print(f"pubkey:            {event.get('pubkey')}")
    payload = json.loads(event.get("content", "{}"))
    print(f"intended_verifier: {payload.get('intended_verifier', '(none declared)')}")
    print(f"decision_ref:      {payload.get('decision_ref')}\n")

    baseline = verify_proof(event)
    print(f"[BASELINE] valid={baseline['valid']}  checks={baseline['checks']}")
    if not baseline["valid"]:
        print("\nFAIL: the bundled/supplied verdict does not verify clean before any tampering — "
              "nothing downstream is meaningful until this passes.")
        return 1

    print("\ntamper matrix (each row must be REJECTED for the SPECIFIC reason it documents, not just")
    print("'invalid somehow' -- overall rejection alone doesn't prove the mechanism claimed. A row")
    print("could fail closed for the wrong reason (e.g. a pinned-pubkey allowlist rejecting the")
    print("pubkey-swap vector before schnorr verification ever runs) and this matrix would miss it")
    print("if it only checked `valid`):\n")
    failures = 0
    for name, mutate, primary_check in TAMPER_VECTORS:
        tampered = mutate(event)
        result = verify_proof(tampered)
        checks = result["checks"]
        # 2026-08-08, caught by our own /review on this exact file: `primary_check` was defined
        # per-vector but never actually asserted against -- the matrix only checked overall
        # `valid == False`, which a pinned-pubkey policy rejecting for the WRONG reason (e.g.
        # issued_by_invinoveritas failing before signature_valid is even meaningful) would still
        # pass, without proving the claimed mechanism (id_integrity or signature_valid) is what
        # actually caught it. Fixed: assert the specific check that should fail, per vector.
        specific_field = {"id": "id_integrity", "sig": "signature_valid"}[primary_check]
        specific_failed = checks.get(specific_field) is False
        rejected = not result["valid"]
        mechanism_ok = rejected and specific_failed
        if mechanism_ok:
            status = "REJECTED (correct, and for the claimed reason)"
        elif rejected:
            status = f"REJECTED, but NOT via {specific_field} — mechanism claim unproven"
        else:
            status = "ACCEPTED (WRONG — placebo check)"
        print(f"  [{name:40}] valid={result['valid']!s:5}  {status}")
        print(f"      checks: {checks}")
        if not mechanism_ok:
            failures += 1

    print(f"\n{len(TAMPER_VECTORS) - failures}/{len(TAMPER_VECTORS)} tamper vectors correctly rejected.")
    if failures:
        print(f"FAIL: {failures} tampered event(s) were incorrectly accepted as valid.")
        return 1

    print("\nOK: baseline verifies clean, all four tamper vectors correctly rejected for their")
    print("claimed reason (not just rejected somehow).")
    print("\nWhat this proves: the signed verdict is authentically invinoveritas's, byte-exact and")
    print("untampered, and its content cryptographically COMMITS to the declared intended_verifier")
    print("string (changing that string would change content, which id_integrity would catch) —")
    print("checkable by anyone re-running this file against the published pubkey, no API call, no")
    print("trust in either party. This is a commitment check, not a validation of the address: it")
    print("does not confirm the declared address is actually the MandateGate contract, is on Base")
    print("Sepolia, or that the verdict payload is meaningful to that specific contract.")
    print("\nWhat this does NOT prove: anything about the ECDSA/secp256k1 side of a MandateGate-style")
    print("on-chain gate. That is a genuinely different signature scheme over a genuinely different")
    print("preimage (keccak/EIP-191, not sha256/NIP-01) — closing THAT gap is separate, unbuilt work:")
    print("either an off-chain adapter that re-presents this event in the gate's expected shape, or")
    print("an on-chain schnorr verifier (the ecrecover-trick route, plus x-only-key parity handling).")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=DEFAULT_FILE)
    args = ap.parse_args()
    with open(args.file, encoding="utf-8") as f:
        event = json.load(f)
    if not isinstance(event, dict) or any(k not in event for k in ("id", "pubkey", "created_at", "kind", "content", "sig")):
        print(f"FAIL: {args.file} is not a well-formed NIP-01 event "
              f"(needs id/pubkey/created_at/kind/content/sig)")
        sys.exit(1)
    sys.exit(run(event))


if __name__ == "__main__":
    main()
