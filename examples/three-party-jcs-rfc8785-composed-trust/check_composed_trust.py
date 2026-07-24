#!/usr/bin/env python3
"""check_composed_trust.py — independently recompute THREE artifacts from THREE
separately-operated systems, sourced verbatim from microsoft/autogen#7353
(2026-07-24), each committing to the same canonicalization discipline
(jcs-rfc8785-v1) while never trusting any of the three issuers' own /verify
endpoints:

  1. Yarmoluk / Graphify.md's CKG knowledge_receipt (Ed25519, key from a
     separate /keys endpoint fetched live, not pasted in the receipt)
  2. giskard09's Argentum-core action_ref (Ed25519, key pasted alongside the
     receipt -- a real, if weaker, key-distribution shape worth naming as a
     structural difference from CKG's, not glossed over)
  3. invinoveritas's own /review pre-action verdict (a different signature
     scheme entirely -- Nostr NIP-01/schnorr, checked via the decision_ref
     recompute here; full signature verification lives in
     ../decision-ref-recompute/ and the live /verify-proof endpoint, not
     duplicated in this script)

The point being demonstrated: three parties who have never shared code can
each independently commit to "recomputable from published bytes, key never
embedded in the artifact" and a fourth party (this script) can check all
three without asking any of them to vouch for the others.

Zero third-party dependencies beyond `cryptography` (Ed25519 verification).
No network calls -- everything here recomputes from the fixture's own bytes.
Run: python3 check_composed_trust.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

try:
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Requires the `cryptography` package: pip install cryptography")
    sys.exit(2)

HERE = Path(__file__).resolve().parent


def jcs(obj) -> bytes:
    """RFC 8785-equivalent for these fixtures: sorted keys, compact separators,
    raw UTF-8 (no \\uXXXX escaping). Sufficient for every payload in this fixture
    (plain strings/ints/null, no floats or exotic Unicode edge cases where the
    real RFC 8785 number-formatting/NFC rules would diverge from this)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_ed25519_receipt(artifact: dict) -> dict:
    """Recompute receipt_ref = sha256(JCS(payload)) and check the Ed25519
    signature over the canonical bytes -- both from scratch, no library call
    into the issuer's own verify endpoint."""
    canon = jcs(artifact["payload"])
    digest = hashlib.sha256(canon).hexdigest()
    expected_ref = f"sha256:{digest}"
    ref_ok = expected_ref == artifact["receipt_ref"]

    pubkey = Ed25519PublicKey.from_public_bytes(base64.b64decode(artifact["issuer_pubkey_base64"]))
    sig = base64.b64decode(artifact["signature_base64"])
    sig_ok = False
    try:
        pubkey.verify(sig, canon)
        sig_ok = True
    except InvalidSignature:
        sig_ok = False

    return {
        "party": artifact["party"],
        "kind": artifact["kind"],
        "receipt_ref_recomputes": ref_ok,
        "signature_verifies": sig_ok,
        "recomputed_ref": expected_ref,
        "claimed_ref": artifact["receipt_ref"],
    }


def verify_decision_ref(artifact: dict) -> dict:
    """invinoveritas's decision_ref: sha256(JCS(preimage)) over the exact field
    list the proof itself discloses (decision_ref_preimage_fields) -- same
    construction as the other Ed25519 receipts above, different signature
    scheme wrapping it (Nostr/schnorr, not checked here -- see the module
    docstring)."""
    preimage = {k: artifact["decision_ref_preimage"][k] for k in artifact["decision_ref_preimage_fields"]}
    digest = hashlib.sha256(jcs(preimage)).hexdigest()
    expected_ref = f"sha256:{digest}"
    ref_ok = expected_ref == artifact["decision_ref"]
    return {
        "party": "invinoveritas",
        "kind": artifact["kind"],
        "decision_ref_recomputes": ref_ok,
        "recomputed_ref": expected_ref,
        "claimed_ref": artifact["decision_ref"],
        "note": "signature scheme is Nostr NIP-01 (schnorr/secp256k1), not Ed25519 -- "
                "verified live via POST /verify-proof at fixture-build time "
                f"(response recorded in fixture.json: {artifact['verify_proof_response_checks']})",
    }


def main() -> int:
    fixture = json.loads((HERE / "fixture.json").read_text())
    artifacts = fixture["artifacts"]

    print("=" * 78)
    print("THREE-PARTY COMPOSED TRUST: jcs-rfc8785-v1 across 3 independent systems")
    print("=" * 78)

    results = []
    for artifact in artifacts:
        if artifact["kind"] == "pre_action_verdict":
            r = verify_decision_ref(artifact)
            ok = r["decision_ref_recomputes"]
        else:
            r = verify_ed25519_receipt(artifact)
            ok = r["receipt_ref_recomputes"] and r["signature_verifies"]
        results.append((artifact["party"], artifact["kind"], ok, r))
        print(f"\n[{artifact['kind']}] {artifact['party']}")
        for k, v in r.items():
            if k in ("party", "kind"):
                continue
            print(f"  {k}: {v}")

    print("\n" + "-" * 78)
    all_ok = True
    for party, kind, ok, _ in results:
        status = "PASS" if ok else "FAIL"
        print(f"{status} -- {kind:20s} {party}")
        all_ok = all_ok and ok

    print()
    if all_ok:
        print("PASS -- all three artifacts independently recompute from their own")
        print("        published bytes. None of the three checks above called any of")
        print("        the three issuers' own /verify endpoints -- this script is the")
        print("        fourth, unrelated party doing the checking.")
        return 0
    print("FAIL -- at least one artifact did not recompute or verify.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
