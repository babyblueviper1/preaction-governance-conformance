#!/usr/bin/env python3
"""Derive the board-shaped fixtures from the verbatim endpoint response (positive.raw.json) + jwks.json.

Nothing here signs with the AgentID key. The positive fixture is the live response byte-for-byte (under
`verifier_attestation`) plus a `governance` block and an RFC 7515 general-serialization `jws` that are
pure re-encodings of values already in the response / JWKS, so adapters/live_check.py can read them:
  governance.envelope_hash        = response.digest
  governance.canonical_bytes_utf8 = JCS(core)   (== the decoded JWS payload, asserted at build time)
  governance.verifier_pubkey      = hex(base64url_decode(jwks.keys[kid].x))
  jws                             = compact JWS re-encoded as {payload, signatures:[{protected, signature}]}

Negatives:
  negative_bound_field_altered.json  same envelope + same signature, binding.charge_ref altered -> digest no longer recomputes
  negative_throwaway_key.json        same core, same header (kid claims agentid-2026-03), signed by a throwaway key
                                     (seed = sha256(b"agentid-conformance-throwaway") -- deliberately public, never trusted)
Run: python3 build_fixtures.py   (deps: cryptography, jcs)
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
ENDPOINT = "https://getagentid.dev/api/v1/agents/gateway/verifier-attestation"
JWKS_URL = "https://getagentid.dev/.well-known/jwks.json"


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def dump(name: str, obj: dict) -> None:
    (HERE / name).write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("wrote", name)


def shape(att: dict, pubkey_hex: str, expected: dict, name: str, description: str, request: dict) -> dict:
    core = {k: v for k, v in att.items() if k not in ("digest", "jws")}
    canonical = jcs.canonicalize(core).decode("utf-8")
    h, p, s = att["jws"].split(".")
    return {
        "fixture": name,
        "description": description,
        "expected_live_check": expected,
        "source": {
            "endpoint": ENDPOINT,
            "request": request,
            "jwks_url": JWKS_URL,
            "kid": att["verifier"]["kid"],
            "issued_at": att["issued_at"],
        },
        "verifier_attestation": att,
        "governance": {
            "envelope_hash": att["digest"],
            "canonical_bytes_utf8": canonical,
            "verifier_pubkey": pubkey_hex,
            "verifier_kid": att["verifier"]["kid"],
            "signature": s,
            "sig_scheme": "ed25519-jcs",
            "signature_input": "ASCII(BASE64URL(protected) '.' BASE64URL(payload)) per RFC 7515; payload bytes == canonical_bytes_utf8",
        },
        "jws": {"payload": p, "signatures": [{"protected": h, "signature": s}]},
    }


def main() -> None:
    raw = json.loads((HERE / "positive.raw.json").read_text(encoding="utf-8"))
    jwks = json.loads((HERE / "jwks.json").read_text(encoding="utf-8"))
    request = json.loads((HERE / "request.json").read_text(encoding="utf-8"))
    key = next(k for k in jwks["keys"] if k["kid"] == raw["verifier"]["kid"])
    pub_hex = b64u_decode(key["x"]).hex()
    print("issuer pubkey hex:", pub_hex)

    h, p, s = raw["jws"].split(".")
    core = {k: v for k, v in raw.items() if k not in ("digest", "jws")}
    assert b64u_decode(p) == jcs.canonicalize(core), "JWS payload must equal JCS(core)"
    assert hashlib.sha256(jcs.canonicalize(core)).hexdigest() == raw["digest"]

    # ---- positive ----
    dump("positive.json", shape(
        raw, pub_hex,
        {"canonical_envelope": "pass", "admission_invariant": "pass",
         "anchoring_existence": "fail:ordering_unanchored (no anchor claimed; ordering is the board's layer)",
         "anchoring_precedence": "not_assessable", "chain_invariant": "not_provided"},
        "agentid.positive",
        "Real verifier_attestation signed by AgentID issuer key kid agentid-2026-03 (OKP/Ed25519, "
        "https://getagentid.dev/.well-known/jwks.json) over a bound read action for agent_d1b7ef01f9af191f. "
        "digest == sha256(JCS(core)); JWS payload == JCS(core); verifies against the JWKS with nothing else trusted.",
        request))

    # ---- negative 1: bound field altered, signature untouched ----
    alt = json.loads(json.dumps(raw))
    alt["binding"]["charge_ref"] = "conformance-fixture-ALTERED"
    dump("negative_bound_field_altered.json", shape(
        alt, pub_hex,
        {"canonical_envelope": "fail:envelope_hash_mismatch", "admission_invariant": "fail:admission_signature_invalid",
         "anchoring_existence": "fail:ordering_unanchored", "anchoring_precedence": "not_assessable", "chain_invariant": "not_provided"},
        "agentid.negative_bound_field_altered",
        "Same envelope and same signature as the positive, with one bound field altered "
        "(binding.charge_ref 'conformance-fixture' -> 'conformance-fixture-ALTERED'). The declared digest / "
        "envelope_hash is unchanged so it no longer recomputes from the envelope, binding_digest no longer "
        "recomputes, and the JWS payload no longer equals the canonical bytes.",
        request))

    # ---- negative 2: throwaway key, header claims the issuer kid ----
    seed = hashlib.sha256(b"agentid-conformance-throwaway").digest()
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    tpub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    sig = b64u(sk.sign(f"{h}.{p}".encode("ascii")))
    forged = json.loads(json.dumps(raw))
    forged["jws"] = f"{h}.{p}.{sig}"
    neg2 = shape(
        forged, tpub,
        {"canonical_envelope": "pass", "admission_invariant": "fail:key_different_but_identity_unproven",
         "anchoring_existence": "fail:ordering_unanchored", "anchoring_precedence": "not_assessable", "chain_invariant": "not_provided"},
        "agentid.negative_throwaway_key",
        "Same core and same protected header (kid claims agentid-2026-03) signed by a throwaway Ed25519 key "
        f"(pub {tpub}; seed = sha256(b'agentid-conformance-throwaway'), deliberately public). The signature is "
        "internally valid under the throwaway key but is NOT the key served at the JWKS, so admission must fail.",
        request)
    neg2["governance"]["signature_note"] = "verifier_pubkey here is the throwaway key, not the JWKS key; the mapping's trust_policy lists only the JWKS key"
    dump("negative_throwaway_key.json", neg2)

    # ---- flattened JWS records for tools/issuer_profile.py (jws-eddsa profile) ----
    dump("positive.flattened-jws.json", {"protected": h, "payload": p, "signature": s})
    dump("negative_throwaway_key.flattened-jws.json", {"protected": h, "payload": p, "signature": sig})


if __name__ == "__main__":
    main()
