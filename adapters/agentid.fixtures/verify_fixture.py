#!/usr/bin/env python3
"""Independent re-verification of an AgentID `verifier_attestation` (CTEF v0.1) fixture.

Trusts NOTHING but the Ed25519 key served at https://getagentid.dev/.well-known/jwks.json (or a
saved copy via --jwks). Recomputes every bound value from the envelope bytes in the fixture:

  1. digest           == sha256(JCS(core))            core = response minus {digest, jws}
  2. JWS payload      == JCS(core) bytes               (compact JWS, header.payload.signature)
  3. EdDSA signature  over ASCII(header '.' payload)  against the JWKS key whose kid == header.kid
  4. binding_digest   == sha256(JCS({amount_usd, charge_ref, nonce, subject_did}))
  5. action_ref       == sha256(agent_id || action_type || scope || int64_be(ms(issued_at)))
                         (argentum-core action-ref-v1, raw concatenation — NOT sha256(JCS(...)))
  6. attestation_ref  == sha256(JCS({kid, subject_did, verifier}))

Deps: `cryptography` (Ed25519 verify) and `jcs` (RFC 8785). Exit 0 iff every check passes.
Usage: python3 verify_fixture.py positive.raw.json [--jwks jwks.json] [--action-type read --scope conformance-fixture]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import struct
import sys
import urllib.request
from datetime import datetime, timezone

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

JWKS_URL = "https://getagentid.dev/.well-known/jwks.json"


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def iso_to_ms(iso: str) -> int:
    dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(timezone.utc)
    return int(round(dt.timestamp() * 1000))


def load_jwks(path: str | None) -> dict:
    if path:
        return json.load(open(path, encoding="utf-8"))
    with urllib.request.urlopen(JWKS_URL, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("fixture")
    ap.add_argument("--jwks", default=None, help="saved JWKS JSON (default: fetch live)")
    ap.add_argument("--action-type", default="read")
    ap.add_argument("--scope", default="conformance-fixture")
    a = ap.parse_args()

    resp = json.load(open(a.fixture, encoding="utf-8"))
    # Accept either the raw endpoint response or a board-shaped fixture that embeds it.
    att = resp.get("verifier_attestation", resp)
    core = {k: v for k, v in att.items() if k not in ("digest", "jws")}
    canonical = jcs.canonicalize(core)
    results: list[tuple[str, bool, str]] = []

    # 1. digest == sha256(JCS(core))
    d = sha256_hex(canonical)
    results.append(("digest == sha256(JCS(core))", d == att.get("digest"), f"{d[:16]} vs {str(att.get('digest'))[:16]}"))

    # 2 + 3. JWS payload == JCS(core); EdDSA over header.payload with the JWKS key
    h_b64, p_b64, s_b64 = att["jws"].split(".")
    header = json.loads(b64u_decode(h_b64))
    payload = b64u_decode(p_b64)
    results.append(("JWS payload bytes == JCS(core)", payload == canonical, f"{len(payload)} bytes"))
    results.append(("JWS header alg == EdDSA", header.get("alg") == "EdDSA", json.dumps(header)))
    jwks = load_jwks(a.jwks)
    key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
    if key is None:
        results.append(("JWKS has kid == header.kid", False, f"kid {header.get('kid')!r} not in {[k.get('kid') for k in jwks['keys']]}"))
        sig_ok = False
    else:
        pub_raw = b64u_decode(key["x"])
        results.append(("JWKS key is OKP/Ed25519 (32 bytes)", key.get("kty") == "OKP" and key.get("crv") == "Ed25519" and len(pub_raw) == 32,
                        f"kid={key['kid']} pub_hex={pub_raw.hex()}"))
        try:
            Ed25519PublicKey.from_public_bytes(pub_raw).verify(b64u_decode(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
            sig_ok = True
        except InvalidSignature:
            sig_ok = False
        results.append(("EdDSA signature verifies over header.payload", sig_ok, f"kid={header.get('kid')}"))

    # 4. binding_digest
    b = att["binding"]
    bd_pre = {"amount_usd": b["amount_usd"], "charge_ref": b["charge_ref"], "nonce": b["nonce"], "subject_did": att["subject"]["did"]}
    bd = sha256_hex(jcs.canonicalize(bd_pre))
    results.append(("binding_digest == sha256(JCS({amount_usd,charge_ref,nonce,subject_did}))", bd == b["binding_digest"], f"{bd[:16]} vs {b['binding_digest'][:16]}"))
    results.append(("binding_digest == sha256(JCS(core))  [babyblueviper1's stated expectation]", bd == d, "NOT the construction used" if bd != d else ""))

    # 5. action_ref — raw-concat (argentum-core action-ref-v1) vs JCS form
    ts_ms = iso_to_ms(att["issued_at"])
    agent_id = att["subject"]["agent_id"] or att["subject"]["did"]
    raw_pre = agent_id.encode() + a.action_type.encode() + a.scope.encode() + struct.pack(">q", ts_ms)
    ar_raw = sha256_hex(raw_pre)
    ar_jcs = sha256_hex(jcs.canonicalize({"agent_id": agent_id, "action_type": a.action_type, "scope": a.scope, "timestamp_ms": ts_ms}))
    results.append((f"action_ref == sha256(agent_id||action_type||scope||int64_be(ms(issued_at)))  ts_ms={ts_ms}", ar_raw == b["action_ref"], f"{ar_raw[:16]} vs {b['action_ref'][:16]}"))
    results.append(("action_ref == sha256(JCS({agent_id,action_type,scope,timestamp_ms}))  [JCS form, for the record]", ar_jcs == b["action_ref"], f"{ar_jcs[:16]} vs {b['action_ref'][:16]}"))

    # 6. attestation_ref
    ar = sha256_hex(jcs.canonicalize({"kid": att["verifier"]["kid"], "subject_did": att["subject"]["did"], "verifier": att["verifier"]["id"]}))
    results.append(("attestation_ref == sha256(JCS({kid,subject_did,verifier}))", ar == att["attestation_ref"], f"{ar[:16]} vs {att['attestation_ref'][:16]}"))

    # Informational lines (not pass/fail): the two "expectation" rows above are reported, not required.
    required = [r for r in results if "[" not in r[0]]
    for name, ok, detail in results:
        tag = "PASS" if ok else ("FAIL" if "[" not in name else "no  ")
        print(f"[{tag}] {name} — {detail}")
    print(f"canonical bytes sha256 = {d}  ({len(canonical)} bytes)")
    all_ok = all(ok for _, ok, _ in required)
    print("RESULT:", "VERIFIED" if all_ok else "NOT VERIFIED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
