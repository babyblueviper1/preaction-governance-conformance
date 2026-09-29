"""Issuer profiles for the issuer-neutral marker checkers (trace-spec #397 / #398). Stdlib only.

The marker checks (vantage_limitation_check.py, related_claims_check.py) are the same for every issuer. What differs per
issuer is data, so it comes from a published issuer profile passed with --profile:

    {
      "schema": "trace-issuer-profile.v1",
      "issuer": "<name>",
      "envelope": "nip01-schnorr" | "jws-eddsa",
      "keys": ["<hex public key>", ...],          # nip01: 32-byte x-only BIP-340 key; jws: 32-byte Ed25519 key
      "nip01": {"kinds": [30078], "schema_prefix": "invinoveritas."},   # nip01 only; both optional
      "preimage_member": "decision_ref_preimage_fields",   # payload member listing the signed-preimage field names
      "irreversible_artifact_types": ["trade", ...],
      "notes_by_policy": {"<policy id>": {"<source_class>": "<exact note>"}}
    }

With no --profile the checkers use DEFAULT_PROFILE, which reproduces invinoveritas exactly as before (published key, kind 30078,
schema prefix "invinoveritas.", tools/vantage_notes_by_policy.json), so existing invocations keep byte-identical output.

A profile is not trusted content: it is the issuer's own public declaration, the way a verifier takes a trust anchor. The
checker reports its sha256 so a reader can see which profile a PASS was relative to.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
from _bip340_nostr import PUBLISHED_PUBKEY, nostr_event_id, schnorr_verify  # noqa: E402
import _ed25519  # noqa: E402

ENVELOPES = ("nip01-schnorr", "jws-eddsa")


def _default_profile() -> dict:
    t = json.load(open(os.path.join(HERE, "vantage_notes_by_policy.json"), encoding="utf-8"))
    return {"schema": "trace-issuer-profile.v1", "issuer": "invinoveritas", "envelope": "nip01-schnorr",
            "keys": [PUBLISHED_PUBKEY], "nip01": {"kinds": [30078], "schema_prefix": "invinoveritas."},
            "preimage_member": "decision_ref_preimage_fields",
            "irreversible_artifact_types": t["irreversible_artifact_types"], "notes_by_policy": t["policies"]}


DEFAULT_PROFILE = _default_profile()


class ProfileError(ValueError):
    pass


def load_profile(path: str | None) -> tuple[dict, str]:
    """-> (profile, label). label names the profile and its sha256 for the report."""
    if not path:
        return DEFAULT_PROFILE, "built-in default (invinoveritas)"
    raw = open(path, "rb").read()
    try:
        p = json.loads(raw)
    except ValueError as e:
        raise ProfileError(f"profile is not JSON: {e}")
    if not isinstance(p, dict) or p.get("schema") != "trace-issuer-profile.v1":
        raise ProfileError("profile schema must be trace-issuer-profile.v1")
    if p.get("envelope") not in ENVELOPES:
        raise ProfileError(f"envelope must be one of {ENVELOPES}")
    keys = p.get("keys")
    if not (isinstance(keys, list) and keys and all(isinstance(k, str) and len(k) == 64 for k in keys)):
        raise ProfileError("keys must be a nonempty list of 64-hex-char public keys")
    for k in ("preimage_member",):
        if not isinstance(p.get(k), str) or not p[k]:
            raise ProfileError(f"{k} must be a nonempty string")
    if not isinstance(p.get("irreversible_artifact_types"), list):
        raise ProfileError("irreversible_artifact_types must be a list")
    if not isinstance(p.get("notes_by_policy"), dict):
        raise ProfileError("notes_by_policy must be an object")
    return p, f"{p.get('issuer', '?')} ({os.path.basename(path)} sha256 {hashlib.sha256(raw).hexdigest()[:16]})"


def envelope_label(profile) -> str:
    """What "proof valid" means under this profile, for the report line. None/nip01 keeps the original wording."""
    if profile is None or profile["envelope"] == "nip01-schnorr":
        return "(id, schnorr, issuer, kind)"
    return "(JWS EdDSA signature, kid among the profile's keys)"


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_envelope(record, profile: dict) -> dict:
    """-> {"valid": bool, "payload": dict|None, "why": str}. Never raises."""
    env = profile["envelope"]
    keys = [k.lower() for k in profile["keys"]]
    try:
        if env == "nip01-schnorr":
            if not isinstance(record, dict) or any(record.get(k) in (None, "") for k in ("id", "pubkey", "created_at", "kind", "content", "sig")):
                return {"valid": False, "payload": None, "why": "not a NIP-01 event"}
            id_ok = nostr_event_id(record).lower() == str(record["id"]).lower()
            try:
                sig_ok = schnorr_verify(bytes.fromhex(str(record["id"])), bytes.fromhex(str(record["pubkey"])), bytes.fromhex(str(record["sig"])))
            except Exception:
                sig_ok = False
            key_ok = str(record["pubkey"]).strip().lower() in keys
            try:
                payload = json.loads(str(record["content"]))
            except Exception:
                payload = None
            nip = profile.get("nip01") or {}
            kind_ok = int(record["kind"]) in nip.get("kinds", [int(record["kind"])])
            prefix = nip.get("schema_prefix")
            schema = (payload or {}).get("schema", "") if isinstance(payload, dict) else ""
            shape_ok = kind_ok and (prefix is None or (isinstance(schema, str) and schema.startswith(prefix)))
            valid = id_ok and sig_ok and key_ok and shape_ok
            why = "" if valid else ",".join(n for n, ok in (("id", id_ok), ("sig", sig_ok), ("key", key_ok), ("kind/schema", shape_ok)) if not ok)
            return {"valid": valid, "payload": payload if isinstance(payload, dict) else None, "why": why}
        # jws-eddsa, flattened JSON serialization: {"protected": b64url(header), "payload": b64url(json), "signature": b64url}
        if not isinstance(record, dict) or not all(isinstance(record.get(k), str) for k in ("protected", "payload", "signature")):
            return {"valid": False, "payload": None, "why": "not a flattened JWS"}
        header = json.loads(_b64url(record["protected"]))
        if header.get("alg") != "EdDSA":
            return {"valid": False, "payload": None, "why": "alg is not EdDSA"}
        kid = str(header.get("kid", "")).lower()
        if kid not in keys:
            return {"valid": False, "payload": None, "why": "kid not among the profile's keys"}
        signing_input = (record["protected"] + "." + record["payload"]).encode("ascii")
        if not _ed25519.verify(bytes.fromhex(kid), signing_input, _b64url(record["signature"])):
            return {"valid": False, "payload": None, "why": "sig"}
        payload = json.loads(_b64url(record["payload"]))
        return {"valid": isinstance(payload, dict), "payload": payload if isinstance(payload, dict) else None, "why": ""}
    except Exception as e:
        return {"valid": False, "payload": None, "why": f"malformed: {type(e).__name__}"}
