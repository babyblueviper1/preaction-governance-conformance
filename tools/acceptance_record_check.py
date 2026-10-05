#!/usr/bin/env python3
"""Cold checker for counterparty ACCEPTANCE records (x402-foundation/tsc#4, Shodai's acceptance condition set,
2026-10-04 comment 'acceptance conditions in the crosswalk format'), written from that comment plus
draft-krausz-verification-state-03 Section 5.4.2, which the comment reuses unchanged for the confirming party's key.

An acceptance record is a record made AFTER the outcome and signed by the counterparty, stating its disposition
(accepted / rejected / disputed) toward a record someone else issued (a receipt, a payment record). -03 covers a
claim checked before acting by one verifier; this is its post-settlement companion. Stdlib only.
Readings the comment does not fix are marked `# READING An` and listed in examples/acceptance-record-cold/README.md.

    python3 tools/acceptance_record_check.py case.json
        case.json: {"acceptance": <flattened JWS>, "accepted_record": {...}, "trust_material": <JWKS>,
                    "trust_material_complete": bool (default false), "delegation": {party: [kid, ...]}}
        or {"accepted_record": {...}} with no "acceptance" member (no record was supplied).

Exit: 0 verified, 2 unknown / key_unresolved / no record, 1 malformed. Output: JSON report.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _ed25519  # noqa: E402
import _rfc8785  # noqa: E402

VERSION = "acceptance-record-v0"          # READING A1: provisional; the comment names no version member
SIGNED_DISPOSITIONS = ("accepted", "rejected", "disputed")
NOT_RESPONDED = "not_responded"
TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")   # -03 5.3.2 timestamp form
HEX64 = re.compile(r"^[0-9a-f]{64}$")

VERIFIED, UNKNOWN, MALFORMED, KEY_UNRESOLVED, NO_RECORD = "verified", "unknown", "malformed", "key_unresolved", "no_record"

# Shodai's six (tsc#4, 2026-10-04) + one structural name this checker needed (PROPOSED, not in the comment).
CONDITIONS = {
    "confirming_party_absent": MALFORMED,
    "acceptance_signer_is_issuer": MALFORMED,
    "acceptance_terms_digest_mismatch": MALFORMED,
    "acceptance_outcome_digest_mismatch": MALFORMED,
    "acceptance_precedes_outcome": MALFORMED,
    "acceptance_authority_unresolved": UNKNOWN,
    "acceptance_member_invalid": MALFORMED,     # PROPOSED (A3): a required member is absent or ill-typed
    "acceptance_record_digest_mismatch": MALFORMED,   # added 2026-10-05 on Shodai's request (tsc#4): binds WHICH record is accepted
}


def record_digest(rec: dict) -> str:
    """READING A8: sha256 over the RFC 8785 (JCS) bytes of the accepted record as the relying party holds it."""
    import hashlib
    return hashlib.sha256(_rfc8785.jcs(rec).encode("utf-8")).hexdigest()


def _valid_ts(s):
    m = TS_RE.match(s) if isinstance(s, str) else None
    if not m:
        return False
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and h <= 23 and mi <= 59 and se <= 59):
        return False
    dim = [31, 29 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1]
    return 1 <= d <= dim


def _b64url_dec(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _resolve_kid(kid, jwks):
    """Ed25519 public key bytes for kid in the supplied JWKS, or None."""
    for k in (jwks or {}).get("keys", []) if isinstance(jwks, dict) else []:
        if isinstance(k, dict) and k.get("kid") == kid and k.get("kty") == "OKP" and k.get("crv") == "Ed25519":
            try:
                x = _b64url_dec(k.get("x", ""))
            except ValueError:
                continue
            if len(x) == 32:
                return x
    return None


def _party_of_kid(kid, delegation):
    return {p for p, kids in (delegation or {}).items() if isinstance(kids, list) and kid in kids}


def check(case: dict) -> dict:
    rec = case.get("accepted_record") or {}
    if "acceptance" not in case or case.get("acceptance") is None:
        # READING A2: not_responded is what a relying party reports when NO acceptance record exists. It is a
        # disposition with no verification behind it, so it is never 'verified' and never a weaker 'accepted'.
        return {"result": NO_RECORD, "disposition": NOT_RESPONDED, "conditions": [],
                "note": "no acceptance record supplied; not_responded is not a form of accepted"}
    jws = case["acceptance"]
    complete = case.get("trust_material_complete") is True          # -03 5.4.2: default 'not complete'
    out = {"result": None, "disposition": None, "conditions": [], "key_step": None}

    # step 0: the envelope must be parseable far enough to name a kid (else nothing can be resolved)
    try:
        hdr = json.loads(_b64url_dec(jws["protected"]))
        payload_bytes = _b64url_dec(jws["payload"])
        sig = _b64url_dec(jws["signature"])
        kid, alg = hdr["kid"], hdr["alg"]
        if not isinstance(kid, str) or alg != "EdDSA":
            raise ValueError("kid/alg")
    except Exception:
        out.update(result=MALFORMED, conditions=["acceptance_member_invalid"], detail="JWS envelope (protected/kid/alg EdDSA/payload/signature)")
        return out

    # step 1 = -03 5.4.2 unchanged: key_unresolved (not malformed; + policy refusal if declared complete) /
    # signature_invalid (malformed) / signature_verified. Evaluation stops on the first two.
    key = _resolve_kid(kid, case.get("trust_material"))
    if key is None:
        out.update(result=KEY_UNRESOLVED, key_step="key_unresolved")
        if complete:
            out["policy_refusal"] = True            # a disposition of the relying party, not a check result
        return out
    if not _ed25519.verify(key, (jws["protected"] + "." + jws["payload"]).encode("ascii"), sig):
        out.update(result=MALFORMED, key_step="signature_invalid", conditions=["signature_invalid"])
        return out
    out["key_step"] = "signature_verified"

    try:
        p = json.loads(payload_bytes)
        if not isinstance(p, dict):
            raise ValueError
    except ValueError:
        out.update(result=MALFORMED, conditions=["acceptance_member_invalid"], detail="payload is not a JSON object")
        return out

    conds, bad = [], set()
    # structural checks with type-check suppression: a member that is ill-typed does not also raise the
    # comparison condition that depends on it (same discipline as -03's report-all).
    if p.get("acceptance_version") != VERSION:
        bad.add("acceptance_version")
    cp = p.get("confirming_party")
    if cp is None or cp == "":
        conds.append("confirming_party_absent")
    elif not isinstance(cp, str):
        bad.add("confirming_party")
    if p.get("disposition") not in SIGNED_DISPOSITIONS:
        bad.add("disposition")                      # READING A2: a signed 'not_responded' is self-contradictory
    for k in ("terms_sha256", "outcome_sha256", "accepted_record_sha256"):
        if not (isinstance(p.get(k), str) and HEX64.match(p[k])):
            bad.add(k)
    if not _valid_ts(p.get("accepted_at")):
        bad.add("accepted_at")
    if not (isinstance(rec.get("issuer"), str) and isinstance(rec.get("issuer_kid"), str)
            and all(isinstance(rec.get(k), str) and HEX64.match(rec[k]) for k in ("terms_sha256", "outcome_sha256"))
            and _valid_ts(rec.get("outcome_at"))):
        bad.add("accepted_record")                  # READING A4: the referenced record's members, as the relying party holds them
    if bad:
        conds.append("acceptance_member_invalid")

    # acceptance_signer_is_issuer: "signed by the key OR party that issued the record being accepted".
    # READING A5: same key = same public key bytes (a re-used key under a new kid still counts); same party = the
    # confirming party equals the issuer, or the delegation material binds the signing kid to the issuer.
    if "accepted_record" not in bad:
        ik = _resolve_kid(rec["issuer_kid"], case.get("trust_material"))
        same_key = rec["issuer_kid"] == kid or (ik is not None and ik == key)
        same_party = (isinstance(cp, str) and cp == rec["issuer"]) or rec["issuer"] in _party_of_kid(kid, case.get("delegation"))
        if same_key or same_party:
            conds.append("acceptance_signer_is_issuer")
        if "accepted_record_sha256" not in bad and p["accepted_record_sha256"] != record_digest(rec):
            conds.append("acceptance_record_digest_mismatch")
        if "terms_sha256" not in bad and p["terms_sha256"] != rec["terms_sha256"]:
            conds.append("acceptance_terms_digest_mismatch")
        if "outcome_sha256" not in bad and p["outcome_sha256"] != rec["outcome_sha256"]:
            conds.append("acceptance_outcome_digest_mismatch")
        # fixed-width -03 timestamps compare correctly as strings
        if "accepted_at" not in bad and p["accepted_at"] < rec["outcome_at"]:
            conds.append("acceptance_precedes_outcome")

    if conds:
        out.update(result=MALFORMED, conditions=sorted(set(conds)), members_invalid=sorted(bad) or None)
        return out
    # authority: unknown (a limit of the verifier, like -03 5.4.1(h)), checked only once nothing is malformed.
    # READING A6: resolved iff the delegation material lists the signing kid under the confirming party.
    if cp not in _party_of_kid(kid, case.get("delegation")):
        out.update(result=UNKNOWN, conditions=["acceptance_authority_unresolved"], disposition=p["disposition"])
        return out
    out.update(result=VERIFIED, disposition=p["disposition"])
    return out


EXIT = {VERIFIED: 0, UNKNOWN: 2, KEY_UNRESOLVED: 2, NO_RECORD: 2, MALFORMED: 1}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    r = check(json.load(open(sys.argv[1])))
    print(json.dumps(r, indent=1, sort_keys=True))
    sys.exit(EXIT[r["result"]])
