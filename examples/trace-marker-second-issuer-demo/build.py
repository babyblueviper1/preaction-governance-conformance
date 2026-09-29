#!/usr/bin/env python3
"""Build the DEMONSTRATION second-issuer records for the issuer-neutral marker checkers (trace-spec #397 / #398).

This is NOT an independent issuer. It is a fixture issuer we wrote, with a deliberately published demo key, whose only
job is to show that tools/vantage_limitation_check.py and tools/related_claims_check.py accept a record from an issuer
that differs from invinoveritas in envelope (flattened JWS, EdDSA), key, policy ids, note wording and preimage member,
with no change to checker code: only a different --profile. An independent issuer passing it is still open.

Needs `cryptography` (build-time only; the checkers themselves stay stdlib). Deterministic: same seeds -> same bytes.
    python3 build.py && python3 run_demo.py
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
import _ed25519  # noqa: E402

# DEMO KEYS, PUBLISHED ON PURPOSE. Anyone can sign as "example-issuer"; that is the point of a fixture, not a trust anchor.
DEMO_SEED = hashlib.sha256(b"trace-marker-second-issuer-demo/example-issuer/v1").digest()
OTHER_SEED = hashlib.sha256(b"trace-marker-second-issuer-demo/not-the-issuer/v1").digest()
POLICY = "example-issuer.policy.2026-09"
MEMBER = "signed_fields"
NOTES = {POLICY: {
    "self_reported": "Operator-reported inputs; the issuer did not observe execution.",
    "issuer_observed": "Issuer observed the request; settlement was not observed.",
}}
IRREVERSIBLE = ["wire_transfer", "contract_signature"]
INV_INNER = os.path.join(HERE, "..", "trace-v20-fixtures", "events", "inner.json")
INV_CLAIMS = os.path.join(HERE, "..", "trace-v20-fixtures", "events", "claims_exact.json")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pub_hex(sk) -> str:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def jws(payload: dict, sk, kid: str | None = None, alg: str = "EdDSA") -> dict:
    header = {"alg": alg, "kid": kid or pub_hex(sk), "typ": "example-issuer.decision+jws"}
    prot = b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    body = b64u(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    sig = sk.sign(f"{prot}.{body}".encode("ascii"))
    return {"protected": prot, "payload": body, "signature": b64u(sig)}


def jcs(claims: dict) -> bytes:
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def main():
    sk = Ed25519PrivateKey.from_private_bytes(DEMO_SEED)
    other = Ed25519PrivateKey.from_private_bytes(OTHER_SEED)
    demo_pub = pub_hex(sk)

    # cross-check the stdlib verifier the checkers use against `cryptography`, on these exact inputs
    for i in range(32):
        m = hashlib.sha256(b"xcheck%d" % i).digest() * (i % 3)
        s = sk.sign(m)
        assert _ed25519.verify(bytes.fromhex(demo_pub), m, s), i
        assert not _ed25519.verify(bytes.fromhex(demo_pub), m + b"x", s), i
        assert not _ed25519.verify(bytes.fromhex(pub_hex(other)), m, s), i

    profile = {"schema": "trace-issuer-profile.v1", "issuer": "example-issuer (DEMONSTRATION, not independent)",
               "envelope": "jws-eddsa", "keys": [demo_pub], "preimage_member": MEMBER,
               "irreversible_artifact_types": IRREVERSIBLE, "notes_by_policy": NOTES}

    base = {"issuer": "example-issuer", "policy_version": POLICY, "decision": "allow_with_conditions",
            "decided_at": "2026-09-29T20:00:00Z", "decision_id": "ex-0001"}
    def vl(**kw):
        p = dict(base, **kw)
        p.setdefault(MEMBER, sorted({k for k in p if k != MEMBER} | {"vantage_limitation"}))  # absence is signed too
        return p

    irrev = vl(artifact_type="wire_transfer", source_class="self_reported",
               vantage_limitation=NOTES[POLICY]["self_reported"])
    records = {
        # must PASS
        "vl_pass_irreversible.json": jws(irrev, sk),
        "vl_pass_reversible.json": jws(vl(artifact_type="draft_email", source_class="issuer_observed"), sk),
        # must FAIL
        "vl_mut_edited_note.json": jws(dict(irrev, vantage_limitation=NOTES[POLICY]["self_reported"].replace("did not", "may not")), sk),
        "vl_mut_note_on_reversible.json": jws(vl(artifact_type="draft_email", source_class="self_reported",
                                                 vantage_limitation=NOTES[POLICY]["self_reported"]), sk),
        "vl_mut_note_missing.json": jws(vl(artifact_type="contract_signature", source_class="issuer_observed"), sk),
        "vl_mut_note_outside_preimage.json": jws(dict(irrev, **{MEMBER: [k for k in irrev[MEMBER] if k != "vantage_limitation"]}), sk),
        "vl_mut_wrong_class_note.json": jws(dict(irrev, vantage_limitation=NOTES[POLICY]["issuer_observed"]), sk),
        "vl_mut_other_key.json": jws(irrev, other),
        "vl_mut_kid_claims_issuer_key.json": jws(irrev, other, kid=demo_pub),
        "vl_mut_alg_none.json": jws(irrev, sk, alg="none"),
    }
    t = records["vl_pass_irreversible.json"]
    records["vl_mut_payload_swapped.json"] = dict(t, payload=records["vl_mut_edited_note.json"]["payload"])

    # related_claims: the demo issuer's outer proof references an invinoveritas inner proof (cross-issuer, --inner-profile)
    inner_payload = json.loads(json.load(open(INV_INNER))["content"])
    claims = json.load(open(INV_CLAIMS))
    rc = dict(base, artifact_type="api_call", source_class="issuer_observed", decision_id="ex-0002",
              related_claims_hash="sha256:" + hashlib.sha256(jcs(claims)).hexdigest(),
              related_claims_result="matched", related_claims_comparison_version="related-claims-eq-v1",
              related_decision_ref=inner_payload["decision_ref"])
    rc[MEMBER] = sorted(k for k in rc if k != MEMBER)
    records["rc_outer_matched.json"] = jws(rc, sk)
    records["rc_mut_outer_says_mismatched.json"] = jws(dict(rc, related_claims_result="mismatched"), sk)
    records["rc_mut_outer_wrong_ref.json"] = jws(dict(rc, related_decision_ref="sha256:" + "0" * 64), sk)

    out = os.path.join(HERE, "records")
    os.makedirs(out, exist_ok=True)
    for name, rec in records.items():
        with open(os.path.join(out, name), "w") as f:
            json.dump(rec, f, indent=1, sort_keys=True)
            f.write("\n")
    with open(os.path.join(HERE, "example-issuer.profile.json"), "w") as f:
        json.dump(profile, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {len(records)} records, demo key {demo_pub}; stdlib Ed25519 agrees with cryptography on 96 checks")


if __name__ == "__main__":
    main()
