#!/usr/bin/env python3
"""Build the trace-manifest-ref-v0 vectors (deterministic). Standard library + cryptography.

Shape under test: the optional signed top-level `manifest {id, digest, media_type}` proposed for TRACE v0.3
in agentrust-io/trace-spec#483. Records are TRACE v0.2 records (the fields of trace-spec
examples/signature-encoding/01) plus that object, signed embedded per v0.2 s3.2.2: Ed25519 over RFC 8785 JCS
of the record with `signature` absent, base64url without padding, key in cnf.jwk. The signing key is a PUBLIC
TEST KEY derived from a fixed seed; never use it for anything else.
"""
import base64, copy, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
from _rfc8785 import jcs

SEED = hashlib.sha256(b"trace-manifest-ref-v0 test key").digest()
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
digest = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()

# Two manifests served under the same id: the deployment the record ran under, and a later one.
M_RAN = json.dumps({"manifest_id": "urn:example:agent-manifest:payments-agent", "version": "1.4.0",
                    "tools": ["refund", "lookup_payment"], "model_id": "example-model-1"}, separators=(",", ":")).encode()
M_LATER = json.dumps({"manifest_id": "urn:example:agent-manifest:payments-agent", "version": "1.5.0",
                      "tools": ["refund", "lookup_payment", "wire_transfer"], "model_id": "example-model-1"}, separators=(",", ":")).encode()
MID = "urn:example:agent-manifest:payments-agent"

BASE = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2", "iat": 1785000000,
    "subject": "spiffe://factory.example/agent/payments/prod",
    "model": {"provider": "example-provider", "model_id": "example-model-1"},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "0" * 64},
    "policy": {"bundle_hash": "sha256:" + "a" * 64, "enforcement_mode": "enforce"},
    "data_class": "confidential",
    "build_provenance": {"slsa_level": 0, "digest": "sha256:" + "b" * 64},
    "appraisal": {"status": "affirming", "verifier": "https://verifier.example/v1"},
    "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64u(PUB)}},
}

def sign(rec):
    r = copy.deepcopy(rec); r.pop("signature", None)
    r["signature"] = b64u(KEY.sign(jcs(r).encode("utf-8")))
    return r

def with_manifest(extra=None):
    r = copy.deepcopy(BASE)
    r["manifest"] = {"id": MID, "digest": digest(M_RAN), "media_type": "application/json", **(extra or {})}
    return r

added_after = sign(BASE); added_after["manifest"] = {"id": MID, "digest": digest(M_RAN), "media_type": "application/json"}

CASES = [
    {"id": "m1-digest-matches", "record": sign(with_manifest()), "resolver": {MID: M_RAN},
     "expect": {"record": "VALID", "manifest": "ESTABLISHED"},
     "why": "the signed digest equals sha256 of the manifest bytes the verifier resolved"},
    {"id": "m2-digest-mismatch", "record": sign(with_manifest()), "resolver": {MID: M_LATER},
     "expect": {"record": "VALID", "manifest": "MISMATCH:manifest-digest-mismatch"},
     "why": "the id now resolves to a later deployment (1.5.0 adds wire_transfer); the record ran under 1.4.0"},
    {"id": "m3-mismatch-with-asserted-result", "record": sign(with_manifest({"verification_result": "verified"})),
     "resolver": {MID: M_LATER}, "expect": {"record": "VALID", "manifest": "MISMATCH:manifest-digest-mismatch"},
     "why": "the producer also wrote verification_result=verified; a verifier recomputes and does not carry it forward"},
    {"id": "m4-unresolvable", "record": sign(with_manifest()), "resolver": {},
     "expect": {"record": "VALID", "manifest": "NOT_ESTABLISHED:manifest-unresolved"},
     "why": "not a pass and not a reason to reject the record (the s3.1.2 rule 3 posture for pointers)"},
    {"id": "m5-added-after-signing", "record": added_after, "resolver": {MID: M_RAN},
     "expect": {"record": "REJECTED:signature-invalid", "manifest": "NOT_EVALUATED"},
     "why": "manifest is outside the signed bytes; s3.3 step 1 fails before any field is trusted"},
    {"id": "m6-control-no-manifest", "record": sign(BASE), "resolver": {MID: M_RAN},
     "expect": {"record": "VALID", "manifest": "NOT_ESTABLISHED:no-manifest-named"},
     "why": "a v0.2 record with no manifest object verifies exactly as today and names no deployment"},
]

if __name__ == "__main__":
    out = {"name": "trace-manifest-ref-v0", "proposal": "agentrust-io/trace-spec#483",
           "test_public_key_ed25519": PUB.hex(),
           "manifests": {"ran_1_4_0": M_RAN.decode(), "later_1_5_0": M_LATER.decode()},
           "cases": [{**c, "resolver": {k: v.decode() for k, v in c["resolver"].items()}} for c in CASES]}
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False); f.write("\n")
    print(f"wrote {len(CASES)} cases to vectors.json")
