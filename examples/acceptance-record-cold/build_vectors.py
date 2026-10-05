#!/usr/bin/env python3
"""Builds vectors.json for tools/acceptance_record_check.py. Ed25519 keys come from FIXED seeds and Ed25519 signing is
deterministic (RFC 8032), so a rerun regenerates the file byte-identically. Needs the `cryptography` package (signing
only; the checker itself is stdlib and verifies with tools/_ed25519.py). Every expected result below is written by
hand from the condition table in x402-foundation/tsc#4 (Shodai, 2026-10-04), not read back from the checker."""
import base64, copy, hashlib, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import _rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
h = lambda s: hashlib.sha256(s.encode()).hexdigest()


def key(seed_label):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_label.encode()).digest())
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pk


ISS_SK, ISS_PK = key("acceptance-vectors/issuer")          # issued the receipt being accepted
CP_SK, CP_PK = key("acceptance-vectors/counterparty")       # the confirming party
OTHER_SK, OTHER_PK = key("acceptance-vectors/unlisted")      # a key the relying party does not hold
jwk = lambda kid, pk: {"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": b64(pk)}
JWKS = {"keys": [jwk("iss-1", ISS_PK), jwk("cp-1", CP_PK), jwk("cp-reused", ISS_PK)]}
DELEG = {"did:example:counterparty": ["cp-1"], "did:example:issuer": ["iss-1"]}
RECORD = {"issuer": "did:example:issuer", "issuer_kid": "iss-1", "record_id": "receipt-0001", "terms_sha256": h("terms v1"),
          "outcome_sha256": h("delivered: report.pdf"), "outcome_at": "2026-10-04T18:00:00.000Z"}
# A second receipt with the SAME terms and outcome (a repeat purchase of the same deliverable): only the record itself differs.
RECORD2 = {**RECORD, "record_id": "receipt-0002", "outcome_at": "2026-10-04T18:30:00.000Z"}
rd = lambda rec: hashlib.sha256(_rfc8785.jcs(rec).encode("utf-8")).hexdigest()
BODY = {"acceptance_version": "acceptance-record-v0", "confirming_party": "did:example:counterparty",
        "disposition": "accepted", "terms_sha256": RECORD["terms_sha256"], "outcome_sha256": RECORD["outcome_sha256"],
        "accepted_at": "2026-10-04T18:05:00.000Z", "accepted_record_sha256": rd(RECORD)}


def jws(body, kid="cp-1", sk=CP_SK, raw_payload=None):
    prot = b64(json.dumps({"alg": "EdDSA", "kid": kid}, sort_keys=True, separators=(",", ":")).encode())
    pay = b64(raw_payload if raw_payload is not None else json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    return {"protected": prot, "payload": pay, "signature": b64(sk.sign(f"{prot}.{pay}".encode()))}


def case(acc, record=RECORD, complete=False, deleg=DELEG):
    return {"acceptance": acc, "accepted_record": record, "trust_material": JWKS, "trust_material_complete": complete, "delegation": deleg}


def body(**kw):
    b = copy.deepcopy(BODY)
    for k, v in kw.items():
        if v is KeyError:
            b.pop(k, None)
        else:
            b[k] = v
    return b


V = []
def add(vid, c, result, conditions=(), what="", **extra):
    V.append({"id": vid, "what": what, "case": c, "expect": {"result": result, "conditions": sorted(conditions), **extra}})


add("acc-accepted-verified", case(jws(BODY)), "verified", disposition="accepted", what="well-formed, counterparty-signed, authority resolved")
add("acc-rejected-verified", case(jws(body(disposition="rejected"))), "verified", disposition="rejected",
    what="'verified' means a valid counterparty-signed record exists; the judgment (rejected) stays the counterparty's")
add("acc-disputed-verified", case(jws(body(disposition="disputed"))), "verified", disposition="disputed")
add("acc-no-record-not-responded", {"accepted_record": RECORD}, "no_record", disposition="not_responded",
    what="no acceptance record: not_responded, never a weaker accepted, never verified")
add("acc-confirming-party-absent", case(jws(body(confirming_party=KeyError))), "malformed", ["confirming_party_absent"])
add("acc-confirming-party-empty", case(jws(body(confirming_party=""))), "malformed", ["confirming_party_absent"])
add("acc-signer-is-issuer-same-kid", case(jws(BODY, kid="iss-1", sk=ISS_SK)), "malformed", ["acceptance_signer_is_issuer"],
    what="the issuer's own key signs the acceptance")
add("acc-signer-is-issuer-reused-key-new-kid", case(jws(BODY, kid="cp-reused", sk=ISS_SK)), "malformed", ["acceptance_signer_is_issuer"],
    what="the issuer's key bytes under a different kid: same key, so the condition still fires")
add("acc-signer-is-issuer-same-party", case(jws(body(confirming_party="did:example:issuer"))), "malformed", ["acceptance_signer_is_issuer"],
    what="the confirming party named is the issuer itself")
add("acc-terms-digest-mismatch", case(jws(body(terms_sha256=h("terms v2")))), "malformed", ["acceptance_terms_digest_mismatch"])
add("acc-outcome-digest-mismatch", case(jws(body(outcome_sha256=h("delivered: other.pdf")))), "malformed", ["acceptance_outcome_digest_mismatch"])
add("acc-precedes-outcome", case(jws(body(accepted_at="2026-10-04T17:59:59.999Z"))), "malformed", ["acceptance_precedes_outcome"])
add("acc-same-instant-as-outcome-ok", case(jws(body(accepted_at=RECORD["outcome_at"]))), "verified", disposition="accepted",
    what="'earlier than' is strict: an acceptance at the outcome's own instant does not precede it")
add("acc-authority-unresolved", case(jws(BODY), deleg={"did:example:issuer": ["iss-1"]}), "unknown", ["acceptance_authority_unresolved"],
    disposition="accepted", what="delegation material does not bind cp-1 to the confirming party: a limit of the verifier, not a finding")
add("acc-report-all-two-mismatches", case(jws(body(terms_sha256=h("terms v2"), accepted_at="2026-10-04T17:00:00.000Z"))), "malformed",
    ["acceptance_terms_digest_mismatch", "acceptance_precedes_outcome"], what="report-all: both conditions, compared as a set")
add("acc-illtyped-digest-suppresses-mismatch", case(jws(body(terms_sha256="not-hex"))), "malformed", ["acceptance_member_invalid"],
    what="type-check suppression: an ill-typed digest raises acceptance_member_invalid only, not a mismatch")
add("acc-signed-not-responded", case(jws(body(disposition="not_responded"))), "malformed", ["acceptance_member_invalid"],
    what="READING A2: a counterparty-signed 'not_responded' contradicts itself")
add("acc-malformed-plus-authority", case(jws(body(outcome_sha256=h("x"))), deleg={}), "malformed", ["acceptance_outcome_digest_mismatch"],
    what="a malformed finding is reported; the authority unknown is not added on top of it")
add("acc-record-digest-matches-second-receipt", case(jws(body(accepted_record_sha256=rd(RECORD2), accepted_at="2026-10-04T18:35:00.000Z")), record=RECORD2),
    "verified", disposition="accepted", what="the acceptance names receipt-0002 and is checked against receipt-0002")
add("acc-record-digest-mismatch-replayed", case(jws(body(accepted_record_sha256=rd(RECORD2), accepted_at="2026-10-04T18:35:00.000Z"))), "malformed",
    ["acceptance_record_digest_mismatch"], what="the SAME acceptance presented against receipt-0001: terms and outcome digests match, the record does not")
add("acc-record-digest-absent", case(jws(body(accepted_record_sha256=KeyError))), "malformed", ["acceptance_member_invalid"],
    what="no accepted_record_sha256 member: ill-formed, not a mismatch")
add("acc-key-unresolved", case(jws(BODY, kid="cp-9", sk=OTHER_SK)), "key_unresolved", [], key_step="key_unresolved",
    what="-03 5.4.2(a): not malformed, not a failed signature, no result")
add("acc-key-unresolved-declared-complete", case(jws(BODY, kid="cp-9", sk=OTHER_SK), complete=True), "key_unresolved", [],
    key_step="key_unresolved", policy_refusal=True, what="-03 5.4.2(b): same token, plus the relying party's refusal")
add("acc-signature-invalid", case(jws(BODY, kid="cp-1", sk=OTHER_SK)), "malformed", ["signature_invalid"], key_step="signature_invalid",
    what="-03 5.4.2(c): the key resolves and the signature fails; declaring completeness never changes this")
add("acc-signature-invalid-declared-complete", case(jws(BODY, kid="cp-1", sk=OTHER_SK), complete=True), "malformed", ["signature_invalid"],
    key_step="signature_invalid")

out = {"description": "Acceptance-record vectors for Shodai's condition set (x402-foundation/tsc#4, 2026-10-04), keys per "
       "draft-krausz-verification-state-03 5.4.2. Conditions compare as SETS. Built by build_vectors.py; CC0-1.0.",
       "vectors": V}
open(os.path.join(HERE, "vectors.json"), "w").write(json.dumps(out, indent=1, sort_keys=True) + "\n")
print(len(V), "vectors")
