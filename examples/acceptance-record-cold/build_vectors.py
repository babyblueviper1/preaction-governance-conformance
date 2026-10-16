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


def jws(body, kid="cp-1", sk=CP_SK, raw_payload=None, hdr=None):
    prot = b64(json.dumps(hdr if hdr is not None else {"alg": "EdDSA", "kid": kid}, sort_keys=True, separators=(",", ":")).encode())
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

# One acceptance (BODY, kid cp-1, signed by the counterparty's own key) presented two ways. The existing key-step vectors
# reach their results by signing with a different key; this pair holds the signed record fixed and changes one thing each.
SAME = jws(BODY)
JWKS_NO_CP1 = {"keys": [k for k in JWKS["keys"] if k["kid"] != "cp-1"]}


def flip_sig_byte(acc, i=0):
    sig = bytearray(base64.urlsafe_b64decode(acc["signature"] + "=" * (-len(acc["signature"]) % 4)))
    sig[i] ^= 0x01
    return {**acc, "signature": b64(bytes(sig))}


add("acc-key-unresolved-valid-signature-kid-not-in-trust-material", {**case(SAME), "trust_material": JWKS_NO_CP1}, "key_unresolved", [],
    key_step="key_unresolved", what="-03 5.4.2(a): a correctly signed record whose kid (cp-1) is not in the trust material; "
    "no check ran, so this is not malformed and not a failed signature")
add("acc-signature-invalid-one-byte-flipped", case(flip_sig_byte(SAME)), "malformed", ["signature_invalid"], key_step="signature_invalid",
    what="-03 5.4.2(c): the SAME record with cp-1 resolvable and the first signature byte XOR 0x01; "
    "signature_invalid is the only condition reported")

# Sentences 5-8 (tsc#4, 2026-10-12): probes by @Tetsurohhori's fourth reader where the text was silent and the checkers enforced a rule.
add("acc-accepted-at-no-fraction", case(jws(body(accepted_at="2026-10-04T18:05:00Z"))), "malformed", ["acceptance_member_invalid"],
    what="sentence 5: a timestamp is the -03 5.3.2 form YYYY-MM-DDTHH:MM:SS.mmmZ exactly; valid RFC 3339 without the fraction is ill-typed")
add("acc-accepted-at-offset-same-instant", case(jws(body(accepted_at="2026-10-05T03:05:00.000+09:00"))), "malformed", ["acceptance_member_invalid"],
    what="sentence 5: the same instant as acc-accepted-verified written with +09:00 is ill-typed, so the ordering rule is never reached")
RECORD_NOFRAC = {**RECORD, "outcome_at": "2026-10-04T18:00:00Z"}
add("acc-outcome-at-no-fraction", case(jws(body(accepted_record_sha256=rd(RECORD_NOFRAC))), record=RECORD_NOFRAC), "malformed",
    ["acceptance_member_invalid"], what="sentence 5 applies to the supplied record's outcome_at too (members_invalid: accepted_record)")
add("acc-header-alg-not-eddsa", case(jws(BODY, hdr={"alg": "ES256", "kid": "cp-1"})), "malformed", ["acceptance_member_invalid"],
    what="sentence 6: the protected header's alg must be EdDSA; ES256 with a valid Ed25519 signature is malformed before the key step")
add("acc-header-no-kid", case(jws(BODY, hdr={"alg": "EdDSA"})), "malformed", ["acceptance_member_invalid"],
    what="sentence 6: no kid (or a non-string kid) is malformed, not key_unresolved: there is no kid to look up")
add("acc-complete-not-boolean", case(jws(BODY, kid="cp-9", sk=OTHER_SK), complete="true"), "key_unresolved", [], key_step="key_unresolved",
    policy_refusal=None, what="sentence 8: trust_material_complete is a declaration only as JSON true; the string \"true\" (or 1) is not, so no policy_refusal")

# The four README sentences under "Inputs the vectors do not yet pin" (tsc#4, 2026-10-12). Each vector changes one thing in
# acc-accepted-verified (SAME): one signed member or one envelope field, re-signed by cp-1 where the signed bytes change, or one
# trust-material key; the exceptions are noted. Expectations are written by hand from those sentences.
add("acc-extra-signed-member-ignored", case(jws(body(note="extra member, signed"))), "verified", disposition="accepted",
    what="sentence 1: a signed member other than the seven the vectors use is ignored")
add("acc-envelope-signature-padded", case({**SAME, "signature": SAME["signature"] + "=" * (-len(SAME["signature"]) % 4)}),
    "malformed", ["acceptance_member_invalid"], what="sentence 2: the same signature with base64 '=' padding is not base64url "
    "without padding (RFC 7515 2); found before the key step")
add("acc-envelope-signature-standard-alphabet", case({**SAME, "signature": SAME["signature"].replace("-", "+").replace("_", "/")}),
    "malformed", ["acceptance_member_invalid"], what="sentence 2: the same signature bytes in the standard base64 alphabet "
    "('+' for '-') are not base64url; found before the key step")


def jws_raw_protected(prot_raw, body, sk=CP_SK):
    prot = b64(prot_raw)
    pay = b64(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    return {"protected": prot, "payload": pay, "signature": b64(sk.sign(f"{prot}.{pay}".encode()))}


add("acc-envelope-protected-not-json-object", case(jws_raw_protected(b'["EdDSA","cp-1"]', BODY)), "malformed",
    ["acceptance_member_invalid"], what="sentence 2: the protected header decodes to a JSON array, not an object; found before "
    "the key step")
NOT_OBJECT = jws(None, raw_payload=b"[]")
add("acc-envelope-payload-not-json-object", case(NOT_OBJECT), "malformed", ["acceptance_member_invalid"],
    what="sentence 2: the payload is validly signed by cp-1 and decodes to a JSON array, not an object")
add("acc-envelope-payload-not-json-object-signature-invalid", case(flip_sig_byte(NOT_OBJECT)), "malformed", ["signature_invalid"],
    key_step="signature_invalid", what="README order note: a payload that decodes but is not a JSON object is found after the "
    "key step, so with the first signature byte XOR 0x01 the result is signature_invalid")
add("acc-version-absent", case(jws(body(acceptance_version=KeyError))), "malformed", ["acceptance_member_invalid"],
    what="sentence 3: acceptance_version is required")
add("acc-version-not-string", case(jws(body(acceptance_version=0))), "malformed", ["acceptance_member_invalid"],
    what="sentence 3: acceptance_version present but not a string")
add("acc-version-other-value", case(jws(body(acceptance_version="acceptance-record-v1"))), "malformed", ["acceptance_member_invalid"],
    what="sentence 3: any value other than acceptance-record-v0 is malformed, not unknown")

# Sentence 4. Small-order points (order divides 8): the identity, and a point of order 8. Under the identity key,
# R = identity and S = 0 satisfies [S]B = R + [k]A for every message.
IDENTITY = bytes([1]) + bytes(31)
ORDER8 = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")


def jwks_cp1(x):
    return {"keys": [jwk(k["kid"], x) if k["kid"] == "cp-1" else k for k in JWKS["keys"]]}


FORGED = {**SAME, "signature": b64(IDENTITY + bytes(32))}
add("acc-small-order-key-identity-forged-signature", {**case(FORGED), "trust_material": jwks_cp1(IDENTITY)}, "key_unresolved", [],
    key_step="key_unresolved", what="sentence 4: cp-1's key is the identity point and the signature is R = identity, S = 0 "
    "(two inputs change: the key and the signature); the key is not a key of the confirming party, so no check ran")
add("acc-small-order-key-identity-declared-complete", {**case(FORGED, complete=True), "trust_material": jwks_cp1(IDENTITY)},
    "key_unresolved", [], key_step="key_unresolved", policy_refusal=True,
    what="sentence 4: the previous vector with trust material declared complete: same token, plus policy_refusal (5.4.2(b))")
add("acc-small-order-key-order-8-genuine-signature", {**case(SAME), "trust_material": jwks_cp1(ORDER8)}, "key_unresolved", [],
    key_step="key_unresolved", what="sentence 4: cp-1's key replaced by a point of order 8; the record and signature are SAME")

# A small-order R under cp-1's real key. R = identity, S = k*a mod L (a = cp-1's secret scalar, k = SHA-512(R || A || M) mod L)
# satisfies [S]B = R + [k]A, and so also the cofactored equation of RFC 8032 5.1.7: it fails by the small-order-R refusal.
L = 2 ** 252 + 27742317777372353535851937790883648493
_h = hashlib.sha512(hashlib.sha256(b"acceptance-vectors/counterparty").digest()).digest()
_a = int.from_bytes(_h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
_k = int.from_bytes(hashlib.sha512(IDENTITY + CP_PK + f"{SAME['protected']}.{SAME['payload']}".encode()).digest(), "little") % L
add("acc-small-order-r-real-key", case({**SAME, "signature": b64(IDENTITY + ((_k * _a) % L).to_bytes(32, "little"))}), "malformed",
    ["signature_invalid"], key_step="signature_invalid", what="sentence 4: cp-1's real key; signature R = identity, S = k*a mod L, "
    "which passes [S]B = R + [k]A; a small-order R is signature_invalid")

# Sentence 7: confirming_party is compared byte-exact and is NOT trimmed, so a
# whitespace-only value is a party name rather than confirming_party_absent, and the
# authority step decides it. Stated at 0abf726; no vector pinned it, and a checker
# that trims scores 46/46.
add("acc-confirming-party-whitespace-only", case(jws(body(confirming_party="   "))), "unknown",
    ["acceptance_authority_unresolved"],
    what="sentence 7: whitespace only is a party name, not absent; a trimming checker calls this malformed/confirming_party_absent")

# Sentence 9: mixed-order points (a prime-order part plus a torsion part, so neither small-order nor in the prime-order
# subgroup). Whether a signature under such a key, or with such an R, verifies depends on the verification equation: the
# cofactorless [S]B = R + [k]A and the cofactored [8][S]B = [8]R + [8][k]A of RFC 8032 5.1.7 disagree whenever the torsion
# term does not vanish. Reported on x402-foundation/tsc#4 by TKCollective's measurement table (2026-10-13, case 3:
# mixed-order A and R accepted by their guard and by the library). Built on cp-1's real scalar a and the order-8 point above.
import _ed25519 as _E
_T = _E._decode(ORDER8)
assert _E._eq(_E._mul(8, _T), _E._O) and not _E.is_torsion_free(_T)
assert _E.encode(_E._mul(_a, _E._B)) == CP_PK
_MSG = f"{SAME['protected']}.{SAME['payload']}".encode()
_A_MIX = _E.encode(_E._add(_E._mul(_a, _E._B), _T))           # cp-1's key plus an order-8 torsion component
assert _E.is_mixed_order_key(_A_MIX)


def _eqs(pub, sig, reduce_k=False):
    """(cofactorless, cofactored) RFC 8032 5.1.7 results for this signature over _MSG, computed directly. RFC 8032 takes k as the full
    512-bit digest; many verifiers reduce it mod L first. With a mixed-order A the two differ (L is odd, so k and k mod L can differ
    mod 8 and the torsion term [k]T only vanishes when k = 0 mod 8): every vector below asserts BOTH conventions (TKCollective, x402
    TSC #4, 2026-10-15: the first build reduced k and so held only for reducing verifiers)."""
    A, R, S = _E._decode(pub), _E._decode(sig[:32]), int.from_bytes(sig[32:], "little")
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + _MSG).digest(), "little")
    if reduce_k:
        k %= L
    lhs, rhs = _E._mul(S, _E._B), _E._add(R, _E._mul(k, A))
    return _E._eq(lhs, rhs), _E._eq(_E._mul(8, lhs), _E._mul(8, rhs))


def _eqs_both(pub, sig):
    """The (cofactorless, cofactored) result when it is the same under full k and k mod L; asserts that it is."""
    full, red = _eqs(pub, sig), _eqs(pub, sig, reduce_k=True)
    assert full == red, f"k convention changes the result: full k {full}, k mod L {red}"
    return full


def _mixed_key_sig(want_k_mult_8):
    for i in range(4096):
        r = int.from_bytes(hashlib.sha512(b"acceptance-vectors/mixed-order nonce " + str(i).encode()).digest(), "little") % L
        R = _E.encode(_E._mul(r, _E._B))
        k = int.from_bytes(hashlib.sha512(R + _A_MIX + _MSG).digest(), "little")
        if (k % 8 == 0) == want_k_mult_8 and ((k % L) % 8 == 0) == want_k_mult_8:   # same answer under full k and k mod L
            return R + ((r + k * _a) % L).to_bytes(32, "little")
    raise SystemExit("no nonce found")


_SIG_BOTH = _mixed_key_sig(True)
_SIG_SPLIT = _mixed_key_sig(False)
assert _eqs_both(_A_MIX, _SIG_BOTH) == (True, True)       # every RFC 8032 verifier accepts it
assert _eqs_both(_A_MIX, _SIG_SPLIT) == (False, True)     # cofactored accepts, cofactorless rejects
add("acc-mixed-order-key-accepted-by-both-equations", {**case({**SAME, "signature": b64(_SIG_BOTH)}), "trust_material": jwks_cp1(_A_MIX)},
    "key_unresolved", [], key_step="key_unresolved",
    what="sentence 9: cp-1's key plus an order-8 torsion point (mixed-order); the signature satisfies both the cofactorless and "
    "the cofactored equation (k divisible by 8), so a plain RFC 8032 verifier accepts it; a mixed-order key is not a key of the "
    "confirming party")
add("acc-mixed-order-key-equations-disagree", {**case({**SAME, "signature": b64(_SIG_SPLIT)}), "trust_material": jwks_cp1(_A_MIX)},
    "key_unresolved", [], key_step="key_unresolved",
    what="sentence 9: the same mixed-order key; this signature satisfies the cofactored equation and fails the cofactorless one, "
    "so two conforming RFC 8032 verifiers disagree on it; the key step decides it before any equation is used")
_r3 = int.from_bytes(hashlib.sha512(b"acceptance-vectors/mixed-order R").digest(), "little") % L
_R3 = _E.encode(_E._add(_E._mul(_r3, _E._B), _T))
_k3 = int.from_bytes(hashlib.sha512(_R3 + CP_PK + _MSG).digest(), "little") % L
_SIG_R3 = _R3 + ((_r3 + _k3 * _a) % L).to_bytes(32, "little")
assert _eqs_both(CP_PK, _SIG_R3) == (False, True)         # cofactored accepts a mixed-order R; cofactorless rejects
add("acc-mixed-order-r-real-key", case({**SAME, "signature": b64(_SIG_R3)}), "malformed", ["signature_invalid"],
    key_step="signature_invalid",
    what="sentence 9: cp-1's real key; R = [r]B plus an order-8 torsion point, S = r + k*a: the cofactored equation accepts it, "
    "the cofactorless one rejects it; a mixed-order R is signature_invalid")

# Four rules the README states that no vector pinned: a checker that broke any one of them still scored 50/50. Found by
# mutating an independent checker (actaseal/x402-acceptance-check-cold) and asking the corpus which mutants it kills.
add("acc-terms-digest-uppercase-hex", case(jws(body(terms_sha256=RECORD["terms_sha256"].upper()))), "malformed",
    ["acceptance_member_invalid"],
    what="sentence 2: a *_sha256 member is exactly 64 LOWERCASE hex characters; the same digest in upper case is ill-typed, "
    "and the mismatch it would otherwise cause is suppressed")
add("acc-accepted-at-six-fraction-digits", case(jws(body(accepted_at="2026-10-04T18:05:00.000000Z"))), "malformed",
    ["acceptance_member_invalid"],
    what="sentence 5: three fractional digits exactly; six digits naming the same instant is another spelling, so ill-typed")
add("acc-signer-is-issuer-by-delegation",
    case(jws(BODY), deleg={"did:example:counterparty": ["cp-1"], "did:example:issuer": ["iss-1", "cp-1"]}), "malformed",
    ["acceptance_signer_is_issuer"],
    what="A5 third reading: the delegation material also binds the signing kid (cp-1) to the issuer, so the signer is the "
    "issuer even though the key bytes and the confirming party differ")
RECORD_NA = {**RECORD, "record_id": "re\u0301ceipt-0003 \u00e9t\u00e9", "outcome_at": "2026-10-04T18:40:00.000Z"}
add("acc-record-digest-non-ascii-verified",
    case(jws(body(accepted_record_sha256=rd(RECORD_NA), accepted_at="2026-10-04T18:45:00.000Z")), record=RECORD_NA),
    "verified", disposition="accepted",
    what="A8: the record digest is over RFC 8785 bytes, where non-ASCII strings are written as UTF-8, not as \\u escapes; "
    "a checker that escapes them computes a different digest and reports a mismatch")

out = {"description": "Acceptance-record vectors for Shodai's condition set (x402-foundation/tsc#4, 2026-10-04), keys per "
       "draft-krausz-verification-state-03 5.4.2. Conditions compare as SETS. Built by build_vectors.py; CC0-1.0.",
       "vectors": V}
open(os.path.join(HERE, "vectors.json"), "w").write(json.dumps(out, indent=1, sort_keys=True) + "\n")
print(len(V), "vectors")
