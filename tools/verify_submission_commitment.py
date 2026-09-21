#!/usr/bin/env python3
"""Offline verifier for a submission_commitment v0 object (eth-magicians t/29563, chugarchugarr #13/#15).

    python3 tools/verify_submission_commitment.py COMMITMENT.json [EXPECTED_REQUEST_DIGEST_HEX]

Stdlib only (reuses the schnorr_verify already in _bip340_nostr.py -- no network, no pip install). Prints one of
PASS / FAIL and, on PASS, the submission_commitment_ref a provider's admission receipt would bind to. Exit 0 on
PASS, 1 on FAIL.

What this proves: the object is well-formed and was signed by the stated requester_pubkey, and (when an expected
digest is given) it commits to exactly that submission. What it does NOT prove: that any provider ever admitted,
reviewed, or resolved the request -- a submission_commitment is requester-side evidence of an attempt only, and
stays meaningful even when no receipt from a provider exists at all.
"""
import hashlib
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _bip340_nostr import schnorr_verify  # noqa: E402

TYPE, VERSION = "submission_commitment", "v0"
BODY_FIELDS = ("type", "version", "request_digest", "attempt_id", "sent_at", "requester_pubkey")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX128 = re.compile(r"^[0-9a-f]{128}$")
_ATTEMPT = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")
MAX_FUTURE_SKEW_S = 300


def _canon(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signing_message(obj):
    return hashlib.sha256(_canon({k: obj.get(k) for k in BODY_FIELDS})).digest()


def commitment_ref(obj):
    return hashlib.sha256(_canon({**{k: obj.get(k) for k in BODY_FIELDS}, "sig": obj.get("sig")})).hexdigest()


def verify(obj, expected_request_digest=None, now=None):
    if not isinstance(obj, dict):
        return False, "not_an_object", None
    extra = set(obj) - set(BODY_FIELDS) - {"sig"}
    if extra:
        return False, "unknown_fields:" + ",".join(sorted(extra)), None
    if obj.get("type") != TYPE or obj.get("version") != VERSION:
        return False, "wrong_type_or_version", None
    if not (isinstance(obj.get("request_digest"), str) and _HEX64.match(obj["request_digest"])):
        return False, "bad_request_digest", None
    if not (isinstance(obj.get("attempt_id"), str) and _ATTEMPT.match(obj["attempt_id"])):
        return False, "bad_attempt_id", None
    if not (isinstance(obj.get("sent_at"), int) and not isinstance(obj["sent_at"], bool) and obj["sent_at"] > 0):
        return False, "bad_sent_at", None
    if not (isinstance(obj.get("requester_pubkey"), str) and _HEX64.match(obj["requester_pubkey"])):
        return False, "bad_requester_pubkey", None
    if not (isinstance(obj.get("sig"), str) and _HEX128.match(obj["sig"])):
        return False, "bad_sig_format", None
    if expected_request_digest is not None and obj["request_digest"] != expected_request_digest:
        return False, "request_digest_mismatch", None
    if obj["sent_at"] > (time.time() if now is None else now) + MAX_FUTURE_SKEW_S:
        return False, "sent_at_in_the_future", None
    try:
        ok = schnorr_verify(signing_message(obj), bytes.fromhex(obj["requester_pubkey"]), bytes.fromhex(obj["sig"]))
    except Exception:
        ok = False
    if not ok:
        return False, "bad_signature", None
    return True, None, commitment_ref(obj)


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 64
    obj = json.load(open(argv[1]))
    expected = argv[2] if len(argv) == 3 else None
    ok, reason, ref = verify(obj, expected)
    if ok:
        print(f"PASS submission_commitment verifies (signed by {obj['requester_pubkey']})")
        print(f"     submission_commitment_ref = {ref}")
        print("     Proves attempted submission only -- not admission, not a verdict.")
        return 0
    print(f"FAIL {reason}")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
