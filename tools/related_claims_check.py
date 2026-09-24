#!/usr/bin/env python3
"""Check a v20 `related_claims` comparison offline, stdlib only (no pip install).

    python3 tools/related_claims_check.py OUTER_EVENT.json INNER_EVENT.json CLAIMS.json
    python3 tools/related_claims_check.py OUTER_EVENT.json - CLAIMS.json      # inner proof not available
    python3 tools/related_claims_check.py --referenced-set-is-complete OUTER_EVENT.json - CLAIMS.json

--referenced-set-is-complete: the caller DECLARES that the proofs it holds are its complete set, so a referenced proof it does not
hold is a policy refusal (FAIL), not an absence. Default (flag absent): a proof the relying party does not hold is CANNOT_ESTABLISH,
because failing would assert something about the artifact that was never checked (x402-foundation/tsc#4; same split as
cryptovalid-opencore's keys_are_complete).

OUTER/INNER are full signed Nostr events ({id,pubkey,created_at,kind,tags,content,sig}); CLAIMS is the exact JSON
object the caller sent as `related_claims`. Every line is one of PASS / FAIL / CANNOT_ESTABLISH (an unrunnable check is
never a pass). Exit code: 1 if any FAIL, else 2 if any CANNOT_ESTABLISH, else 0.

What it establishes (agentrust-io/trace-spec#398, issuer-specific prototype -- no core TRACE field):
  * the outer proof's signed boundary carries related_claims_hash, related_claims_comparison_version and
    related_claims_result, and they are inside decision_ref's declared preimage;
  * sha256(RFC 8785 JCS(CLAIMS)) equals the bound hash (which claims were compared is committed);
  * recomputing the comparison yourself -- exact, type-strict equality of every supplied key against the referenced
    proof's own signed payload -- gives the recorded result; a missing or unverifiable proof is distinguished from a
    mismatch and from claims not supplied.
What it does NOT establish: that the referenced verdict is relevant to, authorizes, or is true of the outer call.
Exact equality means the restatement is faithful, nothing more.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _bip340_nostr import verify_proof  # noqa: E402

PASS, FAIL, CANNOT = "PASS", "FAIL", "CANNOT_ESTABLISH"
ALLOWED_KEYS = ("artifact_hash", "verdict", "verified_at", "policy_version", "decision_ref")
RESULTS = ("not_supplied", "missing_proof", "unverifiable_proof", "matched", "mismatched")
KNOWN_COMPARISON_VERSIONS = ("related-claims-eq-v1",)
NEW_FIELDS = ("related_claims_hash", "related_claims_result", "related_claims_comparison_version")


def jcs_dumps(claims):
    """RFC 8785 for the claims grammar: an object of printable-ASCII strings and safe integers. Anything else cannot be
    canonicalized by this stdlib checker and is reported CANNOT_ESTABLISH rather than guessed at."""
    for k, v in claims.items():
        if isinstance(v, bool) or not isinstance(v, (str, int)):
            raise ValueError(f"{k}: only string/integer values are in the grammar")
        if isinstance(v, str) and not all(0x20 <= ord(c) < 0x7F for c in v):
            raise ValueError(f"{k}: non-printable-ASCII string, outside this checker's canonicalizer")
        if isinstance(v, int) and abs(v) > 2 ** 53 - 1:
            raise ValueError(f"{k}: integer outside the JSON-safe range")
    return json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def expected_result(claims, inner_payload):
    ok = all(k in inner_payload and inner_payload[k] == v and type(inner_payload[k]) is type(v)
             for k, v in claims.items())
    return "matched" if ok else "mismatched"


def check(outer_ev, inner_ev, claims):
    out = []
    def add(status, name, detail=""):
        out.append((status, name, detail))

    ov = verify_proof(outer_ev)
    add(PASS if ov["valid"] else FAIL, "outer proof valid (id, schnorr, issuer, kind)")
    op = ov.get("proof_payload") or {}
    declared = op.get("decision_ref_preimage_fields") or []
    if not all(f in declared for f in NEW_FIELDS):
        add(CANNOT, "outer proof declares the v20 related_claims_* preimage fields",
            f"policy_version={op.get('policy_version')} does not carry them; nothing to check")
        return out
    add(PASS, "outer proof declares related_claims_hash / _result / _comparison_version in decision_ref's preimage")
    result = op.get("related_claims_result")
    add(PASS if result in RESULTS else FAIL, "recorded result is one of the five defined states", str(result))

    if claims is None:
        add(PASS if (result == "not_supplied" and op.get("related_claims_hash") is None) else FAIL,
            "no CLAIMS file: proof must say not_supplied with no claims hash")
        return out

    bad = [k for k in claims if k not in ALLOWED_KEYS] if isinstance(claims, dict) else ["<not an object>"]
    if bad or not claims:
        add(FAIL, "claims object is inside the grammar (non-empty subset of the five keys)", str(bad))
        return out
    add(PASS, "claims object is inside the grammar")
    try:
        h = "sha256:" + hashlib.sha256(jcs_dumps(claims)).hexdigest()
    except ValueError as exc:
        add(CANNOT, "sha256(JCS(claims)) == related_claims_hash", str(exc))
        h = None
    if h is not None:
        add(PASS if h == op.get("related_claims_hash") else FAIL, "sha256(JCS(claims)) == related_claims_hash")
    cv = op.get("related_claims_comparison_version")
    add(PASS if cv in KNOWN_COMPARISON_VERSIONS else CANNOT, "comparison version is one this checker implements", str(cv))
    if cv not in KNOWN_COMPARISON_VERSIONS:
        return out

    if result == "missing_proof":
        add(PASS if op.get("related_decision_ref") is None else FAIL,
            "missing_proof: no related_decision_ref bound (nothing was referenced)")
        return out
    if result == "unverifiable_proof":
        add(PASS if op.get("related_decision_ref") is None else FAIL,
            "unverifiable_proof: no related_decision_ref bound (the referenced proof did not verify)")
        # The signature authenticates the ISSUER'S assertion that the referenced proof did not verify; without the inner event nobody
        # can reproduce that, so it is CANNOT_ESTABLISH, exactly like the matched path (agentrust-io/trace-spec#398, imran-siddique).
        if inner_ev is None:
            if COMPLETE:
                add(FAIL, "referenced proof is in the relying party's set", "not held, and the set was declared complete (policy refusal)")
            else:
                add(CANNOT, "the referenced proof really does fail verification", "inner event not supplied (pass it instead of '-')")
            return out
        add(PASS if not verify_proof(inner_ev)["valid"] else FAIL,
            "the supplied inner event really does fail verification")
        return out
    if result not in ("matched", "mismatched"):
        add(FAIL, "claims were supplied but the recorded result is not a comparison outcome", str(result))
        return out

    if inner_ev is None:
        if COMPLETE:
            add(FAIL, "referenced proof is in the relying party's set", "not held, and the set was declared complete (policy refusal)")
        else:
            add(CANNOT, "recompute the comparison", "inner event not supplied (pass it instead of '-')")
        return out
    iv = verify_proof(inner_ev)
    add(PASS if iv["valid"] else FAIL, "inner proof valid (id, schnorr, issuer, kind)")
    ip = iv.get("proof_payload") or {}
    add(PASS if op.get("related_decision_ref") == ip.get("decision_ref") else FAIL,
        "outer.related_decision_ref == inner.decision_ref (referenced proof identity)")
    exp = expected_result(claims, ip)
    add(PASS if exp == result else FAIL, f"recomputed comparison == recorded result", f"recomputed={exp} recorded={result}")
    return out


COMPLETE = False


def main(argv):
    global COMPLETE
    if "--referenced-set-is-complete" in argv:
        COMPLETE = True
        argv = [a for a in argv if a != "--referenced-set-is-complete"]
    if len(argv) != 4:
        print(__doc__)
        return 2
    outer = json.load(open(argv[1]))
    inner = None if argv[2] == "-" else json.load(open(argv[2]))
    claims = json.load(open(argv[3]))
    res = check(outer, inner, claims)
    for s, n, d in res:
        print(f"{s:<17} {n}" + (f"  [{d}]" if d else ""))
    print("NOTE: exact equality establishes faithful restatement; it does not establish relevance, authorization or truth.")
    if any(s == FAIL for s, _, _ in res):
        return 1
    return 2 if any(s == CANNOT for s, _, _ in res) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
