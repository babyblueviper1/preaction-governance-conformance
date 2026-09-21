#!/usr/bin/env python3
"""Check a related_decision_ref chain offline, stdlib only (no pip install).

    python3 tools/proof_chain_check.py OUTER_EVENT.json INNER_EVENT.json

Each argument is a full signed Nostr event ({id,pubkey,created_at,kind,tags,content,sig}). Every line is one of:
    PASS              the check held
    FAIL              the check ran and the values do not match
    CANNOT_ESTABLISH  the check could not be run (e.g. the claim text is not in the recognised form). This is
                      deliberately neither PASS nor FAIL: an unparseable claim proves nothing either way.
Exit code: 1 if any FAIL, else 2 if any CANNOT_ESTABLISH, else 0.

How the claim is compared (this replaced an earlier version that tested `value in disclosed_summary`, which is a
substring test: `approve` matches inside `not_approve`, and a value matches anywhere in the text). Now the whole
`disclosed_summary` must match ONE fixed sentence grammar (re.fullmatch), each named field is captured from its own
slot, and each captured value is compared for EXACT string equality with the referenced proof's field. Text outside
the grammar (extra sentences, duplicate clauses, reordered slots, uppercase hex) makes the claim unparseable, which is
CANNOT_ESTABLISH, never a pass.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from _bip340_nostr import verify_proof  # noqa: E402  (stdlib BIP-340 + NIP-01, same logic as POST /verify-proof)

_HEX64 = r"[0-9a-f]{64}"
_TOKEN = r"[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*"
CLAIM_RE = re.compile(
    r"CLAIM: the referenced verdict \(decision_ref (sha256:" + _HEX64 + r"), nostr event id (" + _HEX64 + r")\) "
    r"recorded artifact_hash (" + _HEX64 + r"), verdict (" + _TOKEN + r"), verified_at ([0-9]+), "
    r"policy_version (" + _TOKEN + r")\. "
    r"This review covers ONLY whether the claim restates those fields of the referenced proof exactly\. "
    r"It does not assess the correctness of the referenced artifact\."
)
CLAIM_FIELDS = ("decision_ref", "event_id", "artifact_hash", "verdict", "verified_at", "policy_version")

PASS, FAIL, CANNOT = "PASS", "FAIL", "CANNOT_ESTABLISH"


def parse_claim(summary):
    """Named fields from the claim sentence, or None if the summary is not exactly that sentence."""
    m = CLAIM_RE.fullmatch(summary) if isinstance(summary, str) else None
    return dict(zip(CLAIM_FIELDS, m.groups())) if m else None


def compare_claim(outer_payload, inner_payload, inner_event_id):
    """Field-by-field, exact-equality comparison of the outer claim against the referenced (inner) proof."""
    out = []
    claim = parse_claim(outer_payload.get("disclosed_summary"))
    if claim is None:
        return [(CANNOT, "claim parses as the recognised CLAIM sentence",
                 "disclosed_summary is not exactly the fixed claim grammar; no field can be compared")]
    expected = {
        "decision_ref": inner_payload.get("decision_ref"),
        "event_id": inner_event_id,
        "artifact_hash": inner_payload.get("artifact_hash"),
        "verdict": inner_payload.get("verdict"),
        "verified_at": str(inner_payload.get("verified_at")),
        "policy_version": inner_payload.get("policy_version"),
    }
    for f in CLAIM_FIELDS:
        got, want = claim[f], expected[f]
        out.append((PASS if got == want else FAIL, f"claim {f} == inner {f}",
                    "" if got == want else f"claim says {got!r}, referenced proof has {want!r}"))
    return out


def check_label(payload):
    """The context_provenance label is derived from related_decision_ref and sits OUTSIDE the signed hash; report
    a mismatch as inconsistency with the signed reference. This finds a mismatch, never its cause."""
    label, ref = payload.get("context_provenance"), payload.get("related_decision_ref")
    derived = "bound_to_verified_decision_ref" if ref is not None else "caller_asserted_unverified"
    name = "outer.context_provenance consistent with the signed related_decision_ref"
    if label == derived:
        return (PASS, name, "")
    return (FAIL, name, f"label {label!r} is inconsistent with the signed reference (derived {derived!r}); "
                        f"this finds a mismatch, not its cause")


def check_chain(outer_event, inner_event):
    out = []
    ov, iv = verify_proof(outer_event), verify_proof(inner_event)
    out.append((PASS if ov["valid"] else FAIL, "outer proof valid (id, schnorr, issuer)", "" if ov["valid"] else str(ov.get("checks"))))
    out.append((PASS if iv["valid"] else FAIL, "inner proof valid (id, schnorr, issuer)", "" if iv["valid"] else str(iv.get("checks"))))
    op, ip = ov.get("proof_payload"), iv.get("proof_payload")
    if not isinstance(op, dict) or not isinstance(ip, dict):
        return out + [(CANNOT, "payloads readable", "an event's content is not a JSON object")]
    ref = op.get("related_decision_ref")
    if ref is None:
        out.append((CANNOT, "outer carries a related_decision_ref", "none present: there is no signed reference to chain to"))
    else:
        out.append((PASS if ref == ip.get("decision_ref") else FAIL, "outer.related_decision_ref == inner.decision_ref",
                    "" if ref == ip.get("decision_ref") else f"outer references {ref!r}, inner decision_ref is {ip.get('decision_ref')!r}"))
    out.append(check_label(op))
    if ref is not None:
        out.extend(compare_claim(op, ip, inner_event.get("id")))
    return out


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 64
    outer, inner = (json.load(open(p)) for p in argv[1:3])  # noqa: SIM115
    results = check_chain(outer, inner)
    for status, name, detail in results:
        print(f"{status:<16} {name}" + (f"  -- {detail}" if detail else ""))
    statuses = {r[0] for r in results}
    return 1 if FAIL in statuses else 2 if CANNOT in statuses else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
