#!/usr/bin/env python3
"""Check a proof's `vantage_limitation` offline, stdlib only (no pip install).

    python3 tools/vantage_limitation_check.py EVENT.json [EVENT.json ...]

Each EVENT is a full signed Nostr event ({id,pubkey,created_at,kind,tags,content,sig}) issued by invinoveritas.
Lines are PASS / FAIL / CANNOT_ESTABLISH. Exit code: 1 if any FAIL, else 2 if any CANNOT_ESTABLISH, else 0.

The note is a pure function of three fields already inside the signed decision_ref preimage:
    vantage_limitation = NOTE[policy_version][source_class]   if artifact_type is irreversible-class
                         null                                  otherwise
tools/vantage_notes_by_policy.json is the per-policy-version table of exact strings (v19, v20 archived; v21 current). A
policy version not in the table cannot be checked for exact wording (CANNOT_ESTABLISH), only for presence/absence.

What passing means (agentrust-io/trace-spec#397): the note is consistent with the signed fields and was not stripped or
edited after issuance (it is inside decision_ref, so changing it also breaks the id and the signature). What it does
NOT mean: that source_class is TRUE, or that the governed action could not bypass the check. The v20 notes say so.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from _bip340_nostr import verify_proof  # noqa: E402

PASS, FAIL, CANNOT = "PASS", "FAIL", "CANNOT_ESTABLISH"
TABLE = json.load(open(os.path.join(HERE, "vantage_notes_by_policy.json"), encoding="utf-8"))


def check(event):
    out = []
    def add(s, n, d=""):
        out.append((s, n, d))
    v = verify_proof(event)
    add(PASS if v["valid"] else FAIL, "proof valid (id, schnorr, issuer, kind)")
    p = v.get("proof_payload") or {}
    pv, sc, at = p.get("policy_version"), p.get("source_class"), p.get("artifact_type")
    presented = p.get("vantage_limitation")
    irreversible = at in TABLE["irreversible_artifact_types"]
    declared = p.get("decision_ref_preimage_fields") or []
    add(PASS if "vantage_limitation" in declared else FAIL, "vantage_limitation is inside the declared decision_ref preimage")
    if not irreversible:
        add(PASS if presented is None else FAIL, f"artifact_type={at} is not irreversible-class: note must be absent")
        return out
    add(PASS if presented is not None else FAIL, f"artifact_type={at} is irreversible-class: note must be present")
    table = TABLE["policies"].get(pv)
    if table is None:
        add(CANNOT, f"exact wording for policy_version={pv}", "not in the note table; presence/absence checked only")
        return out
    expected = table.get(sc)
    if expected is None:
        add(FAIL, f"source_class={sc} has a defined note under {pv}")
        return out
    add(PASS if presented == expected else FAIL, f"note == NOTE[{pv}][{sc}] (exact string)")
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    worst = 0
    for path in argv[1:]:
        print(f"== {path}")
        res = check(json.load(open(path)))
        for s, n, d in res:
            print(f"{s:<17} {n}" + (f"  [{d}]" if d else ""))
        if any(s == FAIL for s, _, _ in res):
            worst = 1
        elif any(s == CANNOT for s, _, _ in res) and worst == 0:
            worst = 2
    print("NOTE: passing = consistent with the signed fields; it does not show source_class is true or that execution cannot bypass the check.")
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv))
