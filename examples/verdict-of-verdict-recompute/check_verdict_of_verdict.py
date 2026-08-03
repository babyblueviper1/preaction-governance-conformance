#!/usr/bin/env python3
"""check_verdict_of_verdict.py — does a re-review's source_class actually inherit the vantage of
the verdict it reviews, or does it mint fresh?

Follow-up to decision-ref-recompute/, on the same discussion (a2aproject/A2A#1734, giskard09): a
"verdict-of-verdict" is a /review call whose ARTIFACT is another party's already-signed verdict —
Gateway B reviewing Gateway A's proof, not Gateway A's original action. Until invinoveritas
REVIEW_POLICY_VERSION v6, source_class in that case was computed purely from the OUTER caller's
own registry status, with zero mechanical link to the INNER verdict's vantage — a chain of
agent_reported re-reviews could each independently claim independent_mediator with nothing
structurally preventing it (silent trust amplification).

v6 closes it with a min-rule bound the same way decision_ref itself is bound (recomputable, not
asserted):

    outer.source_class = "agent_reported" if (own_computed == "agent_reported"
                                               or inner.source_class == "agent_reported")
                          else "independent_mediator"

    outer.related_decision_ref = inner.decision_ref   # ONLY when inner independently verifies

This check recomputes decision_ref for 5 real, cryptographically-signed vectors (each proof's own
published preimage fields, same discipline as decision-ref-recompute/), then checks the min-rule
and the fail-closed property hold as claimed:

  inner_agent_reported                        -> agent_reported (no related verdict cited)
  inner_independent_mediator                   -> independent_mediator (no related verdict cited)
  outer_capped_by_agent_reported_inner         -> agent_reported (mediator-class caller, CAPPED
                                                   by the agent_reported inner verdict)
  outer_stays_elevated_with_mediator_inner     -> independent_mediator (mediator-class caller,
                                                   inner verdict ALSO independent_mediator — never
                                                   upgrades, but a matching inner class doesn't cap)
  outer_fails_closed_on_tampered_inner         -> agent_reported (mediator-class caller, but the
                                                   cited inner event is tampered/unverifiable —
                                                   FAILS CLOSED regardless of the caller's own
                                                   registry status)

HONEST SCOPE (stated plainly, not left implicit — same standard as decision-ref-recompute's own
disclosure of what it does and doesn't check): this recomputes hashes from published preimage
fields and checks the min-rule / fail-closed logic mechanically. It does NOT independently
recompute the schnorr signatures on the underlying Nostr events (that's `/verify-proof`'s job,
exercised in `tests/test_verdict_of_verdict_binding.py` in the invinoveritas repo itself, with
real nsec-signed events) — this example is about the DECISION_REF/source_class binding logic,
zero-dependency and offline, same scope boundary as decision-ref-recompute/.

Provenance of the 5 vectors: real calls through the actual production `build_verdict_proof()`
code path (real schnorr-signed Nostr events, real `verify_proof_event` re-verification inside the
function itself for the related_proof_event cases) — NOT hand-built JSON. The mediator-tier
vectors use a LOCALLY SIMULATED registry match ("ExampleMediator") rather than a real external
partner's live Bearer key, since using a real partner's actual credentials for a public demo
wouldn't be appropriate — everything else about the signing/verification path is the real one.

Zero-dependency, offline. Run: python3 check_verdict_of_verdict.py
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def decision_ref(fields: dict, preimage_keys) -> str:
    """sha256(JCS(projection)). JCS = sorted keys, compact separators, raw UTF-8 (RFC 8785)."""
    preimage = {k: fields.get(k) for k in preimage_keys}
    canon = json.dumps(preimage, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def check(vectors: dict) -> int:
    print("=" * 78)
    print("VERDICT-OF-VERDICT — does a re-review's source_class inherit the reviewed vantage?")
    print("=" * 78)
    ok = True

    print("\n[1/3] decision_ref recomputes from each proof's own published preimage fields:")
    for name, proof in vectors.items():
        keys = proof["decision_ref_preimage_fields"]
        got = decision_ref(proof, keys)
        match = got == proof["decision_ref"]
        print(f"  {name:42s} match={match}")
        ok &= match

    print("\n[2/3] the min-rule holds (inner vantage caps outer, never upgrades it):")
    expect_source_class = {
        "inner_agent_reported": "agent_reported",
        "inner_independent_mediator": "independent_mediator",
        "outer_capped_by_agent_reported_inner": "agent_reported",
        "outer_stays_elevated_with_mediator_inner": "independent_mediator",
        "outer_fails_closed_on_tampered_inner": "agent_reported",
    }
    for name, expected in expect_source_class.items():
        actual = vectors[name].get("source_class")
        match = actual == expected
        print(f"  {name:42s} expected={expected:20s} actual={actual:20s} {'OK' if match else 'FAIL'}")
        ok &= match

    print("\n[3/3] related_decision_ref is cryptographically bound, never a side-channel:")
    inner_ar_ref = vectors["inner_agent_reported"]["decision_ref"]
    inner_im_ref = vectors["inner_independent_mediator"]["decision_ref"]
    capped_related = vectors["outer_capped_by_agent_reported_inner"].get("related_decision_ref")
    elevated_related = vectors["outer_stays_elevated_with_mediator_inner"].get("related_decision_ref")
    failclosed_related = vectors["outer_fails_closed_on_tampered_inner"].get("related_decision_ref")
    check_a = capped_related == inner_ar_ref
    check_b = elevated_related == inner_im_ref
    check_c = failclosed_related is None
    print(f"  outer_capped.related_decision_ref == inner_agent_reported.decision_ref     : {check_a}")
    print(f"  outer_elevated.related_decision_ref == inner_mediator.decision_ref         : {check_b}")
    print(f"  outer_failclosed.related_decision_ref is None (unverified inner not bound) : {check_c}")
    ok &= check_a and check_b and check_c

    print("\nhonest-disclosure check: mediator_name only appears when source_class actually elevated")
    mn_present = {
        "inner_independent_mediator": "mediator_name" in vectors["inner_independent_mediator"],
        "outer_stays_elevated_with_mediator_inner":
            "mediator_name" in vectors["outer_stays_elevated_with_mediator_inner"],
        "outer_capped_by_agent_reported_inner":
            "mediator_name" not in vectors["outer_capped_by_agent_reported_inner"],
        "outer_fails_closed_on_tampered_inner":
            "mediator_name" not in vectors["outer_fails_closed_on_tampered_inner"],
    }
    for name, correct in mn_present.items():
        print(f"  {name:42s} {'OK' if correct else 'FAIL'}")
        ok &= correct

    print("\n" + "-" * 78)
    if ok:
        print("PASS — the min-rule holds, fails closed on a tampered inner claim, related_decision_ref")
        print("       is cryptographically bound (not a side-channel), and mediator_name never appears")
        print("       once source_class was actually capped down.")
        return 0
    print("FAIL — one or more checks above did not hold.")
    return 1


if __name__ == "__main__":
    vectors = json.loads((HERE / "vectors.json").read_text())
    sys.exit(check(vectors))
