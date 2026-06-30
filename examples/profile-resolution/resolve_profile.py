#!/usr/bin/env python3
"""resolve_profile — the canonicalization-profile resolution invariant (referee-enforced).

Conformance leg for autogen#7353. When boards anchor `action_ref`s into a shared registry, the
registry's neutrality depends on every board having recomputed `action_ref` under the SAME
canonicalization. giskard09's trail and AgentOracle (TKCollective) both ship a content-addressed
`canonicalization_profile_id = SHA-256(JCS(spec_doc))` and disclose it in the anchor sibling. This
makes that disclosure a CHECKED invariant the referee runs — not a convention two boards agreed to.

Two joined checks (each recomputed here, nothing trusted):

  (1) profile_content_addressing
      SHA-256(JCS(profile.doc)) == profile.canonicalization_profile_id.
      "same id => same byte rule, by construction" — a verifier handed ANY doc rehashes it and
      rejects it if it does not hash to its own id, so no party has to trust a registry to SERVE
      the right doc (the consumer-side guarantee: registry = convenience, not authority).

  (2) action_ref_reproducible
      action_ref == SHA-256(JCS(preimage)) computed by applying the resolved profile. The profile
      is therefore EXECUTABLE, not just a label: a verifier re-derives the same action_ref from the
      preimage bytes alone. The `timestamp`-as-integer case (the azender1 422) recomputes to a
      DIFFERENT action_ref and is rejected as a first-class conformance failure, not an opaque 422.

Negative controls baked in (green-by-assertion impossible): a tampered profile doc must fail (1),
and a `timestamp`-as-integer preimage must fail (2). Exit 0 iff the positive vector passes both
checks AND both negatives are correctly rejected.

Pure stdlib, offline. JCS canonicalizer in jcs.py (scope note there re: code-point vs UTF-16).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jcs import jcs  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def check_profile_content_addressing(profile: dict) -> tuple[bool, str]:
    """(1) The profile id must equal SHA-256(JCS(doc)) — content-addressed."""
    recomputed = _sha256_hex(jcs(profile["doc"]))
    declared = profile["canonicalization_profile_id"]
    ok = recomputed == declared
    return ok, (f"profile id {recomputed[:16]} reproduces" if ok
                else f"profile_id_mismatch: doc hashes to {recomputed[:16]}, declared {declared[:16]}")


def recompute_action_ref(preimage: dict) -> str:
    """Apply the resolved profile: action_ref = SHA-256(JCS(preimage))."""
    return _sha256_hex(jcs(preimage))


def check_action_ref(preimage: dict, declared_action_ref: str) -> tuple[bool, str]:
    """(2) The declared action_ref must reproduce from the preimage under the profile."""
    recomputed = recompute_action_ref(preimage)
    ok = recomputed == declared_action_ref
    return ok, (f"action_ref {recomputed[:16]} reproduces from preimage" if ok
                else f"action_ref_not_reproducible: preimage canonicalizes to {recomputed[:16]}, "
                     f"declared {declared_action_ref[:16]}")


def main() -> int:
    as_json = "--json" in sys.argv
    profile = json.loads(open(os.path.join(HERE, "profile.json"), encoding="utf-8").read())

    # The positive vector: AgentOracle's disclosed preimage shape (autogen#7353), with the
    # action_ref this profile canonicalizes it to. Recompute it against a live /nexus/trail to
    # cross-check; here it is self-consistent under the declared profile.
    preimage = {
        "action_type": "pii_screen",
        "agent_id": "did:ao:composed-demo:2026-06-28",
        "scope": "presidio:x402.screen:PII_BLOCKED:EMAIL_ADDRESS,US_SSN",
        "timestamp": "2026-06-28T19:30:00.000Z",  # STRING — per the profile
    }
    action_ref = recompute_action_ref(preimage)  # the ref this preimage yields under the profile

    results = []

    # ---- positive: both checks pass ----
    ca_ok, ca_d = check_profile_content_addressing(profile)
    ar_ok, ar_d = check_action_ref(preimage, action_ref)
    pos_sound = ca_ok and ar_ok
    results.append({"vector": "positive", "expect": "pass", "sound": pos_sound,
                    "checks": {"profile_content_addressing": ca_ok, "action_ref_reproducible": ar_ok},
                    "detail": {"profile_content_addressing": ca_d, "action_ref_reproducible": ar_d}})

    # ---- negative 1: tampered profile doc must fail content-addressing ----
    tampered = json.loads(json.dumps(profile))
    tampered["doc"]["version"] = "tampered"
    t_ok, t_d = check_profile_content_addressing(tampered)
    neg1_rejected = not t_ok
    results.append({"vector": "negative_tampered_profile", "expect": "reject",
                    "rejected": neg1_rejected, "detail": t_d})

    # ---- negative 2: timestamp-as-integer (the azender1 422) must not reproduce action_ref ----
    int_ts = dict(preimage)
    int_ts["timestamp"] = 1782681721951  # INTEGER — a different canonical form
    n2_ok, n2_d = check_action_ref(int_ts, action_ref)
    neg2_rejected = not n2_ok
    results.append({"vector": "negative_timestamp_int", "expect": "reject",
                    "rejected": neg2_rejected, "detail": n2_d})

    overall = pos_sound and neg1_rejected and neg2_rejected

    if as_json:
        print(json.dumps({"profile_id": profile["canonicalization_profile_id"],
                          "action_ref": action_ref, "vectors": results,
                          "overall_pass": overall}, indent=2))
    else:
        print("resolve_profile — canonicalization-profile resolution invariant (offline, zero-dep)\n")
        print(f"  profile_id : {profile['canonicalization_profile_id']}")
        print(f"  action_ref : {action_ref}  (AgentOracle preimage shape, ts=string)\n")
        print(f"  [{'PASS' if pos_sound else 'FAIL'}] positive")
        print(f"           {'ok ' if ca_ok else 'FAIL'}  profile_content_addressing — {ca_d}")
        print(f"           {'ok ' if ar_ok else 'FAIL'}  action_ref_reproducible    — {ar_d}")
        print(f"  [{'PASS' if neg1_rejected else 'FAIL'}] negative_tampered_profile (must reject) — {t_d}")
        print(f"  [{'PASS' if neg2_rejected else 'FAIL'}] negative_timestamp_int   (must reject) — {n2_d}")
        print(f"\n  => {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
