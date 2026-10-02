#!/usr/bin/env python3
"""check_cross_layer.py — do call_digest and action_ref actually compose across independent layers,
or do they just look like they should?

microsoft/autogen#7405 (GuardrailProvider RFC) and giskard09/argentum-core converged on two related
but distinct primitives for correlating records about one tool call:

  action_ref   = sha256(JCS({agent_id, action_type, scope, timestamp}))   -- correlates one attempt's
                 records across layers; no arguments in the preimage.
  call_digest  = sha256(JCS({tool_name, arguments}))                      -- binds what the call WAS;
                 recomputable by a layer that never sees agent_id or scope (issuecomment-5933530423).

This fixture (fixture.json) is a join test across three cases a real multi-layer guardrail chain
produces: two layers agreeing on the call but disagreeing on verdict (A), a call rewritten before
dispatch (B), and a call that never reached an inner layer at all (C, the not_reached marker shape
shipped in babyblueviper1/invinoveritas's integrations/autogen/governed_workbench.py on this same
thread). shared_context's action_ref/authorization_ref/args digests are reused verbatim from
giskard09/argentum-core's guardrail-provider-v1.fixture.json (pinned commit c277309b0d51dd3dca87d3c
7c07688a80021a467, referencing confirmed in issuecomment-5934214515) -- recomputed here from the same
preimages, not copied as opaque strings, so a break in either repo's convention would surface as a
mismatch in this check too.

Checks performed, all from bytes:
  1. action_ref / authorization_ref / original_args_digest / effective_args_digest all recompute to
     giskard09's pinned values (parity with the external fixture, re-derived not trusted).
  2. Vector A: provider_record.call_digest == gate_record.call_digest (same call, independently
     computed by two layers) while verdicts disagree -- confirms a verifier can tell "two layers
     looked at the identical call" from "two layers happened to use similar labels."
  3. Vector B: proposed_call_digest != effective_call_digest (rewrite visible at the call_digest
     layer) AND original_args_digest != effective_args_digest (rewrite visible at the args-digest
     layer too, independently) AND effective_call_digest != effective_args_digest (same args, two
     deliberately different primitives -- call_digest folds in tool_name, args_digest doesn't).
  4. Vector C: the not_reached marker carries no call_digest key at all (not a null, not an empty
     string -- absent), and the outer gate's own terminal record has a distinct, independently
     computed action_ref for the attempt it DID see.
  5. Tamper sensitivity: changing tool_name, or any single argument, moves call_digest away from
     the original -- the digest is not just a label that happens to match.

Zero-dependency, offline. Run: python3 check_cross_layer.py
"""
from __future__ import annotations

import json
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rfc8785  # noqa: E402

HERE = Path(__file__).resolve().parent


def jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(obj) -> str:
    return hashlib.sha256(jcs(obj).encode("utf-8")).hexdigest()


def call_digest(tool_name: str, arguments: dict) -> str:
    return digest({"tool_name": tool_name, "arguments": arguments})


def main() -> int:
    fx = json.loads((HERE / "fixture.json").read_text())
    ok = True

    print("=" * 72)
    print("CROSS-LAYER CALL_DIGEST VECTORS — autogen#7405 / argentum-core action_ref")
    print("=" * 72)

    # --- 1. parity with giskard09's pinned fixture ---
    ctx = fx["shared_context"]
    recomputed_action_ref = digest(ctx["intent_tuple"])
    recomputed_authorization_ref = digest(ctx["authorization_preimage"])
    recomputed_original_args_digest = digest(ctx["original_args"])
    recomputed_effective_args_digest = digest(ctx["effective_args"])

    parity_checks = [
        ("action_ref", recomputed_action_ref, ctx["action_ref"]),
        ("authorization_ref", recomputed_authorization_ref, ctx["authorization_ref"]),
        ("original_args_digest", recomputed_original_args_digest, ctx["original_args_digest"]),
        ("effective_args_digest", recomputed_effective_args_digest, ctx["effective_args_digest"]),
    ]
    print("\n-- parity with giskard09/argentum-core guardrail-provider-v1.fixture.json --")
    for name, got, want in parity_checks:
        match = got == want
        ok = ok and match
        print(f"  {'OK' if match else 'FAIL'}  {name}: {got[:16]}... "
              f"{'==' if match else '!='} {want[:16]}...")

    # --- 2. Vector A: provider approve, gate deny, same call_digest ---
    va = fx["vector_a_provider_approve_gate_deny"]
    a_call_digest = call_digest(ctx["tool_name"], ctx["effective_args"])
    a_provider_cd = va["provider_record"]["call_digest"]
    a_gate_cd = va["gate_record"]["call_digest"]

    same_call = (a_call_digest == va["call_digest"] == a_provider_cd == a_gate_cd)
    verdicts_disagree = (va["provider_record"]["verdict"] == "approve"
                          and va["gate_record"]["verdict"] == "deny")
    a_ok = same_call and verdicts_disagree and va["dispatch_allowed"] is False
    ok = ok and a_ok
    print("\n-- Vector A: provider approve / gate deny --")
    print(f"  recomputed call_digest: {a_call_digest[:16]}...")
    print(f"  {'OK' if same_call else 'FAIL'}  provider and gate independently computed the SAME "
          f"call_digest")
    print(f"  {'OK' if verdicts_disagree else 'FAIL'}  verdicts disagree (approve vs deny) on that "
          f"identical call")
    print(f"  {'OK' if a_ok else 'FAIL'}  dispatch_allowed == false (deny wins)")

    # --- 3. Vector B: rewrite ---
    vb = fx["vector_b_rewrite"]
    b_proposed = call_digest(ctx["tool_name"], ctx["original_args"])
    b_effective = call_digest(ctx["tool_name"], ctx["effective_args"])

    b_proposed_matches = b_proposed == vb["proposed_call_digest"]
    b_effective_matches = b_effective == vb["effective_call_digest"]
    rewrite_at_call_digest = b_proposed != b_effective
    rewrite_at_args_digest = ctx["original_args_digest"] != ctx["effective_args_digest"]
    distinct_primitives = b_effective != ctx["effective_args_digest"]

    b_ok = (b_proposed_matches and b_effective_matches and rewrite_at_call_digest
            and rewrite_at_args_digest and distinct_primitives)
    ok = ok and b_ok
    print("\n-- Vector B: rewrite before dispatch --")
    print(f"  {'OK' if b_proposed_matches else 'FAIL'}  proposed_call_digest recomputes")
    print(f"  {'OK' if b_effective_matches else 'FAIL'}  effective_call_digest recomputes")
    print(f"  {'OK' if rewrite_at_call_digest else 'FAIL'}  proposed != effective at the "
          f"call_digest layer")
    print(f"  {'OK' if rewrite_at_args_digest else 'FAIL'}  original != effective at giskard09's "
          f"args_digest layer (independent confirmation)")
    print(f"  {'OK' if distinct_primitives else 'FAIL'}  call_digest(effective) != "
          f"effective_args_digest (complementary, not duplicate, primitives)")

    # --- 4. Vector C: not_reached ---
    vc = fx["vector_c_not_reached"]
    c_action_ref = digest(vc["intent_tuple"])
    c_action_ref_matches = c_action_ref == vc["action_ref"]
    c_distinct_attempt = vc["action_ref"] != ctx["action_ref"]
    marker = vc["inner_not_reached_marker"]
    no_call_digest_field = "call_digest" not in marker
    marker_has_required_fields = {"provider_id", "reason"} <= set(marker.keys())
    outer_has_own_action_ref = vc["outer_terminal_record"]["action_ref"] == vc["action_ref"]

    c_ok = (c_action_ref_matches and c_distinct_attempt and no_call_digest_field
            and marker_has_required_fields and outer_has_own_action_ref)
    ok = ok and c_ok
    print("\n-- Vector C: not_reached (inner layer never saw the call) --")
    print(f"  {'OK' if c_action_ref_matches else 'FAIL'}  action_ref recomputes for the second "
          f"attempt")
    print(f"  {'OK' if c_distinct_attempt else 'FAIL'}  this is a genuinely different attempt "
          f"(distinct action_ref from Vectors A/B)")
    print(f"  {'OK' if no_call_digest_field else 'FAIL'}  not_reached marker carries NO "
          f"call_digest key (absent, not null)")
    print(f"  {'OK' if marker_has_required_fields else 'FAIL'}  marker has provider_id + reason "
          f"(babyblueviper1/invinoveritas governed_workbench.py shape)")
    print(f"  {'OK' if outer_has_own_action_ref else 'FAIL'}  outer gate's terminal record carries "
          f"its own action_ref for the attempt it DID evaluate")

    # --- 5. tamper sensitivity: a changed call must move call_digest (no silent re-attribution) ---
    print("\n-- tamper sensitivity (a changed call must change call_digest) --")
    tamper_cases = [
        ("tool_name", "db.query_v2", ctx["effective_args"]),
        ("limit", ctx["tool_name"], {**ctx["effective_args"], "limit": 101}),
        ("target", ctx["tool_name"], {**ctx["effective_args"], "target": "database_replica"}),
    ]
    tamper_ok = True
    for label, tname, targs in tamper_cases:
        moved = call_digest(tname, targs) != a_call_digest
        tamper_ok = tamper_ok and moved
        print(f"  {'OK' if moved else 'FAIL'}  changing {label} moves call_digest away from "
              f"the original")
    ok = ok and tamper_ok

    # --- 6. Vector D: RFC 8785 number canonicalization ---
    vd = fx["vector_d_number_canonicalization"]
    print("\n-- Vector D: call_digest preimage is RFC 8785 JCS (number text) --")
    d_ok = True
    n_differs = 0
    for case in vd["cases"]:
        args = json.loads(case["args_source_json"])
        canon_ok = rfc8785.jcs(args) == case["canonical_args_rfc8785"]
        dg = {m: hashlib.sha256(rfc8785.jcs({"tool_name": vd["tool_name"], m: args}).encode("utf-8")).hexdigest()
              for m in ("arguments", "tool_input")}
        dg_ok = (dg["arguments"] == case["call_digest_arguments"]
                 and dg["tool_input"] == case["call_digest_tool_input"])
        # the naive serializer must differ exactly where the fixture says it does
        naive_differs = json.dumps(args, sort_keys=True, separators=(",", ":")) != case["canonical_args_rfc8785"]
        flag_ok = naive_differs == case["python_json_dumps_differs"]
        n_differs += naive_differs
        case_ok = canon_ok and dg_ok and flag_ok
        d_ok = d_ok and case_ok
        print(f"  {'OK' if case_ok else 'FAIL'}  {case['args_source_json']} -> {case['canonical_args_rfc8785']}"
              f"{'  (json.dumps differs)' if naive_differs else ''}")
    d_ok = d_ok and n_differs > 0
    ok = ok and d_ok
    print(f"  {'OK' if n_differs else 'FAIL'}  at least one case where the default Python serializer would compute a "
          f"different call_digest ({n_differs} of {len(vd['cases'])})")

    print(f"\n{'OK' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
