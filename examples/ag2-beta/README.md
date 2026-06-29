# AG2 Beta — external-attestation join fixture

A framework-shaped instance of the suite's `verdict_binding_failed` invariant, mapped to the
AG2 Beta governance-middleware field names (`proposed_action` / `gate_decision` /
`external_attestation` / `release_record`), per the discussion in
[ag2ai/ag2#2967](https://github.com/ag2ai/ag2/issues/2967).

**`external_attestation_intent_ref_mismatch.json`** — the *mismatched-evidence* negative:
a real, independently schnorr-signed external attestation that binds a **different**
`artifact_hash` than the proposed action's `intent_ref`. The signature is genuinely valid;
the binding is wrong.

The rule it proves:

```
external_attestation.artifact_hash != proposed_action.intent_ref
  =>  release_record.outcome == "blocked"      (independent of signature validity)
```

Mismatched evidence is a **distinct** terminal outcome from missing evidence, and it must fail
closed *before* execution. Recompute-real:

- `sha256(utf8(proposed_action.canonical_input.canonical_bytes_utf8)) == proposed_action.intent_ref`
- `external_attestation.signed_event` is a valid NIP-01 schnorr event (recompute
  `id = sha256([0,pubkey,created_at,kind,tags,content])`, schnorr-verify `sig` against `pubkey`) —
  valid, and still does not authorize release, because it binds the wrong hash.

The verifier should also *derive* the evidence mode from what it can recompute rather than trust a
producer-asserted label, which is what prevents green-by-assertion.
