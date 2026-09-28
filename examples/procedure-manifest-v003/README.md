# Procedure Manifests v0.0.3: executable F1–F6 fixtures + an independent eligibility checker

For [@chugarchugarr's v0.0.3 acquisition-boundary draft](https://github.com/chugarchugarr/technocore-chat/blob/main/docs/procedure-manifest-v0.0.3-acquisition-boundary.md)
(eth-magicians [t/29563](https://ethereum-magicians.org/t/29563) #17). Section 10 says the boundary "should not merge without executable fixtures for at least" F1–F6.
These are those fixtures, plus a checker written **from the draft text alone**, so the fixtures are exercised by something other than their author.

```
python3 check.py --vectors vectors/     # 15 vectors -> ALL PASS            (stdlib only)
python3 mutation_check.py               # switch off each of C16-C21 -> each is caught by >=1 vector
python3 build.py && python3 build_real.py   # regenerate (build.py needs `coincurve` for signing only)
```

## What the checker evaluates

`eligible(o) = authorized_execution ∧ exact_request_binding ∧ unique_terminal_execution ∧ sufficient_scope`,
each term reported as `true` / `false` / `cannot_establish`. Anything short of four `true`s maps the run to `UNRESOLVED`
(Normative boundary: "If any term is false or cannot be established … map the run to UNRESOLVED").

| rule | enforced as |
|---|---|
| C16 | `dispute_id` must equal the derivation from committed dispute state, committed **before** the first claim; `run_id` derived from it |
| C17 | the claim's `request_hash` must equal `H(manifest-committed request)` |
| C18 | a claim counts only if attested by the manifest-pinned **provider** key; requester evidence never counts as admission |
| C19 | two conflicting attested terminals for one attempt → `EQUIVOCATION`, no silent choice (identical duplicates are fine) |
| C20 | attempt *k+1* is authorized only after a provider-attested `NO_RESULT` for attempt *k* |
| C21 | `observation_scope` must cover the manifest's `required_scope` (`covers_all`) |

## Vectors

| vector | expect | what it pins |
|---|---|---|
| P1–P4 | RESULT / RESULT / RESULT / UNRESOLVED | positive controls: valid run, retry after attested NO_RESULT, identical duplicate terminal, explicit TERMINAL_UNRESOLVED |
| F1 authentic double terminal | UNRESOLVED | C19 |
| F2 suppressed unfavorable result | UNRESOLVED | C20: local timeout ≠ NO_RESULT |
| F3 right slot, wrong request | UNRESOLVED | C17 (temperature 0.7 vs committed 0) |
| F4 authentic, insufficient scope | UNRESOLVED | C21 |
| F5 submission without admission | UNRESOLVED, state AUTHORIZED | §2 / C18 (commitment verified and preserved as evidence) |
| F6 namespace regeneration (+ F6b committed-after-claim) | UNRESOLVED | C16 |
| N1 claim signed by requester | UNRESOLVED | C18 |
| **R-F3 real receipt, wrong request** | UNRESOLVED, binding **false** | a **live** `/review` admission receipt (index 240, 2026-09-28) vs a manifest committing a different model pin |
| **R-P real receipt, exact request** | UNRESOLVED, binding **true** | same live receipt, exact request |
| **R-F5 real commitment, no admission** | UNRESOLVED, state AUTHORIZED | the live requester-signed commitment from #16 (2026-09-21) |

The real objects verify end to end, offline: the receipt's `receipt_hash` recomputes; the commitment's BIP-340 signature is valid;
the receipt binds that commitment by hash (`submission_commitment_ref`); its `artifact_hash` is sha256 of the exact request text.

## Encoding choices the draft leaves open (ours; change them and the vectors regenerate)

`H` = sha256 over canonical JSON (sorted keys, `(",", ":")`). `manifest_hash = H(manifest)`.
`dispute_id = H({manifest_hash, contract_id, dispute_nonce})` from committed dispute state.
`run_id = H({manifest_hash, dispute_id, requirement_id, judge_id, run_index})` (§1). `attempt_id = H({run_id, attempt_index})`,
`attempt_index < max_attempts` (§5). `request_hash = H(requirement.request)` (§3). Attestations are BIP-340 over `H(record without "attestation")`.

## Honest limits

- **Our live profile cannot pass `authorized_execution`.** `/review` has no pre-authorized run slots (no `run_id`), so the real-object
  vectors establish request binding and submission-vs-admission, and report `authorized_execution: cannot_establish`. By the draft's
  rule that means UNRESOLVED even when binding holds (R-P). Adding slot authorization to a live profile is the next step, and one we'd
  build against whatever encoding lands upstream.
- One author wrote the checker and the fixtures. The mutation check shows every rule is load-bearing, but a second, independent
  checker running these vectors is what would make them evidence.
- The real receipts' OpenTimestamps anchoring is checked elsewhere (`tools/verify_admission_chain.py` in the service repo), not here.

## Design note: slot authorization on the live `/review` profile (not built yet)

The real-object vectors stop at `authorized_execution: cannot_establish` because `/review` admits requests without a
pre-authorized slot. Here is how the live service would close that gap once the upstream encodings are settled. Nothing
below is deployed. We'll build it to whatever `run_id` / `dispute_id` / `attempt_id` encoding the spec adopts, not to the guesses above.

| v0.0.3 concept | what `/review` has today | what slot authorization adds |
|---|---|---|
| `run_id` (§1, C16) | nothing: admission is per request | an optional `slot` object on the request: `{manifest_hash, dispute_id, requirement_id, judge_id, run_index, attempt_index}`; the service derives `run_id` and `attempt_id` itself and refuses a slot whose derivation doesn't match |
| claim / admission (§4 CLAIMED, C18) | hash-chained admission receipt (`receipt_hash`), periodic Merkle + OpenTimestamps checkpoints | `run_id`, `attempt_id` and `request_hash` folded into `receipt_hash`. The key is present only when a slot was supplied, so every existing receipt recomputes byte for byte (same rule as `submission_commitment_ref`) |
| single use per attempt (§4, C19) | a replayed `submission_commitment.attempt_id` already returns `duplicate_of_admission:<n>` | the same one-admission-per-`attempt_id` rule, keyed on the derived `attempt_id` under a unique index, so a second admission for a slot is refused, not recorded |
| exact request binding (§3, C17) | `artifact_hash` = sha256 of the exact request text; the requester commitment is bound by hash | `request_hash` over the manifest's declared outcome-relevant inputs, when the caller supplies them as structured fields rather than one text blob |
| terminal record (§4 TERMINAL_RESULT / UNRESOLVED) | the signed verdict proof (BIP-340 event) | the proof carries `claim_receipt_hash`; `terminal_status` = RESULT for a verdict, UNRESOLVED for an explicit inability to rule; `output_hash` = hash of the verdict |
| ATTESTED_NO_RESULT (§4, C20) | every receipt already commits `response_deadline` and a `deadline_policy_commitment` | a provider-signed NO_RESULT once the committed deadline passes with no verdict, and only then may the next `attempt_index` be admitted. Caller-side timeouts are never accepted as NO_RESULT |
| authority scope (§7, C21) | `review_policy_version`, `artifact_type`, `vantage_limitation` in the proof | a structured `observation_scope` list in the terminal record, derived from those fields, so a manifest's `required_scope` can be checked mechanically |

Open questions to settle upstream before building: the canonical encoding for `H` and the three derivations; whether
`dispute_id` commitment evidence (the `committed_at` < first-claim rule) lives in the manifest or a separate anchored record;
and whether ATTESTED_NO_RESULT needs a trusted clock beyond the provider's own committed deadline.
