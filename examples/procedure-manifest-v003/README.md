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
