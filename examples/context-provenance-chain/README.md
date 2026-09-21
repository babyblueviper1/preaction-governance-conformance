# context_provenance chain: full events, strict checker, negative cases

Implementation evidence for [agentrust-io/trace-spec#279](https://github.com/agentrust-io/trace-spec/issues/279),
not a proposed TRACE field. Everything here runs offline with the Python standard library.

## The three events (complete signed Nostr events, unmodified)

| file | event id | role |
|---|---|---|
| `events/inner_7aa10c97.json` | `7aa10c97…7002` | referenced proof, `related_decision_ref: null` |
| `events/outer_303c3d92_bound.json` | `303c3d92…6a31` | outer proof, `related_decision_ref` = inner `decision_ref`, label `bound_to_verified_decision_ref` |
| `events/outer_679b0a16_reference_failed_verification.json` | `679b0a16…a755` | outer proof issued when the supplied inner event failed signature verification: no `related_decision_ref`, label `caller_asserted_unverified` (the reference was not upgraded) |

`MANIFEST.sha256` holds the SHA-256 of each file. These events were also served by
`GET https://api.babyblueviper.com/verdict-proofs/{event_id}`; that store was reset on 2026-09-20T15:00:36Z (see
"Why the API returned 404" below), so this repository is the stable copy.

## Verify

```
python3 tools/proof_chain_check.py examples/context-provenance-chain/events/outer_303c3d92_bound.json \
                                   examples/context-provenance-chain/events/inner_7aa10c97.json
python3 examples/context-provenance-chain/test_chain_negative_cases.py     # 24 cases
```

Each output line is `PASS`, `FAIL`, or `CANNOT_ESTABLISH`; exit code 1 if any FAIL, else 2 if any CANNOT_ESTABLISH,
else 0. `CANNOT_ESTABLISH` is deliberately neither pass nor fail: the check could not be run.

## What the checker compares

The outer proof's `disclosed_summary` is a CLAIM restating six fields of the referenced proof. The checker requires the
**entire** summary to match one fixed sentence grammar (`re.fullmatch`), captures each named field from its own slot, and
compares each for **exact string equality** with the referenced proof's field: `decision_ref`, `event_id`,
`artifact_hash`, `verdict`, `verified_at`, `policy_version`. Text outside the grammar (extra sentences, duplicate
clauses, missing or reordered fields, uppercase hex) is `CANNOT_ESTABLISH`.

This replaced an earlier version (commit `cd04615`) that tested `value in disclosed_summary`. That was a substring
test, not a field comparison: `approve` matched inside `not_approve`, `verified_at 17899033350` matched
`1789903335`, and a value matched anywhere in the text. The earlier README-level description of it as
"field-by-field" was wrong.

## Negative cases (`test_chain_negative_cases.py`)

- **Changed value**, one field at a time (verdict, artifact_hash, verified_at, policy_version, decision_ref, event_id):
  exactly that field FAILs, the rest still PASS.
- **Misleading text** the substring check accepted, each asserted against both checks: `approve` vs `not_approve`;
  extra trailing digit or leading zero on `verified_at`; `policy_version …v190` vs `…v19`; event-id and artifact_hash
  values swapped between slots; correct values appended after wrong ones; a contradicting sentence appended; a
  duplicate conflicting `verdict` clause. Every one of these passes the old substring check and is rejected here.
- **Unparseable**: missing field, uppercase hex, free text only: `CANNOT_ESTABLISH`, never PASS.
- **Chain and label**: `related_decision_ref` mismatch FAILs; the failed-verification outer proof reports
  `CANNOT_ESTABLISH` for the chain and is not upgraded; a claim edited inside a signed event breaks `id_integrity`
  before any comparison; a label that disagrees with the signed reference is reported as "inconsistent with the
  signed reference" (a mismatch check, no claim about cause).
- The suite was mutation-tested: making the comparison always pass fails 12 cases, and using `search` instead of
  `fullmatch` fails 2.

## What this does not establish

The comparison shows the claim restates the referenced proof's fields exactly. It does not show the referenced verdict
supports any particular text, and the engine does not perform that support check: the reviewing model is not given the
contents of `related_proof_event`. `context_provenance` is a derived label outside the signed hash.

## Why the API returned 404

The server's `signed_events` table (and every other table in the same SQLite file) contains no rows from before
2026-09-20T15:00:36Z, and these three events were issued about 11:2xZ that day, so they were not in it when the
404s were reported. The events themselves are unchanged and verify offline (above). The cause of the reset is not
yet identified. The three events have since been re-inserted from the verified copies in this directory. See the
reply on trace-spec#279 for the mitigation.
