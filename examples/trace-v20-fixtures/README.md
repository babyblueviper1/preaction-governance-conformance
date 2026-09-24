# TRACE prototypes: `vantage_limitation` (trace-spec#397) and `related_claims` (trace-spec#398)

Implementation evidence for an **issuer-specific, versioned prototype** (invinoveritas policy `v20`). It does **not** add a core
TRACE field; both items were scoped that way by the TRACE maintainer on the threads.

Everything here is offline and stdlib-only (`_bip340_nostr.py` is the vendored BIP-340/NIP-01 verifier). Events are real, signed by
the published invinoveritas key, issued 2026-09-24 by `POST /review` on the live endpoint.

```bash
python3 examples/trace-v20-fixtures/test_v20_negative_cases.py          # 24 negative/baseline cases
python3 tools/related_claims_check.py  examples/trace-v20-fixtures/events/outer_matched.json examples/trace-v20-fixtures/events/inner.json examples/trace-v20-fixtures/events/outer_matched_claims.json
python3 tools/vantage_limitation_check.py examples/trace-v20-fixtures/events/inner.json
```

## #397 `vantage_limitation` -- narrowed notes, per-version table, checker

`vantage_limitation = NOTE[policy_version][source_class]` if `artifact_type` is irreversible-class (`trade`, `onchain_action`,
`sanctions_screening`), else `null`. It is a pure function of three fields already inside the signed `decision_ref` preimage.
`tools/vantage_notes_by_policy.json` is the exact-string table: **v19** (archived) and **v20** (current).

What changed in v20, per the review on the thread: the `agent_reported` note no longer says it is "sufficient as standalone evidence
for a reversible action", and **every** note now says: *"This note is derived from source_class and artifact_type only: it does not
establish that the source classification is true or that execution cannot bypass this check."* The derivation checks consistency with
signed fields; it never established the classification is true or that the check was non-bypassable, and the text now says so.

The server validates exact wording under the proof's own policy version (v19 proofs against the archived v19 strings, v20 against the
new ones); versions older than the table are checked for presence/absence only and the checker reports `CANNOT_ESTABLISH` for wording.

## #398 `related_claims` -- bound comparison result, checker, vectors

A caller may send `related_claims` (a non-empty subset of `{artifact_hash, verdict, verified_at, policy_version, decision_ref}`,
string/integer values) alongside `related_proof_event`. The server re-verifies the referenced proof itself, compares every supplied
key by **exact, type-strict equality** against that proof's own signed payload, and binds into `decision_ref`:

| preimage field | value |
|---|---|
| `related_claims_hash` | `sha256:` + hex of RFC 8785 JCS of the claims object exactly as supplied (null if none) |
| `related_claims_comparison_version` | `related-claims-eq-v1` (null if no claims) |
| `related_claims_result` | `not_supplied` \| `missing_proof` \| `unverifiable_proof` \| `matched` \| `mismatched` |
| `related_decision_ref` (existing) | the referenced proof's `decision_ref`, only if it independently verified |

Missing proof, unverifiable proof, mismatch and claims-not-supplied are four distinct recorded states. A mismatch is recorded, never
dropped, and never upgrades `context_provenance`. **Exact equality establishes a faithful restatement. It does not establish that the
referenced verdict is relevant to, authorizes, or is true of the outer call.**

### Vectors (`events/`)
| file | what it is |
|---|---|
| `inner.json` | referenced verdict (`trade`, v20) |
| `outer_matched.json` (+ `_claims.json`) | all five keys equal |
| `outer_partial_matched.json` | two keys supplied, both equal (the claims hash commits *which* keys were compared) |
| `outer_mismatched.json` | `verdict` claimed as `reject`; recorded `mismatched` |
| `outer_missing_proof.json` | claims sent, no referenced proof |
| `outer_unverifiable_proof.json` + `inner_tampered.json` | referenced event edited after signing; recorded `unverifiable_proof`, no reference bound |
| `outer_not_supplied.json` | no claims |
| `inner_other.json` | a different valid verdict, for the substituted-proof case |

### Negative cases covered (`test_v20_negative_cases.py`)
Changed claims (bound hash breaks) - substituted proof (referenced identity check fails) - altered result / stripped hash, version or
result after signing (id/signature break) - a mismatch recorded as a match and the reverse (recompute catches it) - missing evidence
(`CANNOT_ESTABLISH`, never a pass) - `missing_proof` that still binds a reference - `not_supplied` carrying a claims hash - pre-v20 proof
- non-ASCII claims (outside this checker's canonicalizer) - vantage: altered/stripped/misplaced/wrong-class note, v19 vs v20 wording,
unknown policy version.

Two layers, as in `examples/context-provenance-chain`: end-to-end edits to real events, and a comparison layer with `verify_proof`
stubbed to valid (we cannot mint a validly-signed *inconsistent* proof, so the comparison logic is exercised separately).

## Honest limits
- The server, not a third party, performs the comparison at issuance; the checker re-derives it offline from the two events plus the
  claims object. The claims object itself is not carried in the proof (only its hash), so a verifier needs it from the caller.
- Nothing here shows `source_class` is true or that the governed action could not bypass the review call.
