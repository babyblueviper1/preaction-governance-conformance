# Work-acceptance record: clean-room verifier (draft, CC0)

An independent verifier for the work-acceptance record (`trilatic.acceptance-receipt/1.2`), written from the README of
[maximusrufus/work-acceptance-record @ d78865c](https://github.com/maximusrufus/work-acceptance-record/tree/d78865c) alone. The
reference implementation was not opened. ACP SEP #303 sec 7.4a weights this record type, discussed in x402-foundation/tsc#4.
Standard library only; Ed25519 is reused from [`../x402-receipt-private-opening`](../x402-receipt-private-opening).

```
python3 war_check.py upstream_vectors/*.json     # 5/5 agree with the upstream `expected`
python3 war_check.py proposed_vectors/*.json     # 6/6 (our expectations)
python3 lax_check.py upstream_vectors            # each lax verifier passes all 5
python3 lax_check.py proposed_vectors            # each lax verifier is caught
python3 build_extra.py                           # regenerate proposed_vectors/
```

## Result on the five upstream vectors: 5/5 agree
`upstream_vectors/` is an unmodified copy of upstream `vectors/` at d78865c (CC0 1.0).
Every field of each `expected` object is reproduced: signature, criteria hash, criteria-before-check, independence, receipt
timestamp, recomputed and stated verdict, problem and warning codes. Both RFC 3161 tokens parse. Each imprint matches what
it covers: the criteria token covers `criteria.sha256`, and 01's receipt token covers SHA-256 of the canonical receipt.

## What the five do not reach
A verifier can skip any one of five steps and still pass all five vectors (`lax_check.py upstream_vectors`):

| skipped step | why no upstream vector catches it |
|---|---|
| Ed25519 signature (step 2) | every receipt is correctly signed |
| criteria hash (step 4) | every criteria file matches |
| verdict recompute (step 6) | every stated verdict equals the recomputed one |
| criteria token time (property 2) | in every vector the token's genTime equals the receipt's own `committed_at` |
| receipt token imprint (step 5) | the one receipt token matches |

The README names `CRITERIA_HASH_MISMATCH` and `VERDICT_MISMATCH`, but no vector produces either.

## Proposed vectors 06-11 (`proposed_vectors/`, CC0; the expectations are ours)
| vector | case | key fields we expect |
|---|---|---|
| 06 | a finding edited after signing | `signature_valid: false`, `SIGNATURE_INVALID` |
| 07 | the supplied criteria file is another document | `criteria_hash: mismatch`, `CRITERIA_HASH_MISMATCH` |
| 08 | the receipt token imprints another receipt | `receipt_timestamp: imprint_mismatch` |
| 09 | signed `pass`, a required criterion `not-evaluated` | `verdict_recomputed: incomplete`, `VERDICT_MISMATCH` |
| 10 | `committed_at` 2026-03-01, but the token over the criteria hash says 2026-12-01, after the check | `criteria_committed_before_check: no` |
| 11 | a required criterion `fail` | `verdict_recomputed: fail` |

- **No re-signing needed:** 06-08 edit an upstream vector's inputs only.
- **Re-signed with our own key:** 09-11 change the signed receipt. The upstream test key is not published, so they use a **public test key** (`sha256("war-cold-test-key/invinoveritas")`, key_id `invinoveritas-test-1`) supplied in the vector's `keys` input, which is how this format identifies keys.

Each of the five lax verifiers fails at least one of 06-11.

## Resolved upstream (2026-10-17, x402-foundation/tsc#4)
Trilatic took vectors 06-11 as contributed, with credit, and ruled on the three choices below the way this checker read them:
`CRITERIA_COMMITTED_AFTER_CHECK` is a problem everywhere; a token over `criteria.sha256` makes its genTime authoritative and a
disagreeing `committed_at` is `COMMITTED_AT_MISMATCH`, while without a token the verifier falls back to `committed_at` and warns
(this checker emits `COMMITMENT_UNVERIFIED`, a placeholder name: none was given, and no vector exercises it yet); a required `fail`
gives `fail`, over `incomplete`. The checker and the proposed vectors' expectations follow those rulings.

## Points for the README (each is where this checker had to choose)
1. **`CRITERIA_COMMITTED_AFTER_CHECK`: problem or warning?** Step 7 lists it as a warning example, but vector 02 has it in
   `problem_codes`. This checker follows the vector.
2. **What decides "committed first"?** Property 2 makes the RFC 3161 token the commitment, but step 4 compares
   `criteria.committed_at`, which the checker writes into its own receipt. This checker reads the token's genTime when a
   token over `criteria.sha256` is supplied. A `committed_at` that disagrees with it is a problem (`COMMITTED_AT_MISMATCH`), and a token over other bytes is `CRITERIA_TOKEN_NOT_FOR_THESE_CRITERIA` (our name). Vector 10 is the case.
3. **A required `fail`.** The verdict rule covers `not-evaluated` and `error` but not `fail`. This checker returns `fail`, and
   `fail` over `incomplete` when both occur.
4. **Code names.** `SIGNATURE_INVALID` and a code for a receipt-token imprint mismatch are not named. This checker emits
   `SIGNATURE_INVALID` and reports the imprint only in `receipt_timestamp`.
5. **Composition (vector 06 upstream):** a counterparty acceptance that references this record by digest is the case
   [`../acceptance-record-cold`](../acceptance-record-cold) would test from the acceptance side once the charter reserves it.

## What it does not check
- **Timestamp-authority signatures.** The upstream tokens are unsigned by design, and so are ours, so only the imprint and the time are read.
- **Key status and revocation.**
- **The delivered file (step 3).** No vector supplies one, and this checker does not implement the comparison.
- **RFC 8785 number serialization.** `jcs()` covers the value types these records use and nothing more.
