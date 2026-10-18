# Work-acceptance record: clean-room verifier (draft, CC0)

An independent verifier for the work-acceptance record (`trilatic.acceptance-receipt/1.2`), written from the README of
[maximusrufus/work-acceptance-record @ d78865c](https://github.com/maximusrufus/work-acceptance-record/tree/d78865c) alone. The
reference implementation was not opened. ACP SEP #303 sec 7.4a weights this record type, discussed in x402-foundation/tsc#4.
Standard library only; Ed25519 is reused from [`../x402-receipt-private-opening`](../x402-receipt-private-opening).

```
python3 war_check.py upstream_vectors/*.json     # 11/11 agree with upstream `expected` (profile 1.2.1, f7d8984)
python3 war_check.py proposed_vectors/*.json     # 8/8 (06-11 now upstream; 22 and 23 are ours)
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

## Profile 1.2.1 (upstream f7d8984): 11/11 agree
`upstream_vectors/` is now an unmodified copy of upstream `vectors/` at f7d8984 (CC0 1.0), which includes 06-11. The checker uses
1.2.1's code names (`CRITERIA_TIME_MISMATCH`, `CRITERIA_TIMESTAMP_MISMATCH`, `CRITERIA_COMMITMENT_UNVERIFIED`, `CHECKER_NOT_SIGNER`,
`INDEPENDENCE_INCONSISTENT`, `CRITERIA_RESULTS_MISMATCH`, `RESULT_VOCABULARY`, `PRODUCER_UNDECLARED`) and refuses with
`{"refused": true, "reason": ...}`.

Against the ten vectors Tetsuroh Hori proposed in [aos-standard/catalog@4f6cf49](https://github.com/aos-standard/catalog/blob/4f6cf49/docs/runs/work-acceptance-record-cold/RUN.md)
(12-21, not copied here): **9/10 agree**, including his three choices (15: a criteria token over other bytes is
`CRITERIA_TIMESTAMP_MISMATCH` plus the `committed_at` fallback and its warning; 19: a result outside the vocabulary counts as not-pass;
21: the refusal shape). The one difference is 12:

- **12:** the signature envelope names `hori-cold-test-2`, the signed `receipt.key_id` names `hori-cold-test-1`. This checker verifies with
  the key the signed bytes name and requires the envelope to agree, so it reports `SIGNATURE_INVALID`. Rebuilding 12 with
  `receipt.key_id` and the envelope both naming test-2, and only `parties.checker.key_id` naming test-1, isolates `CHECKER_NOT_SIGNER`.

## Proposed vector 22: the reference time (`proposed_vectors/22-...`)
1.2.1 step 5 takes the reference time from the record's own token when it covers the record, else `issued_utc`. A covering token
only proves the record existed by its genTime, so it can be later than the check. In 22 the signed record says it checked at 12:00,
the criteria token says 12:30, and a covering record token says 13:00. Under 1.2.1 as written the record is problem-free and says
`criteria_committed_before_check: yes`, although the checker's own signed issue time is before the criteria existed. This checker
uses the **earlier** of `issued_utc` and the covering token's genTime, and 22 expects `no`. `WAR_REF_RULE=1.2.1` reproduces the profile
as written (then 21 of 22 upstream + Hori vectors agree, 12 aside, and 22 says `yes`).

## Proposed vector 23: the imprint algorithm OID
Vector 01 with the criteria token's `messageImprint.hashAlgorithm` changed from SHA-256 (`2.16.840.1.101.3.4.2.1`) to SHA-384
(`...2.2`). The two OIDs encode to the same length, so the DER structure is unchanged and the 32 imprint bytes still equal
`criteria.sha256`. A verifier that ignores the OID reports a clean match. This checker reports `CRITERIA_TIMESTAMP_MISMATCH` and falls
back to `committed_at` with `CRITERIA_COMMITMENT_UNVERIFIED`.

## What it does not check
- **Timestamp-authority signatures.** The upstream tokens are unsigned by design, and so are ours, so only the imprint and the time are read.
- **Key status and revocation.**
- **The delivered file (step 3).** No vector supplies one, and this checker does not implement the comparison.
- **RFC 8785 number serialization.** `jcs()` covers the value types these records use and nothing more.
