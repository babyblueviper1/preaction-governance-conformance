# Pattern statement v0 (draft, 2026-11-04)

A **pattern statement** says, for one producer key and one period, what the invinoveritas work-acceptance record log shows:
how many records were issued naming that key, their verdicts, whether the producer co-signed each one, and where the log
cannot say anything (`NOT_MEASURED`). It is computed only from the daily record log files
(`invinoveritas.work-acceptance.record_log.v1`, stamped with OpenTimestamps), so anyone holding those files can recompute it.
It never claims more than the log shows: a key that was not enrolled, or a day with no file, is `NOT_MEASURED`, never a clean result.

## Input: the daily record log

One file per UTC day `D`: line 1 is a header, every further line one JCS-serialized entry.

* header: `{schema, date, cutoff, prev_root, n_enrollments, n_records, merkle_root, rules}`; `cutoff` = 00:00Z after `D`;
  `log_root = sha256(JCS(header))`; `prev_root` is the previous day's `log_root` (genesis: 64 zeros).
* lines: `{type: "enrollment", key, enrolled_at, statement, signature}` and
  `{type: "record", receipt_sha256, created_at, criteria_id, verdict, producer_key, producer_signature}`, with
  `producer_signature` = `present` | `absent` | `declined` as of the cutoff.
* `merkle_root` over `leaf = sha256(line UTF-8)`; a pair is `sha256((left_hex + right_hex) UTF-8)`; an odd last node pairs with
  itself; empty tree = `sha256("invinoveritas.work-acceptance.record_log.v1|empty")`.
* files are cumulative: day `D` lists every enrollment and enrolled-producer record created before its cutoff.

## The statement

```json
{"schema": "invinoveritas.work-acceptance.pattern_statement.v0",
 "subject_key": "did:key:z6Mk...",
 "period": {"from": "YYYY-MM-DD", "to": "YYYY-MM-DD"},
 "log": {"first_root": "<log_root of the 'from' file>", "last_root": "<log_root of the 'to' file>"},
 "measured": "measured" | "NOT_MEASURED",
 "not_measured_days": ["YYYY-MM-DD", ...],
 "enrolled_at": 1730000000 | null,
 "counts": {"records": n, "verdict": {"pass": n, "fail": n, ...},
            "producer_signature": {"present": n, "absent": n, "declined": n}},
 "decline_rate": declined / (present + declined) | null}
```

* Records counted: lines of the **`to`** file with `type = record`, `producer_key = subject_key` and `created_at` in
  `[00:00Z of from, cutoff of to)`; their states are as of the `to` file's cutoff.
* `not_measured_days`: days in the period with no file, and days whose cutoff is at or before `enrolled_at`.
* `measured` is `NOT_MEASURED` when the subject has no enrollment line in the `to` file, or every day is not measured.
* `decline_rate` is null when `present + declined` is 0 (nothing to rate yet; `absent` records are still inside their 72 h grace).

## Checking a statement (`check.py`)

1. Every file present for the period verifies on its own (`merkle_root` over its lines, `n_*` counts, `log_root`), and each
   file's `prev_root` equals the `log_root` of the day before when both are present. Failures: `LOG_ROOT_MISMATCH`,
   `LOG_CHAIN_BROKEN`.
2. `log.first_root` / `log.last_root` equal the `from` / `to` files' `log_root` (`LOG_REFERENCE_MISMATCH`).
3. Everything else is recomputed from the files and compared field by field (`STATEMENT_MISMATCH`, listing each field).

The OpenTimestamps proof of each `log_root` is checked separately (`ots verify`); `check.py` takes the roots as given.

## What it does not say

That the producer is a party distinct from the checker (identity is outside the log); anything about records issued for the key
before it enrolled (they are not in the log); whether a verdict is right (that is the record's own check).
