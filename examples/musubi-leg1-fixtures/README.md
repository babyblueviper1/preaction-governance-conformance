# MUSUBI leg-1 fixtures (CC0-1.0)

These are regression vectors for the record-to-batch leg of NENRIN MUSUBI anchor composition, from the finding in [horizon-shield#25](https://github.com/ogasurfproject-jpg/horizon-shield/issues/25). The old leg 1 accepted a listed sha256 anywhere in the batch bytes.

Every batch is derived byte-wise from the **real stamped batch** `entry63.raw` (sha256 `368f3196…`, JIDEC entry 63). The record is the **real execution** `exec_19c44a79.json`. Only the control should be accepted.

| id | expect | reason |
|---|---|---|
| L1-control-real-entry63 | accepted | — |
| L1-digest-only-under-rejected | refused | `record_not_listed_in_batch` |
| L1-digest-only-under-supersedes | refused | `record_not_listed_in_batch` |
| L1-not-json-log-line | refused | `batch_not_json` |
| L1-listed-as-kind-agreement | refused | `record_kind_mismatch` |

```
python3 gen_fixtures.py                                  # regenerate leg1_vectors.json + SHA256SUMS
python3 gen_fixtures.py --check <horizon-shield>/workers/hs-ledger/nenrin/musubi-v0
    # (PYTHONPATH=<...>/nenrin/agreement-v0): runs every vector through that tree's anchor_compose.batch_ops -> 5/5 at ce6f98be
```

The vectors are hex-embedded batch bytes, so a downstream copy can vendor `leg1_vectors.json` byte for byte and pin it with `SHA256SUMS`. This directory is the canonical copy.

License: CC0-1.0. `entry63.raw` and `exec_19c44a79.json` are the published NENRIN / MUSUBI bytes, included unchanged for reproducibility.
