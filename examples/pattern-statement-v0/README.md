# Pattern statement v0 (draft)

What the invinoveritas work-acceptance record log shows for one producer key over one period: records issued naming the key, their
verdicts, whether the producer co-signed each, the decline rate, and every day the log cannot speak for (`NOT_MEASURED`).
Computed only from the daily, OpenTimestamps-stamped log files, so anyone holding them can recompute it. A key that never
enrolled, or a missing day, is `NOT_MEASURED`, never a clean result. Spec: [SPEC.md](SPEC.md).

```
python3 -I check.py --vector vectors/*.json        # 9/9: consistent, overstated counts, broken chain, removed line,
                                                   # un-enrolled key (honest / claimed clean), missing day, mid-period
                                                   # enrollment, a decline
python3 -I build_vectors.py                        # rebuilds vectors/ byte for byte (expected values by construction)
python3 -I check.py STATEMENT.json LOG_DAY.jsonl ...   # check a statement against the daily log files
```

Checked against the production log: `check.py` verifies all 17 published daily files (2026-10-17 .. 11-02) with no problem, and its
`log_root` equals the published index for every day. No producer has enrolled yet, so every statement today is `NOT_MEASURED`.

Draft only: no endpoint issues signed statements yet.
