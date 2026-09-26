# truncation-checkpoint

A minimal, reproducible counterexample for one limitation of hash-linked logs: **links expose broken links within a supplied sequence, not truncation**. Dropping entries from the *end* leaves every remaining link valid; only a comparison with an **independently retained checkpoint** (head hash and entry count, kept outside the log's control at write time) detects it.

```
python3 check.py        # standard library only, deterministic, exit 0 iff all three cases behave as stated
```

| presented copy | links verify | matches checkpoint |
|---|---|---|
| full | yes | yes |
| tail_cut (last 3 dropped) | **yes** | **no** |
| gap (one interior entry dropped) | no | no |

Operational counterpart: on a live append-only verdict ledger, dropping an interior entry or reordering broke continuity, but dropping the last two entries verified cleanly; the truncation was caught only by comparing against a chain head broadcast to public relays at write time (mitre-atlas/atlas-data#20, comment 5840517067). Integrity verification that succeeds still does not establish that every event was recorded before signing.
