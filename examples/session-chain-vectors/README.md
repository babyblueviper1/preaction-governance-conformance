# Session-history chain vectors (fail-closed), from a real public ledger

For microsoft/autogen#7353: an append-only, hash-chained session history must FAIL on splice, reorder, tamper and
equivocation. Truncation of the tail with no external head must return **CANNOT_ESTABLISH, never PASS**.

- `base_chain.json`: entries 255-262 of the public invinoveritas verdict ledger, verbatim (`GET https://api.babyblueviper.com/ledger/{n}`).
- `../../tools/session_chain_check.py`: stdlib checker. Chain rule: `content_hash = sha256(JCS-like JSON of record)`,
  `head_hash = sha256(content_hash + "|" + prev_head_hash)`. Exit 0 PASS / 1 FAIL / 2 CANNOT_ESTABLISH.
- `make_and_run.py`: builds 14 variants from the base and checks each against its expected result.

| vector | expected | point |
|---|---|---|
| base_with_head | PASS | consistent, and matches a head held elsewhere |
| base_no_head | CANNOT_ESTABLISH | consistent, but tail removal is invisible without an external head |
| splice_259 / reorder_258_259 / tamper_260 | FAIL | internal continuity catches these, with no head needed |
| truncate_with_later_head | FAIL | log ends at 260, head for 262 is held |
| truncate_no_head | CANNOT_ESTABLISH | the case that must not pass |
| truncate_with_older_head | PASS | but complete only up to the held head (258), and the output says so |
| equivocation | FAIL | two heads for one entry |
| writer_relinks_after_splice (no head / with head) | FAIL / FAIL | caught by the entry-number gap, then by the head |
| writer_full_rewrite_no_head | CANNOT_ESTABLISH | the writer drops, renumbers and recomputes everything: internally perfect |
| writer_full_rewrite_with_held_head (262 / 261) | FAIL / FAIL | only an externally retained head exposes it |

Of the 14 vectors, the full-rewrite ones carry the argument. When the writer controls the log, internal checks establish
nothing about completeness, and only a head someone else kept does. What the external channel buys is exactly that
head, and only for whoever retained it.
