# stillmarcus24 — malformed-input conformance set (Phase 1)

Tests the **instrument, not the receipt**: a conforming verifier must return one of the
four states (`valid` | `invalid` | `indeterminate` | `not_evaluated`) for *any* input,
including malformed input. An exception is not one of the four states — a verifier that
raises has silently opted out of the vocabulary it implements (draft-krausz-verification-state §3.1).

- `vectors.json` — 15 malformed envelopes (non-object envelope, `signatures` as string/int/
  dict/list-of-non-dict, non-string `payload`, missing members, non-object `jws`).
- `expected.json` — the conformance property per vector: must return one of the four states,
  must not raise.
- `results-tanilo-0.1.1.json` — reference results, **as-run, never edited to match**:
  `tanilo-receipt-verify==0.1.1` returns a status on **15/15**, raises on **0**
  (confirming the 0.1.0→0.1.1 fix). Any implementation that raises on these is reported as-run, failures included.
- `build_set.py` — regenerates all three files by running the reference verifier. Recompute it yourself.

CC0 1.0. Contributed to x402-foundation/tsc#4 Phase 1.

## Rebuild
Run from `corpus/phase1/` (the script resolves `stillmarcus24-malformed-input/...` relative to it): `cd corpus/phase1 && python stillmarcus24-malformed-input/build_set.py` with `tanilo-receipt-verify==0.1.1` installed. Independently rebuilt byte-identical by TKCollective (tsc#4 5843190019) and by the repo maintainer before merge.
