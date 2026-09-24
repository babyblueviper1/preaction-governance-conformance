# Phase 1 corpus (x402-foundation/tsc#4): CC0

Everything under `corpus/` is dedicated to the public domain under CC0 1.0 (`corpus/LICENSE`). This is separate from the
rest of this repository's license. Contributions are accepted only under CC0.

Layout, one directory per contributor set, never edited by anyone but its author:

    corpus/phase1/<contributor>-<set>/
        README.md       what the vectors test, which draft section, how they were built (from text / from code)
        vectors/        inputs, one file per case
        expected.json   {case: expected state, reason}. States use the draft's vocabulary; an exception is never an expected state

Rules:
- An implementation's result against the corpus is reported, failures included, never edited to match.
- A vector's expected state cites the draft text it relies on. Where the text is ambiguous, the vector is marked
  `ambiguous: <finding>` rather than choosing a side.
- If the TSC prefers a foundation-owned repository, this directory moves there as-is, history included.

Current sets:
- `../examples/evidence-set-cold/`: draft-krausz-verification-state-02 §5.3/§5.4.1 cold build (payload + content bytes;
  evidence_root fad3cd3f… independently matched by the rev 8 fixture generator).
