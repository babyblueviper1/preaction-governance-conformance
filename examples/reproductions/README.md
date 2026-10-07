# Independent reproductions

Third-party vector sets that we have run cold from the exact pinned commit, on our own machine, with the authors' own verifier.
Each folder has a `reproduce.sh` that anyone can rerun, and the transcript of our run. A reproduction confirms that the published
verdicts come out of the published code at that commit. It is not a review of the specification the vectors encode.

| set | pin | result | date |
|---|---|---|---|
| [argentum-core delegation-chain-ref: mid-hop-revocation + partial-chain-recovery](argentum-delegation-chain-ref-978294f) (giskard09/argentum-core#123) | `978294f` | 4/4 + 5/5, both `vectors.json` rebuild byte-identical, `pytest tests/` 222 passed / 4 skipped | 2026-10-07 · recorded upstream in `provenance.independently_reproduced_by` ([argentum-core#126](https://github.com/giskard09/argentum-core/pull/126)); root `rfc8785` gap it surfaced fixed in [#125](https://github.com/giskard09/argentum-core/pull/125) |
