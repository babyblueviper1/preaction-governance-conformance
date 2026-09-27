# scan-subject-binding

A signed, replayable RAG decision can pass every integrity check and still rest on poisoned data. What does a clean poisoning scan establish about the data a decision *actually consumed*?

- **c0**: corpus B is corpus A plus one inserted document. Signatures, Merkle roots and exact replay all verify for both, and the answer flips from `10000 USD` to `1000000 USD`. PROVENANCE VERIFIED != POISONING ABSENT.
- **c1 / c1b**: a clean scan computed over root(A) is carried next to root(B). A verifier that reads only `poisoning_scan.result` returns VALID. This is the shape of Agent Manifest v0.2 §3.2.5 at [`0a2513df`](https://github.com/agentrust-io/agent-manifest/blob/0a2513df6c84d1c35599c9f7b8bdf976f11746bf/spec/agent-manifest-spec-v0.2.md), where `poisoning_scan` = {scanner_version, scanned_at, result} carries no digest of what was scanned, and `_verify.py` branches on `result` only. A subject-bound verifier returns CANNOT_ESTABLISH.
- **c2**: the scan names the consumed effective-dataset digest, so the result is NO_FINDING and the decision recomputes exactly.
- **c3 / c3b**: the scan names the corpus root and the decision consumed a subset. With RFC 9162 inclusion proofs for every consumed leaf the result is NO_FINDING; without them it is CANNOT_ESTABLISH.

- **c3c**: same bytes as c3, but the scanner declares `corpus_statistical` semantics. A corpus-level NO_FINDING transfers to a consumed subset only when the scanner is **recordwise** (hereditary: a finding in any record is a finding in any set containing it), so the result is CANNOT_ESTABLISH.
- **c4 / c4b**: the scan names a published deterministic scanner (`toy-scan/0.1.0`), so the checker **reruns it** over the bound subject instead of trusting the signed result. c4 reproduces NO_FINDING; in c4b the signed result says clean, but the rerun finds `policy-001b`, so the verdict is CONTRADICTED while a result-only verifier still says VALID.
- **c5**: k=2. `effective_dataset_digest = root(retrieved)` sorts leaves and loses retrieval order, so this profile is frozen to k=1 (CANNOT_ESTABLISH above that; k>1 needs an ordered digest).

**Evidence grades.** A scan *assertion* is not a scan *execution*. NO_FINDING carries `AUTHENTICATED_REPORT` when the checker only verified a signed claim over a bound subject, and `REPRODUCED` only when it reran a deterministic scanner over the subject bytes.

NO_FINDING means "this named scanner reported nothing in this named subject". It is never POISONING_ABSENT, which matches the reading Agent Manifest itself requires of a clean scan; the checker's verdict vocabulary does not contain that word, and a mutant that emits it fails.

```
python3 check.py            # 10/10 cases match, exit 0 (needs: cryptography)
python3 check.py --mutants  # + 4 load-bearing mutants, each must be killed
python3 build.py            # regenerates vectors.json byte-identically
```

`check.py` imports nothing from `build.py`: it recomputes every root, signature, inclusion proof and answer from the vector bytes. Mutation controls: zeroing one inclusion-path node flips c3 to CANNOT_ESTABLISH, and editing a signed manifest field fails the signature check. `--mutants` runs four checker mutants: M1 ignores `subject_digest` and trusts `result: clean` (killed by c1/c1b, among others); M2 promotes NO_FINDING to POISONING_ABSENT (killed mechanically: outside the vocabulary); M3 ignores declared scanner semantics (killed by c3c); M4 grades a signed report as REPRODUCED (killed by c2/c3).

The Merkle construction is Agent Manifest §3.2.5.1. The signing key is a public test key derived from a fixed seed. Built with Pavlo (recompute-kit / receiptos) as the first executable witness for the effective-dataset subject-binding case. **Proposed upstream fix, kept narrow:** a required `poisoning_scan.subject_digest` that Agent Manifest compares to `rag_corpus.merkle_root`, nothing more. Binding a scan to the per-decision effective consumed set, inclusion-proof transfer, scanner semantics and evidence grading are verifier-side rules demonstrated here, not proposed as manifest fields.
