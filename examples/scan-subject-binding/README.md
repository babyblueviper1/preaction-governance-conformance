# scan-subject-binding

A signed, replayable RAG decision can pass every integrity check and still rest on poisoned data. What does a clean poisoning scan establish about the data a decision *actually consumed*?

- **c0**: corpus B is corpus A plus one inserted document. Signatures, Merkle roots and exact replay all verify for both, and the answer flips from `10000 USD` to `1000000 USD`. PROVENANCE VERIFIED != POISONING ABSENT.
- **c1 / c1b**: a clean scan computed over root(A) is carried next to root(B). A verifier that reads only `poisoning_scan.result` returns VALID. This is the shape of Agent Manifest v0.2 §3.2.5 at [`0a2513df`](https://github.com/agentrust-io/agent-manifest/blob/0a2513df6c84d1c35599c9f7b8bdf976f11746bf/spec/agent-manifest-spec-v0.2.md), where `poisoning_scan` = {scanner_version, scanned_at, result} carries no digest of what was scanned, and `_verify.py` branches on `result` only. A subject-bound verifier returns CANNOT_ESTABLISH.
- **c2**: the scan names the consumed effective-dataset digest, so the result is NO_FINDING and the decision recomputes exactly.
- **c3 / c3b**: the scan names the corpus root and the decision consumed a subset. With RFC 9162 inclusion proofs for every consumed leaf the result is NO_FINDING; without them it is CANNOT_ESTABLISH.

NO_FINDING means "this named scanner found nothing in this named subject". It is never POISONING_ABSENT, which matches the reading Agent Manifest itself requires of a clean scan.

```
python3 check.py            # 6/6 cases match, exit 0 (needs: cryptography)
python3 build.py            # regenerates vectors.json byte-identically
```

`check.py` imports nothing from `build.py`: it recomputes every root, signature, inclusion proof and answer from the vector bytes. Mutation controls: zeroing one inclusion-path node flips c3 to CANNOT_ESTABLISH, and editing a signed manifest field fails the signature check.

The Merkle construction is Agent Manifest §3.2.5.1. The signing key is a public test key derived from a fixed seed. Built with Pavlo (recompute-kit / receiptos) as the first executable witness for the effective-dataset subject-binding case. Proposed upstream fix: a required `poisoning_scan.subject_digest`, compared to `merkle_root` (or to the consumed effective dataset).
