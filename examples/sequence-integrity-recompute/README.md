# sequence-integrity-recompute — N artifacts over TIME

The composed-envelope example proves N signers on one artifact. This one
proves the layer above it, the gap named when that example merged: **N
artifacts in an append-only sequence** — that between two signed tree heads
nothing was reordered and nothing was dropped, and that every entry is
provably included under the newer head. Ordering and completeness recompute
from bytes; they are never asserted by whoever built the log.

## Run it

    python3 check_sequence_integrity.py

Zero dependencies (stdlib only; Ed25519 + JCS vendored, same code as the
composed-envelope example). Expected: 7 entries PASS → both STHs recompute →
7 inclusion proofs PASS → consistency PASS → then two tamper demos that
each fail visibly.

## What it recomputes (never trusts)

| Layer | Check |
|---|---|
| each entry | a real composed envelope (2 or 3 independent signers): canonical bytes recompute, every signature verifies against its issuer's own published key set |
| leaf binding | each log leaf's `envelope_hash` re-derives from the entry it claims to commit — a leaf cannot point at bytes it doesn't match |
| tree heads | Merkle root recomputed from the leaves per verification.v0.4 rev-1 §3.3 — `H(0x00‖leaf)`, `H(0x01‖l‖r)`, odd-node promotion — and each STH's Ed25519 signature verifies against the log's published key |
| inclusion | every §3.3-format proof (ordered leaf-to-root `{sibling, position}`) recomputes from its leaf to STH_2's root — entry 7's shorter proof exercises the odd-promotion rule |
| consistency | STH_1 (size 4) and STH_2 (size 7) recompute over the same ordered prefix — append-only or it fails |

## Tamper demos

- **Reorder** (entries 2↔3): both tree heads fail to recompute, every
  inclusion proof breaks — and the leaf-commit lines show exactly *which*
  positions disagree with their entries.
- **Drop** (entry 5 removed): tree size mismatches, STH_2 fails, downstream
  inclusion fails — while STH_1 (whose prefix predates the drop) still
  recomputes. **Damage localizes to where it happened**, which is the point
  of committing to a sequence rather than to a pile.

## An honest note on the consistency check

At 7 entries the checker replays the full leaf set under both heads — the
replay *is* the consistency argument, and every byte of it is committed in
this folder. Production logs too large to replay use succinct RFC 6962-style
consistency proofs; that changes the proof's size, not what is being proven.
This example pins the invariant; the succinct form is an optimization of it.

## Provenance (stated, not discovered)

- Entries are the seven published **accept vectors** of the
  verification.v0.3 composed conformance suite
  (github.com/TKCollective/agentoracle-receipt-spec,
  `examples/v0.3-composed/`) — **fixture-suite keys, not production keys**.
  The same vector set was independently reimplemented byte-identical by a
  second team (giskard09/argentum-core PR #33).
- The log key is a fixture key, published in `log/jwks-log.json` and named
  as such. Signed tree heads follow the shape of the AgentOracle
  transparency-log design (CT-for-agent-actions); the log itself is
  roadmap, this example is its verification contract.
- Merkle construction: verification.v0.4 rev-1 §3.3 (public RFC,
  spec repo PR #5). IETF draft-krausz-verification-state is an individual
  submission — a draft, not an adopted standard.
- `build_sequence_fixture.py` is included for transparency: it is how the
  committed fixtures were made (it needs `cryptography` to sign the fixture
  STHs). The checker never runs it and depends on nothing outside stdlib.

This addresses the suite's issue #3 shape from the artifact side: two heads
plus committed leaves make split-view and history-rewrite recomputable
failures rather than trust questions.

"Conformant" here means **recomputes** — never *we say so*.
