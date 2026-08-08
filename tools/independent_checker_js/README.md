# Independent checker (JavaScript) — closing the checker-independence gap

[Rul1an's critique](https://github.com/crewAIInc/crewAI/issues/4877) against our own `/conformance`
registry, verified against our own code before responding: the registry has real per-row raw-bytes
recomputation, but only ONE shared checker implementation (`integrations/conformance/adapters/
live_check.py` — every graded row calls the same `run(mapping)` function with a different config).
An "adapter" that points a shared checker at a new endpoint tests integration, not code-independence.
A real second checker has to independently re-derive the invariants from the spec text alone, never
importing or delegating to the original.

This is that second checker, for this repo's own five invariants (`canonical_envelope`,
`chain_invariant`, `admission_invariant`, `anchoring_existence`, `anchoring_precedence`).

## What "independent" means here, concretely

- **Different language.** JavaScript (Node.js stdlib only), not Python.
- **Own crypto, from scratch.** `verify.js` implements secp256k1 point arithmetic and BIP-340
  schnorr verification directly in BigInt — it does not call `_bip340_nostr.py`, does not `require`
  any file from this repo's Python side, and does not use a third-party crypto library. If you
  diff the two implementations you will find genuinely different code, not a transliteration.
- **Own NIP-01 event-id recompute.** Same for the JSON-canonicalized event-id hash.
- **Same fixtures, never modified.** Reads the exact same `fixtures/*.json` files the Python
  runner reads — the independence is in the *checker*, not in a separate vector set (a second
  checker against DIFFERENT vectors would prove nothing about whether the two agree on the SAME
  claims).

## Run it

```bash
node run_conformance.js        # asserts every fixture meets the bar (exit 0), same shape as
                                # the Python run_conformance.py
node verify.js ../../fixtures/positive.json ../../fixtures/negative_*.json   # per-fixture detail
```

No `npm install` — zero dependencies, Node's built-in `crypto` module (SHA-256 only) and native
`BigInt` are the entire footprint.

## Why this matters more than it sounds

Any single checker — however carefully written — can share a blind spot with the spec it was
written from, or with the person who wrote it. Two checkers, written independently, from the same
spec text, by (functionally) two different implementations, converging on the exact same verdict
for every fixture — including *which specific invariant* breaks on each of the six negative
fixtures — is a much stronger claim than either checker passing its own tests. That convergence is
asserted in CI on every push, not just claimed in this README.

## Provenance

Real critique, real response: [crewAIInc/crewAI#4877](https://github.com/crewAIInc/crewAI/issues/4877),
Rul1an's comment and our public commitment (issuecomment-5057934692) to build this rather than only
describe it.
