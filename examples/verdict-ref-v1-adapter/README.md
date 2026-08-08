# verdict-ref-v1 adapter — closing a public commitment (microsoft/autogen#7353)

giskard09 ([action_ref](https://github.com/giskard09/argentum-core)) shipped a real conformance
fixture, [`verdict-ref-v1`](https://github.com/giskard09/argentum-core/tree/main/examples/conformance/verdict-ref-v1),
naming `babyblueviper1:review` as the example independent-issuer, and asked a fair question: is
this suite a running system or a design doc? We answered honestly (real code, but not yet shaped
to their exact vector format) and hand-built ONE `verdict_object` as a one-off proof of concept in
the reply itself
([issuecomment-5048203827](https://github.com/microsoft/autogen/issues/7353#issuecomment-5048203827)).

This is the remaining committed piece: an actual adapter that emits `verdict-ref-v1`'s exact schema
**programmatically** from any live `/review` call, not a hand-typed example.

## The schema (vendored verbatim from their `verify.py`)

```python
verdict = {"action_ref": ..., "confidence": ..., "issuer_id": ..., "ts_ms": ..., "verdict": ...}
verdict_ref = sha256(JCS(verdict))   # JCS = compact separators, sorted keys
```

Conformance gates on issuer independence (`issuer_id != agent_id`), not on the verdict outcome.

## What this proves, run in order

1. **Cross-implementation convergence.** `upstream_vectors.json` (vendored verbatim from their
   repo) is recomputed with *our own* hash function — all 4 vectors, `action_ref` and
   `verdict_ref` both, checked byte-identical against their published expected values. If this
   step fails, our hash function disagrees with theirs and step 2 proves nothing.
2. **Live emission, not a one-off.** `live_review_response.json` is a real, independently-
   verifiable `invinoveritas /review(sign=true)` proof (verify it yourself: POST the `event`
   object to `https://api.babyblueviper.com/verify-proof`, or recompute NIP-01 + BIP-340
   locally). The adapter reads it and builds a `verdict_object` in their exact schema
   programmatically — no hand-typing a JSON literal, which is what the July reply did and what
   this closes.

## The one honest substitution, named plainly

`action_ref` in their schema is `sha256(JCS({agent_id, action_type, scope, timestamp}))` — a
4-field execution-event preimage. Our `decision_ref` is `sha256(JCS({11 review-verdict fields}))`
— a different preimage, about a different kind of event (a judgment, not an execution). Both are
"a content-addressed pointer to what this verdict is about," which is the *role* `action_ref` plays
in their schema — so this adapter substitutes our `decision_ref` into that slot rather than
inventing a fake 4-field execution preimage that doesn't correspond to anything real. This is a
role-substitution, not a claim the two hash constructions are the same thing — stated here instead
of left implicit.

## Run it

```bash
python3 build_verdict_object.py
```

Zero dependencies, offline.

## Provenance

- Original ask: [microsoft/autogen#7353](https://github.com/microsoft/autogen/issues/7353),
  giskard09's fixture referenced throughout the thread.
- Their fixture: `github.com/giskard09/argentum-core/tree/main/examples/conformance/verdict-ref-v1`
- `live_review_response.json` is a real `/review` call, verifiable via
  `POST https://api.babyblueviper.com/verify-proof`.
