# Canonicalization-profile resolution invariant

The referee-enforced version of the property two boards converged on in
[autogen#7353](https://github.com/microsoft/autogen/issues/7353): an `action_ref` is only
cross-board comparable if every board recomputed it under the **same** canonicalization — and the
only way to prove "same canonicalization" without a trusted coordinator is to **content-address the
profile** and recompute under it.

giskard09's anchoring trail and AgentOracle (TKCollective) both ship
`canonicalization_profile_id = SHA-256(JCS(spec_doc))` and disclose it in the anchor sibling. This
example makes that disclosure a **checked invariant** rather than a convention: the referee resolves
the profile by id and re-derives the `action_ref`, so a registry row is only admissible if it
recomputes under the profile it declares.

## The two joined checks

| Check | What it proves |
|---|---|
| **profile_content_addressing** | `SHA-256(JCS(profile.doc)) == canonicalization_profile_id`. A verifier handed *any* doc rehashes it and rejects it unless it hashes to its own id — so "same id ⇒ same byte rule" holds **by construction**, and no party has to trust a registry to *serve* the right doc. The registry is a convenience, not an authority (the consumer-side guarantee). |
| **action_ref_reproducible** | `action_ref == SHA-256(JCS(preimage))` under the resolved profile. The profile is **executable**, not just a label: anyone re-derives the same `action_ref` from the preimage bytes. The `timestamp`-as-integer case (the [azender1 `422`](https://github.com/microsoft/autogen/issues/7353)) recomputes to a *different* `action_ref` and is rejected as a first-class conformance failure, not an opaque error. |

An entry is sound iff both hold.

## Run

```bash
python3 resolve_profile.py          # human-readable; exit 0 iff positive passes AND both negatives rejected
python3 resolve_profile.py --json   # machine-readable
```

```
[PASS] positive
         ok   profile_content_addressing — profile id 471b4e7a19b111f4 reproduces
         ok   action_ref_reproducible    — action_ref a6b5cf6ecfa2a590 reproduces from preimage
[PASS] negative_tampered_profile (must reject) — profile_id_mismatch: doc hashes to 0cdf7c8e…, declared 471b4e7a…
[PASS] negative_timestamp_int   (must reject) — action_ref_not_reproducible: preimage canonicalizes to 20e5625b…, declared a6b5cf6e…
=> PASS
```

**Green-by-assertion is impossible:** the positive vector recomputes both joins from bytes, and the
two negatives must be *rejected* — a tampered profile doc (its id no longer matches) and a
`timestamp`-as-integer preimage (a different canonical form, the azender1 case). The script exits
non-zero unless the positive is sound and both negatives are caught.

## Files

| File | What |
|---|---|
| `profile.json` | the content-addressed profile: `{canonicalization_profile_id, doc}`, where the id is `SHA-256(JCS(doc))`. The registry artifact a verifier resolves. |
| `jcs.py` | minimal RFC-8785-style JSON Canonicalization Scheme, pure stdlib (scope note re: code-point vs UTF-16 key ordering — identical for the ASCII/BMP keys here). |
| `resolve_profile.py` | the invariant checker + the two negative controls. |

## Scope / honesty

- The profile in `profile.json` is a **self-contained demo profile** (its own correctly computed id),
  not a copy of giskard09's `jcs-rfc8785-action-ref-v1` (`8c7f7175…`) — that doc's bytes aren't ours
  to reproduce. The *invariant* is what's general; the real-world trail/AgentOracle profile is the
  instance it's designed to check.
- The positive vector uses AgentOracle's disclosed preimage *shape*; the `action_ref` shown is what
  that preimage canonicalizes to **under this demo profile**. Cross-check it against a live
  `/nexus/trail` to confirm wire-agreement with their profile.
- Composes with the anchoring invariant: a registry recomputes `action_ref` *under the declared
  profile* before joining it to an anchor — so the profile_id becomes part of what's re-derived, not
  a trusted annotation (the [join #2](https://github.com/microsoft/autogen/issues/7353) discipline).

## Related

- [`../ledger-recompute`](../ledger-recompute) — per-entry "re-derives to sound" recipe
- [`../../README.md`](../../README.md) — the conformance suite (independent verdict + external Bitcoin-anchored ordering)
