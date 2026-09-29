# Issuer-neutral marker checkers: a demonstration second issuer

For [agentrust-io/trace-spec#397](https://github.com/agentrust-io/trace-spec/issues/397) (vantage limitation) and [#398](https://github.com/agentrust-io/trace-spec/issues/398) (related_claims).

The bar for both proposals is that an independent second issuer passes the checker unchanged. Until this commit that bar could not be met. `vantage_limitation_check.py` and `related_claims_check.py` pinned invinoveritas in four places:

- our public key;
- Nostr kind 30078;
- the schema prefix `invinoveritas.`;
- a note table keyed by our policy ids.

A second issuer would have failed on key and envelope before any marker was read.

## What changed

The marker logic is the same for every issuer. What differs per issuer is data, so it now comes from a published issuer profile (`trace-issuer-profile.v1`, see `tools/issuer_profile.py`) passed with `--profile`. The profile carries:

- the envelope (`nip01-schnorr` or `jws-eddsa`) and the issuer's keys;
- the payload member that lists the signed preimage fields;
- the irreversible artifact types;
- the exact note wording per policy and source class.

The checker prints the profile's sha256, so every PASS is visibly relative to one declared profile.

JWS/EdDSA verification is pure stdlib (`tools/_ed25519.py`, RFC 8032, verification only), so the checkers stay pip-free.

## Our own records are unaffected

- **With no `--profile`,** the original code path runs, and it is byte-identical to the previous checkers across 356 invocations: every fixture event, and every outer × inner × claims × completeness combination.
- **With `--profile profiles/invinoveritas.json`,** the verdicts are identical too; only the header line is new.
- **The `trace-v20-fixtures` suites** (negative cases, mutants, precedence vectors) still pass.

## The demonstration issuer (not independent)

`example-issuer` is a fixture we wrote, and its signing seed is published in `build.py`. Anyone can sign as it. It differs from invinoveritas on everything a profile can vary:

| | invinoveritas | example-issuer |
|---|---|---|
| envelope | NIP-01 event, BIP-340 Schnorr | flattened JWS, EdDSA (Ed25519) |
| key | `PUBLISHED_PUBKEY` | `c384e7a6…a79024` |
| policy id | `invinoveritas.review.v2x` | `example-issuer.policy.2026-09` |
| note wording | ours | its own |
| preimage member | `decision_ref_preimage_fields` | `signed_fields` |
| irreversible types | `trade`, … | `wire_transfer`, `contract_signature` |

```
python3 build.py      # needs `cryptography` (build time only); deterministic
python3 run_demo.py   # stdlib; 18/18 expected outcomes
```

`run_demo.py` asserts the following against the unchanged checkers.

- **Passes:**
  - an irreversible record carrying its exact note;
  - a reversible record with no note (absence is still declared in the signed preimage);
  - a related_claims comparison whose outer proof comes from the demo issuer and whose inner proof comes from invinoveritas (`--inner-profile`), so cross-issuer references work.
- **Fails:**
  - an edited note, a note on a reversible type, a missing note, a note outside the signed preimage, another class's note;
  - a key not in the profile, a `kid` that claims the issuer's key over another signer's signature, `alg: none`, a payload swapped under a valid signature;
  - a false recorded comparison result, a wrong `related_decision_ref`, a tampered inner proof.
- **Controls:**
  - the demo record fails under the invinoveritas profile, and our record fails under the demo profile, so the profile is what admits an issuer;
  - our record passes under our published profile.

## What this does not show

It does not show that an **independent** issuer meets the bar. It shows that the bar is now reachable without changing checker code: an issuer publishes a profile and its records. The first independent issuer to do that closes the criterion. Open an issue or PR here with your profile and a record, and we'll add it to this suite.

A profile is the issuer's own declaration, in the same way a verifier takes a trust anchor. Passing means the record is consistent with that issuer's signed fields and declared wording. It does not mean the declared `source_class` is true.
