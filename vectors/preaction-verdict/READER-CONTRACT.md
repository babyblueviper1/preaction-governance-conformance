# Pre-action verdict: reader contract

A reader is given three things and answers one question.

- **record**: a signed verdict, a Nostr event (NIP-01) of kind 30078 whose `content` is a JSON object.
- **key_set**: the issuer keys the relying party trusts, x-only secp256k1 public keys in hex.
- **relying_party**: `action_hash`, the SHA-256 (hex) of the action the relying party is about to take or took, and
  `executed_at`, the Unix time it executed.

**Question:** may the relying party credit this record as an independent verdict on *this* action, issued *before* it ran?

The answer is `ESTABLISHED` or `REFUSED:<STEP>`. Apply the steps in order; the first step that fails decides the answer.

| step | check | refusal |
|---|---|---|
| 1 | `id` equals SHA-256 of the UTF-8 JSON array `[0, pubkey, created_at, kind, tags, content]`, serialized with no whitespace and non-ASCII characters left unescaped (NIP-01) | `REFUSED:EVENT_ID` |
| 2 | `sig` is a valid BIP-340 Schnorr signature over the 32 bytes of `id` under `pubkey` | `REFUSED:SIGNATURE` |
| 3 | `pubkey` is in `key_set` | `REFUSED:KEY_NOT_IN_SET` |
| 4 | `tags` contains `["schema", "invinoveritas.verdict_proof.v1"]` | `REFUSED:SCHEMA` |
| 5 | `content.verifier_pubkey` equals `pubkey` (the record names the key that signed it) | `REFUSED:KEY_BINDING` |
| 6 | `content.decision_ref` equals `"sha256:"` + SHA-256 of the RFC 8785 (JCS) serialization of an object whose keys are exactly the names in `content.decision_ref_preimage_fields`, each set to the value of that key in `content`, or to `null` when `content` lacks it. An absent field is present as `null`, never omitted. | `REFUSED:DECISION_REF` |
| 7 | `relying_party.action_hash` equals `content.artifact_hash` | `REFUSED:ACTION_UNBOUND` |
| 8 | `content.freshness_beacon.block_time <= created_at < relying_party.executed_at` | `REFUSED:NOT_PRE_ACTION` |

## What each step establishes, and what none of them do

- Steps 1 to 3: the issuer whose key the relying party trusts signed exactly these bytes.
- Steps 4 and 5: the record is the verdict type this contract reads, and it does not borrow another key's identity. Step 5 is the one a reader
  that stops at "signature valid, key trusted" skips (case `n06`).
- Step 6: the verdict's commitment is recomputable from what is published; a reader learns nothing about fields the issuer kept private.
- Step 7: the verdict is about this action, not a neighbouring one.
- Step 8: the verdict was signed after a Bitcoin block the issuer could not know in advance (`freshness_beacon`: not pre-dated) and before the
  action ran. `created_at` is the issuer's own clock. The independent proof that the record existed by a given time is its OpenTimestamps
  anchor and public relay copies, recorded on the issuer's ledger. This contract does not check them, because checking them needs Bitcoin
  block headers, so a reader is offline. A relying party that needs the upper bound proven checks the anchor separately.
- No step judges whether the verdict was *right*. That is an outcome question, settled on the issuer's ledger.

## The cases

`cases.json` lists 13 cases. Five are real verdicts from the public ledger (`https://api.babyblueviper.com/ledger/<n>`, entries 249, 252, 255,
258, 261), with the signed fields exactly as published. Eight are refusals built by `gen.py`:

| case | built as | expected |
|---|---|---|
| `n01-forged-signature` | one hex digit of the signature changed | `REFUSED:SIGNATURE` |
| `n02-wrong-key` | re-signed by a key outside the issuer key set | `REFUSED:KEY_NOT_IN_SET` |
| `n03-content-tampered` | `confidence` edited after signing, id and signature kept | `REFUSED:EVENT_ID` |
| `n04-action-unbound` | a real verdict presented for a different action | `REFUSED:ACTION_UNBOUND` |
| `n05-after-the-fact` | a real verdict for an action that executed 60 s before the verdict was signed | `REFUSED:NOT_PRE_ACTION` |
| `n06-key-binding` | signed by a key the relying party also trusts, while the content names the issuer's key | `REFUSED:KEY_BINDING` |
| `n07-decision-ref-mismatch` | correctly signed and bound, `decision_ref` no longer matches its preimage | `REFUSED:DECISION_REF` |
| `n08-schema-tag-missing` | correctly signed and bound, schema tag removed | `REFUSED:SCHEMA` |

The refusals that need a signature (`n02`, `n06`, `n07`, `n08`) are signed by a TEST-ONLY key whose secret is
SHA-256(`preaction-governance-conformance/test-only/wrong-key`), so anyone can rebuild them. The issuer's production key signs nothing here
except the five real verdicts. Each step has exactly one case that passes the steps before it and fails at it: a reader that skips any step
gets one case wrong.
