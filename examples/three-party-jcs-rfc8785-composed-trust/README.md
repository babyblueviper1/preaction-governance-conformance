# Three-party composed trust: jcs-rfc8785-v1 across three independent systems

**Source thread:** [microsoft/autogen#7353](https://github.com/microsoft/autogen/issues/7353), 2026-07-24.

Three systems that share no code, no operator, and no prior integration each
independently produced an artifact pinned to the same canonicalization
discipline (`jcs-rfc8785-v1` — [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785),
sorted keys, compact separators, no `\uXXXX` escaping):

| Party | System | Artifact | Signature scheme |
|---|---|---|---|
| Yarmoluk / Graphify.md | CKG | `knowledge_receipt` — binds a concept to the hash of the source content it was extracted from | Ed25519, key fetched live from a separate `/keys` endpoint |
| giskard09 | Argentum-core | `action_ref` — binds an agent action to its scope, also anchored on-chain | Ed25519, key resolved from a separate out-of-band registry (`marks.rgiskard.xyz/pubkey/<agent_id>`) |
| invinoveritas | `/review` | `decision_ref` — a pre-action verdict, issued *before* the action it governs | Nostr NIP-01 (schnorr/secp256k1) |

`check_composed_trust.py` recomputes all three from `fixture.json`'s own
published bytes and checks them — **without calling any of the three issuers'
own `/verify` endpoints**. It is the fourth, unrelated party doing the
checking, which is the actual property being demonstrated: none of these
three systems needs the other two's code, trust, or cooperation to be
independently checkable.

```
$ python3 check_composed_trust.py
PASS -- knowledge_receipt    Yarmoluk / Graphify.md (CKG)
PASS -- action_receipt       giskard09 / Argentum-core (action_ref)
PASS -- pre_action_verdict   invinoveritas (/review)
```

## What's actually checked, per artifact

- **CKG knowledge_receipt** — `receipt_ref` recomputes as `sha256(JCS(payload))`,
  and the Ed25519 signature verifies against a public key fetched live from
  `ckg-receipt.onrender.com/keys` (not pasted in the receipt itself — the key
  resolves out-of-band, so the artifact can't vouch for its own signer).
  Separately, `payload.source_content_hash` was independently re-derived by
  fetching the live `source_url` and hashing it — it matches exactly.

- **Argentum action_ref** — same construction (`receipt_ref = sha256(JCS(payload))`,
  Ed25519 over the canonical bytes). At the time this fixture was first built the
  public key had been pasted directly alongside the receipt rather than resolved
  out-of-band the way CKG's is — a real asymmetry worth naming, since an
  artifact that can set its own verifying key inline is weaker than one that
  can't. **Fixed 2026-07-25** (giskard09, autogen#7353): the key now resolves
  from `marks.rgiskard.xyz/pubkey/<agent_id>`, its own out-of-band registry
  endpoint, closing the gap — both receipts now cite an out-of-band key
  location, different registry paths, same invariant. The on-chain anchor claim
  (`argentum.rgiskard.xyz/trails/...`) is recorded in the fixture but **not**
  independently checked by this script.

- **invinoveritas `decision_ref`** — recomputes as `sha256(JCS(preimage))` over
  exactly the field list the proof itself discloses
  (`decision_ref_preimage_fields`). The wrapping signature is a different
  scheme entirely (Nostr NIP-01/schnorr, not Ed25519), so full signature
  verification isn't duplicated in this script — it's already covered by
  [`../decision-ref-recompute/`](../decision-ref-recompute/) and the live,
  free, unauthenticated `POST /verify-proof`. This fixture records that
  `/verify-proof` returned `valid:true` on every check at build time
  (`id_integrity`, `signature_valid`, `issued_by_invinoveritas`,
  `is_proof_event`, `decision_ref_recomputes` — all `true`).

## Why this, not just a thread comment

A reply in a 350-comment GitHub issue scrolls away. This is a durable,
independently-runnable artifact: clone the repo, run one script, get a
pass/fail for three cross-party claims — no trust in the thread, in any
single issuer, or in whoever wrote this README required.

## Open extension

[chopmob-cloud/AlgoVoi](https://github.com/microsoft/autogen/issues/7353#issuecomment-5072305919)
stated the same key-independence invariant for their settlement-receipt
layer (a real, live x402 facilitator across 8 chains) but hasn't handed over
a concrete signed receipt yet — this fixture has a fourth slot ready
(`settlement_receipt`) the moment one exists. Same offer stands for AAR's own
action-receipt shape if a maintainer wants to add it.
