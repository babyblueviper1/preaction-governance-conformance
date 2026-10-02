# Live-endpoint adapters

The verifier in the parent directory checks portable static fixtures. This runs the same three
invariants — `canonical_envelope`, `admission_invariant`, `anchoring_invariant` — against a **live
governance endpoint**, so an implementer can point the suite at a running service and see where the
invariants hold and where the gaps are.

```bash
python3 adapters/live_check.py adapters/safeagent.mapping.json      # live, BIP-340 over the hash
python3 adapters/live_check.py adapters/invinoveritas.mapping.json  # NIP-01 Nostr-event scheme (sample)
```

Zero third-party deps — the crypto is the vendored BIP-340 / NIP-01 core (`../_bip340_nostr.py`).

## How it works

It's **mapping-driven**: a small JSON says how to obtain the governance block and where each field
lives. The verifier is agnostic to the signature scheme — it normalizes per `sig_scheme`:

| `sig_scheme` | check |
|---|---|
| `bip340-hash` / `bip340-schnorr` | BIP-340 schnorr directly over the 32-byte envelope hash |
| `nostr-event` | recompute the NIP-01 event id, verify schnorr over it |
| `ed25519-jcs` | Ed25519 over canonical bytes — verified if an ed25519 lib (PyNaCl) is present, else `unverified_here` |

A mapping fetches live (`fetch`) or reads a saved response (`response_file`). For endpoints that
deduplicate identical claims, put the literal `__NONCE__` anywhere in the request body and the runner
substitutes a unique token per run.

```json
{
  "name": "your-endpoint",
  "fetch": { "method": "POST", "url": "https://…/claim", "body": { "scope": "… __NONCE__" }, "governance_path": ["governance"] },
  "fields": { "envelope_hash": "envelope_hash", "pubkey": "verifier_pubkey", "signature": "signature", "sig_scheme": "sig_scheme", "anchor_endpoint": "anchor_endpoint" },
  "trust_policy": { "independent_verifier_pubkeys": ["<your published governance pubkey>"] }
}
```

## What the result states mean

- `pass` — the invariant holds against the live response.
- `fail` — a specific invariant is broken (with the same negative-case codes as the fixtures).
- `pending` — the anchor is submitted but not yet Bitcoin-confirmed, so "ordered before the outcome"
  is not yet assertable (distinguish `submitted` vs `confirmed` in your `/anchor` response).
- `not_provided` — the endpoint didn't expose enough to run this check (e.g. the raw canonical claim
  for `canonical_envelope`). Exposing it enables the recompute.

## Notes per invariant

- **canonical_envelope** recomputes `SHA-256(JCS(claim))` only if the endpoint returns the raw claim.
  If it returns only the hash, the binding is *asserted*, not recomputed — surface the canonical claim
  to close this.
- **admission_invariant** = a valid signature over the envelope hash by a key in your
  `independent_verifier_pubkeys` that isn't the actor's. Publishing the governance pubkey (e.g. at
  `/.well-known/` or `/governance/pubkey`) is what makes "independent identity" checkable.
- **anchoring_invariant** = the anchor's accepted point (the Bitcoin block) provably precedes the
  terminal outcome. A background OTS submission is `pending` until it confirms.

## AgentID (`adapters/agentid*`)

Off-chain issuer-signed, recomputable, no anchor claimed; ordering and sequence integrity are the
board's layer.

`POST https://getagentid.dev/api/v1/agents/gateway/verifier-attestation` (public, no credential) returns a
CTEF v0.1 `verifier_attestation`: `digest = SHA-256(JCS(core))` where `core` = the response minus
`{digest, jws}`, and `jws` is a compact EdDSA JWS whose payload bytes **are** `JCS(core)`, signed by
`kid agentid-2026-03` (OKP/Ed25519, `https://getagentid.dev/.well-known/jwks.json`, also the
`verificationMethod` of `did:web:getagentid.dev`).

```bash
PYTHONUTF8=1 python3 adapters/live_check.py adapters/agentid.mapping.json                                # positive: canonical_envelope + admission pass, anchoring unanchored (by design)
PYTHONUTF8=1 python3 adapters/live_check.py adapters/agentid.negative_bound_field_altered.mapping.json   # envelope_hash_mismatch
PYTHONUTF8=1 python3 adapters/live_check.py adapters/agentid.negative_throwaway_key.mapping.json         # key_different_but_identity_unproven
python3 adapters/agentid.fixtures/verify_fixture.py adapters/agentid.fixtures/positive.raw.json          # independent recompute (cryptography + jcs), live JWKS
```

- `agentid.fixtures/positive.raw.json` — the endpoint response verbatim; `request.json` — the exact body sent.
- `agentid.fixtures/positive.json` — the same response under `verifier_attestation`, plus a `governance`
  block (`envelope_hash` = `digest`, `canonical_bytes_utf8` = `JCS(core)`, `verifier_pubkey` = hex of the
  JWKS `x`) and the same JWS re-encoded as RFC 7515 general serialization, so `live_check.py` can read it.
  `build_fixtures.py` derives it; nothing is re-signed.
- Negatives: `negative_bound_field_altered.json` (same envelope + same signature, `binding.charge_ref`
  altered, declared digest unchanged) and `negative_throwaway_key.json` (same core and header, signed by a
  deliberately public throwaway key).
- `agentid.profile.json` — `trace-issuer-profile.v1` / `jws-eddsa` for `tools/issuer_profile.py`. Known gap:
  that profile matches `kid` against the hex pubkey list, while the live header carries the JWKS label
  `kid: "agentid-2026-03"` (RFC 7517), so `verify_envelope` on `positive.flattened-jws.json` returns
  `kid not among the profile's keys` even though `tools/_ed25519.verify` accepts the signature under the
  JWKS key. `live_check.py` resolves the key by value and is unaffected.
- Bound-field constructions (see `verify_fixture.py`): `binding_digest = SHA-256(JCS({amount_usd,
  charge_ref, nonce, subject_did}))`; `action_ref = SHA-256(agent_id ‖ action_type ‖ scope ‖
  int64_be(ms(issued_at)))` (argentum-core action-ref-v1, raw concatenation, where `action_type`/`scope`
  come from the request, not the envelope). Neither is `SHA-256(JCS(core))` — that is the envelope `digest`.
- The `response_file` form is used because the live response has no hex pubkey / `canonical_bytes_utf8`
  field and a compact (not general-serialization) JWS, which `live_check.py` cannot consume directly;
  `_fetch` in the mapping documents the request so the raw fixture can be regenerated.
