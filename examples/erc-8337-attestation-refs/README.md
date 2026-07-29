# ERC-8337 attestation-refs — real live Sepolia fixture

Executable conformance for [`docs/interop/attestation-refs.md`](https://github.com/AwareLiquid/ERC-8337/blob/main/docs/interop/attestation-refs.md)
(the joint interop note between ERC-8350/ERC-8337, Agent Memory State Registry, and
WYRIWE/ERC-8299 — [t/29098](https://ethereum-magicians.org/t/erc-8350-agent-memory-state-registry/29098)
x [t/25098](https://ethereum-magicians.org/t/erc-8004-trustless-agents/25098)), committed on-thread
2026-07-26 (t/25098 post #334). Checks §2 (entry schema), §3 (canonicalization), and §6 (authority
as a consumer-policy question, never an entry property).

**Real deployment, not a synthetic example** — `sepolia-fixture-v1.json` and `fixture-keys-v1.json`
are everest-an's own live Sepolia test vectors (registry `0xDdf21937ba80b5fF973610877A0955b320C91241`,
spaceId `0xfbe20b841e2cb8d5e8094da6a9be9ebe19bb4d52c6155f465b40aa7bf1c13564`), vendored verbatim from
[`AwareLiquid/ERC-8337/test-vectors`](https://github.com/AwareLiquid/ERC-8337/tree/main/test-vectors),
same "real deployment over fixtures" discipline as every other example in this repo.

## What gets recomputed

| Invariant | §  | Check |
|---|---|---|
| Canonicalization | §3 | raw `attestation_refs` → dedupe by `(event_id, pubkey)`, sort by `decision_ref` (bytewise lowercase hex), `verify_url` excluded — must match the fixture's own declared `attestation_refs_canonical` exactly |
| Signature | §2 | NIP-01 `event_id` recomputes from the signed event's own fields; BIP-340 signature verifies against the entry's `pubkey` — identity resolved from the event, never a self-claim |
| decision_ref | §2 | `sha256(JCS({artifact_hash, artifact_type, policy_version, verdict, source_class, vantage_limitation}))` recomputes from the event's own `content` |
| Authority | §6 | three-valued: `structurally_invalid` / `structurally_valid_zero_authority` / `valid_and_authorized` — read from a **consumer trust policy**, never from the entry itself |

## A real cross-implementation convergence, verified not assumed

The fixture's `decision_ref` values (`"0x95aefde3…"`) and invinoveritas's own
`services/proof_signing.py:compute_decision_ref()` (`"sha256:95aefde3…"`) use the **identical
6-field preimage** and produce the **identical hash bytes** — differing only in cosmetic prefix
style (`0x` vs `sha256:`). This checker compares hash bytes, not string prefixes, and the seq-2
transition's recompute confirms the convergence directly against real fixture bytes, not asserted.

## The seq-3 stress case

Sequence 3's `attestation_refs_raw_input` carries **3 raw entries with one exact duplicate**
`(event_id, pubkey)` pair, in non-canonical order; the fixture's own `attestation_refs_canonical`
is the correctly deduped-to-2, sorted result. This is the one transition in the live fixture that
actually exercises both the sort AND the dedupe rule in the same input, not just one or the other.

## Negatives — proving the checker is sensitive, not just echoing the fixture

| Case | Proves |
|---|---|
| Tampered `decision_ref` (1 hex char flipped) | recompute correctly diverges and is caught |
| Tampered signature (1 hex char flipped) | `schnorr_verify` correctly fails |
| Shuffled + duplicated raw input | canonical result is unchanged — the unordered-set + dedupe rule actually holds, not just for the fixture's own pre-sorted order |
| Authorized-key contrast | the **same bytes**, under a **different consumer trust policy**, reach `valid_and_authorized` instead of `structurally_valid_zero_authority` — proves all three §6 outcomes are reachable, and that authority genuinely lives in the consumer's policy, not the entry |

## Run it

```bash
python3 check_attestation_refs.py
```

Zero third-party dependencies — reuses the suite's vendored `_bip340_nostr.py` (pure stdlib) for
NIP-01 event-id recompute and BIP-340 signature verification, and a self-contained JCS (RFC 8785
subset) implementation for `decision_ref`/canonical-entry hashing.
