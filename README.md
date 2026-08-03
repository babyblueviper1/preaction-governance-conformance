# Pre-action governance — conformance fixtures

[![conformance](https://github.com/babyblueviper1/preaction-governance-conformance/actions/workflows/conformance.yml/badge.svg)](https://github.com/babyblueviper1/preaction-governance-conformance/actions/workflows/conformance.yml)

A portable, implementation-independent conformance suite for the pre-action governance receipt model
discussed in [vercel/ai#13215](https://github.com/vercel/ai/issues/13215): a verifier should be able to
confirm, from the **bytes and declared trust inputs alone**, that a consequential agent action was
judged by an independent party and committed before it executed — without calling back to whatever
runtime produced the records.

The suite is **offline and zero-dependency**. The BIP-340 / NIP-01 core is vendored
(`_bip340_nostr.py`, pure stdlib); a second verifier using any correct BIP-340 implementation reaches
the same result.

```bash
python3 run_conformance.py        # asserts every fixture meets the bar (exit 0)
python3 verifier.py fixtures/positive.json fixtures/negative_*.json   # per-fixture detail
```

## The three joined invariants

Recompute the canonical envelope hash **once**, then test three joins against that single byte commitment:

| Suite | What it proves |
|---|---|
| `chain_invariant` | the pre-action and terminal records join on the same envelope hash |
| `admission_invariant` | an **independent identity** signed that same envelope hash before execution |
| `anchoring_invariant` | the commitment was **externally anchored before** the terminal outcome |

The receipt chain proves *what ran*. The admission record proves *a party that isn't the actor*
approved it. The anchor proves *the approval came first*. The three are separable and each fails for
its own reason.

## Fixture layers (what each carries)

- **canonical_envelope**: `raw_input`, `canonicalization` version, `canonical_bytes_utf8`, and the
  `expected_envelope_hash`. The verifier recomputes `sha256(canonical_bytes)` and ignores the declared
  hash except to confirm it.
- **chain**: `pre_action` (action_ref, actor_pubkey, envelope_hash) and `terminal`
  (action_ref, executed_envelope_hash, terminal_outcome_time).
- **admission**: the signed `verdict_event` (a NIP-01 schnorr event), whose content binds
  `artifact_hash == envelope_hash`. Identity is resolved from the event's **own** pubkey, not from any
  self-claim in the content.
- **anchor**: `commitment_digest` (must equal the admission event id), `accepted_anchor_point`
  (a declared trust input — see below), `terminal_outcome_time`, and the OTS `anchor_proof`.
- **trust_policy**: `independent_verifier_pubkeys` — the identities the policy treats as independent.

## Positive + five one-broken-join negatives

The positive fixture passes all three suites end to end. Each negative breaks **exactly one** join and
passes the rest:

| Fixture | Fails | Why |
|---|---|---|
| `positive` | — | chain joins, an independent published key signed the hash, anchored before the outcome |
| `verdict_binding_failed` | admission | valid signature, but over a *different* canonical hash |
| `admission_not_independent` | admission | signer resolves to the actor/executor (self-attested) |
| `key_different_but_identity_unproven` | admission | signer ≠ actor, but not a declared-independent identity (a second self-issued key passes the signature check yet proves no independence) |
| `late_commitment` | anchoring | valid anchor, but accepted *after* the terminal outcome |
| `ordering_unanchored` | anchoring | valid internal chain, no external existence proof at all |

## Examples — recompute properties, each runnable and CI-green

Beyond the core fixtures, `examples/` holds zero-dependency demonstrations that each turn a property
argued in a live standards thread into something a third party *runs*, not trusts. Every one recomputes
its claim from bytes and is wired into CI.

| Example | Recompute property |
|---|---|
| [`ledger-recompute`](examples/ledger-recompute) | a `/ledger` verdict re-derives to a sound result from its own bytes — a tampered one fails |
| [`crosswalk-recompute`](examples/crosswalk-recompute) | a vocabulary mapping between two boards is a recomputation, not an assertion (fails closed on an authority collision) |
| [`action-id-canonicalization`](examples/action-id-canonicalization) | the cross-implementation `SHA-256(JCS(...))` convergence — construction converges, the timestamp field set doesn't; plus the three-case locked-profile vector (byte-identical id / wrong-type fail-closed / order-independence) |
| [`decision-ref-recompute`](examples/decision-ref-recompute) | the pre-execution decision (`/review`'s `decision_ref`) recomputes from its own self-described preimage; signer ≠ runtime; tamper-sensitive |
| [`verdict-of-verdict-recompute`](examples/verdict-of-verdict-recompute) | a re-review's `source_class` is capped by the vantage of the verdict it reviews, never upgraded — a min-rule bound into `decision_ref` via `related_decision_ref`, fails closed on a tampered/unverifiable inner claim |
| [`reputation-pointer-recompute`](examples/reputation-pointer-recompute) | a typed Agent-Card reputation pointer (issuer/scheme/ref, verifying key, anchored `committed_at`, monotonic head commitment, published head location, explicit genesis marker) mapped onto a real `/ledger` entry — content-addressed, chain-recomputable, tamper-sensitive |
| [`benchmark-grade`](examples/benchmark-grade) | a submitted benchmark trace dump is graded by recomputing its verdicts from bytes, not by trusting the score |
| [`profile-resolution`](examples/profile-resolution) | a canonicalization profile resolves to a content-addressed, reproducible `action_ref` |
| [`ag2-beta`](examples/ag2-beta) | the external-attestation contract triple recomputes its verdicts (portable conformance, independent of the framework) |
| [`action-ref-serialization-lineage`](examples/action-ref-serialization-lineage) | field-set convergence ≠ identifier convergence one level down — same four fields, three named constructions (wrong-doc / wrong-field-type / normative), three distinct bytes |
| [`guardrail-decision-crosswalk`](examples/guardrail-decision-crosswalk) | invinoveritas `/review` ↔ ibex `GuardrailDecision`: 3 states preserve authority, 1 (`approve_with_concerns`) has no equivalent — reported as a named gap, not forced onto a label that doesn't carry the same authority |
| [`plaintext-verdict-consistency`](examples/plaintext-verdict-consistency) | a hash matching isn't the same as the label matching — found live in a real published package: a plaintext `expected_verdict` field can be tampered independently of the `valid` hash check that's supposed to guard it |
| [`erc-8337-attestation-refs`](examples/erc-8337-attestation-refs) | attestation-refs.md §3/§6 against everest-an's real live Sepolia fixture — canonicalization (sort+dedupe+verify_url-excluded), signature, `decision_ref` (byte-identical to invinoveritas's own preimage), and three-valued authority all recompute from bytes, not asserted |
| [`deils-leg2`](examples/deils-leg2) | Merlini's held-content-behind-commitment design (existence mandatory-public + non-suppressible, content optional-private until reveal) — 5 pinned cases recompute the reveal-check predicate, including a deep-nested-key-shuffle adversarial case a naive top-level-only canonicalizer would get wrong |
| [`sequence-integrity-recompute`](examples/sequence-integrity-recompute) | N artifacts over TIME, not just N signers on one artifact (TKCollective/AgentOracle) — two signed tree heads + 7 real composed-envelope entries; ordering and completeness recompute from bytes (Merkle root, inclusion proofs, consistency), and both a reorder and a drop are caught with damage localized to exactly where it happened |
| [`smolagents-guardrail-recompute`](examples/smolagents-guardrail-recompute) | huggingface/smolagents#2117/#2126's `GuardrailProvider.before_tool_call` — 10 pinned cases independently reimplement Allowlist/Blocklist/Composite guardrail semantics (first-denial-wins composition), including a substring-vs-exact-membership adversarial case |

Each is the executable form of a thread the suite tracks — "conformant" means *recomputes*, never *we say so*.

## `tools/` — the one exception to offline/zero-dependency

Everything above recomputes from local bytes alone, by design. `tools/broadcast_byte_diff.py` is
different in kind, not degree: it audits whether a *published* Nostr proof event is byte-identical
to what a relay actually serves back — a property that structurally requires talking to the network
(`pip install websockets`), which is why it's kept out of `run_conformance.py` / CI rather than
forced into the offline shape. A plain reachability check only proves a relay has *something*
answering to the event id; this refetches the event by id from each relay and diffs every NIP-01
field individually.

```bash
pip install websockets
python3 tools/broadcast_byte_diff.py path/to/event.json
```

## Provenance (these are real signatures, not mocks)

- The **positive** admission is signed by the live verifier's published secp256k1 key
  (`6786e18a…`); you can confirm it independently by POSTing the event to
  `https://api.babyblueviper.com/verify-proof` (or recomputing NIP-01 + BIP-340 locally with the
  zero-dep `invinoveritas-verify` package). It returns `valid: true`.
- The **identity negatives** carry real, valid schnorr signatures from throwaway keys — the signature
  verifies, the *identity* does not. That is the whole point of `admission_invariant`.

## The anchoring trust root

`accepted_anchor_point` is a **declared trust input** — the deterministic suite tests the *ordering*
relation (anchor point precedes the terminal outcome). Confirming that the anchor point is real (a
Bitcoin block, not a declaration) is the out-of-band step a deployment verifier runs:
`ots verify <commitment>.ots` resolves the block, and the block time is the accepted anchor point.

`fixtures/live_confirmed_anchor.json` is a **real, fully Bitcoin-confirmed** anchored verdict from the
live `/ledger` — real signed event, real `.ots`, real block — so the trust root isn't hypothetical.
The mechanism runs end to end in production; the synthetic fixtures isolate the verifier *logic*.

## Regenerating

`generate_fixtures.py` produces the fixtures (it needs the live signer for the positive fixture's real
signature). The committed fixtures under `fixtures/` are the contract; the verifier and `run_conformance.py`
depend on nothing in this repo beyond the vendored stdlib core.

## License

MIT
