# Composed profile: admission + recompute + chain-fork

Requested by rpelevin on [autogen#7353](https://github.com/microsoft/autogen/issues/7353)
(2026-07-03): "the useful next conformance step seems to be composing the two properties
that are now being tested separately... a self-signed ALLOW, a verdict that does not
recompute, and a same-sequence fork should fail for different reasons, but the composed
profile should catch all three."

## The two properties this composes

- [`../x402-payment-decision-recompute/`](../x402-payment-decision-recompute/) — is a
  payment **decision** entitled to its own verdict? Two negatives: **admission** (signer
  independence — a decision signed by the actor's own wallet is self-approval, not a
  second opinion) and **recompute** (the recorded verdict must re-derive from its own
  cited controls, `verdict = f(controls)`, not just carry a valid signature).
- `services/ledger_chain.py` (production, invinoveritas) — does the **receipt history**
  become fork-detectable, not just individually-anchored? `head_hash = sha256(content_hash
  + "|" + prev_head_hash)`, published to the same public Nostr relays every proof event
  already goes to, so a fork is two conflicting, independently-computable heads at the
  same sequence position — not something you have to take the server's word for.

## What "composed" means here

Take the accepted decision (`presidio-x402-decision-001`), commit it as a chain entry
using the exact production construction (vendored verbatim from `services/ledger_chain.py`,
not reinvented), then:

1. **Predictability** — recomputing from the identical content + prior head reproduces the
   identical `head_hash`, deterministically.
2. **Fork detection** — a divergent entry at the *same sequence position* (same
   `prior_head`, different content) produces a *different* `head_hash`. Both heads remain
   independently computable from their own content, so a server showing head A to one
   party and head B to another is caught by comparing recomputed heads against what was
   published — not hidden by a silent overwrite.

The script runs all three failure modes together and reports which axis each one fails on:

| Vector | Admission | Recompute | Fails on |
|---|---|---|---|
| `presidio-x402-decision-001` (accepted) | ✓ independent | ✓ recomputes | — (the starting point) |
| `presidio-x402-decision-signer-equals-runtime` | ✗ self-signed | ✓ recomputes | **who** signed it |
| `presidio-x402-decision-verdict-not-recomputable` | ✓ independent | ✗ doesn't recompute | **whether** the verdict follows from its inputs |
| divergent same-sequence chain entry | — | — | **where** two conflicting heads meet at one position |

Three distinct, individually-diagnosable failure reasons — not one pass/fail bit.

## Axis 4 — pshkv's fork-matrix

pshkv, same thread (2026-07-03), on the two independent implementations (this repo and
`giskard09/argentum-core`) landing on byte-identical `head_hash` values: "that is the useful
proof... the fork is externally reconstructable from retained bytes," and proposed
formalizing it as four separately-checkable properties rather than one demo run:

- (a) same `content_hash`, same `prev_head` → same `head_hash` (determinism)
- (b) same sequence position, different `prev_head` → chain fork detected
- (c) same payload under a different chain context → different `head_hash` (replay resistance)
- (d) the verifier reports **both** competing heads, never collapses to a generic `invalid`

`report_fork()` returns both heads plus the shared sequence position as a structured
result — never a bare bool — so (d) is a property of the return shape, not a claim in a
comment. All four hold under recompute; see the script output for the actual values.

```
python3 check_composed_chain.py      # zero-dependency, offline
```
