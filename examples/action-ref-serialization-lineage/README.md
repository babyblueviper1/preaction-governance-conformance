# action_ref serialization lineage — field-set convergence ≠ identifier convergence, one level down

[crewAI#4877](https://github.com/crewAIInc/crewAI/issues/4877) (haroldmalikfrimpong-ops / AgentID,
2026-06-30) found that `giskard09/argentum-core` carries **two documents** that both claim to define
`action_ref` for the same logical action shape — and they commit different bytes.

| Construction | Source | Form | Status |
|---|---|---|---|
| **(A)** | `docs/spec/guarantee-model.md` | raw concat: `SHA-256(agent_id‖action_type‖scope‖int64_be(timestamp_ms))` | a **different, narrower joint spec** (Mycelium × SafeAgent × DashClaw) — not competing for the same slot as (B)/(C) |
| **(B)** | the lineage cited in the original report | `SHA-256(JCS({agent_id, action_type, scope, timestamp_ms:int}))` | named divergence — **explicitly non-conformant** per (C)'s own text |
| **(C)** | `docs/spec/action-ref.md` v1.1 (linked reference impl: `plugins/agt_evidence_anchor/action_ref.py`) | `SHA-256(JCS({agent_id, action_type, scope, timestamp:"RFC3339, 3ms, Z"}))` | **normative** — the spec the wider cross-builder thread (A2A#1734, ibex) is actually converging toward |

## Why this is one level beneath the field-set question

The thread's earlier finding (see `examples/action-id-canonicalization/`) was: three builders agree on
*method* (JCS) but disagree on one field's *type* (`timestamp_ms` int vs `timestamp` string) — a
field-set delta. This example shows the delta survives even when the field set is fully pinned: (B)
and (C) commit the **same four field names**, and still produce different bytes, because (B) never
converts the epoch-ms integer to the RFC 3339 string `action-ref.md` requires. The spec's own
conversion note makes this explicit, not inferred:

> "Implementations that hash the epoch-ms integer directly (without conversion) will produce a
> different digest and are not conformant with this spec."

And (A) isn't even a divergent reading of the *same* spec — `guarantee-model.md` is a separate
document for a different three-system stack that happens to reuse the name `action_ref`. Citing it as
"the canonical giskard09/argentum-core derivation" conflates two normative documents that share a
repo, not a definition.

## Practical implication

A submission's `action_ref` recomputing to a hash doesn't tell you which spec it's conformant to. The
honest classification is a **named row**, not a flat match/no-match:

- matches **(A)** → wrong document (Mycelium × SafeAgent × DashClaw joint spec)
- matches **(B)** → wrong field type (epoch-ms int; non-conformant by the cited spec's own text)
- matches **(C)** → conformant to `action-ref.md` v1.1

`AgentID`'s own deployed `action_ref` was independently confirmed (2026-06-30) to be byte-faithful to
**(A)** — meaning it is not yet conformant to `action-ref.md` if interoperability with the A2A/ibex
side is the goal. Not a defect; a fact worth knowing before it enters a cross-builder vector, not after.

```
python3 check_action_ref_lineage.py      # zero-dependency, offline
```

Exit `0` iff all three constructions recompute to their locked, independently-verified values **and**
are pairwise distinct — i.e. the divergence is real and reproducible, not a one-off typo.
