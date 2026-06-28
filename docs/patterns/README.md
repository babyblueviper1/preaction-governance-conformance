# Reference patterns

Each invariant in this suite asks a *question*; a "pattern" here is a reusable, implementation-agnostic
*way to satisfy* one of them that any verifier can adopt. Patterns are descriptive, not normative — the
conformance bar is still the three invariants checked against your live endpoint by `adapters/live_check.py`.
They exist so an implementer doesn't reinvent the wedge a peer already solved.

Contributions welcome from any conforming implementation — open a PR adding a `docs/patterns/<name>.md`
with: the invariant it serves, the mechanism, a minimal interface, and a pointer to a live/source
reference. Credit stays with the contributor.

## Anchoring invariant

| Pattern | Mechanism | Reference |
|---|---|---|
| **Anchor sweep** | A scheduled endpoint submits an external timestamp (OTS / CT-style log) for any *unanchored* claims, so every commitment gets a forward, pre-outcome anchor without blocking the hot path. Mechanism-agnostic: works the same on Bitcoin OTS or a transparency log. | SafeAgent — `safeagent_governance.py` ([github.com/azender1/SafeAgent](https://github.com/azender1/SafeAgent)) *(write-up incoming)* |
| **Stamp-at-issue** | Commit + sign the verdict, then OTS-stamp its event id while the entry is still unsettled, so the Bitcoin block provably precedes the outcome. Precedence is a durable fact fixed at stamp time. | invinoveritas — `/ledger/{n}/commitment` (entry 38) |

**Precedence vs existence (the load-bearing distinction):** an anchor that is merely *confirmed* proves the
record existed by block T. It only proves *committed before the outcome* if the stamp was made before the
outcome's own timestamp — a strict inequality (`anchor_block_time < outcome_timestamp`). A forward stamp
(submitted at claim/issue time) is precedence-bearing; a post-hoc backfill is existence-only. The
`anchoring_invariant` check distinguishes the two.
