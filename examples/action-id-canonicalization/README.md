# action-id canonicalization — recompute the cross-implementation convergence

crewAI#4877 and safal207's [`ibex-agent-verification` PR #63](https://github.com/safal207/ibex-agent-verification/pull/63)
converged three independent implementations on
`action_id = SHA-256(JCS(preimage))`:
the ibex `⟦#⛓✓⟧` reference chain, the AlgoVoi `action_ref`, and the rgiskard Argentum trail.

"Three teams chose JCS" is strong signal — but it's an **assertion** until recomputed. This example
recomputes it, and separates two claims that get conflated:

| Claim | Status | Why |
|---|---|---|
| **(A) construction converges** | ✅ true, provable | every team hashes JCS-canonical JSON, so key *order* is irrelevant |
| **(B) field set converges** | ❌ not yet | AlgoVoi commits `timestamp_ms` (int); rgiskard commits `timestamp` (ISO string) — same action, different preimage, **different id** |

(B) is the claim the alignment note actually gates on. So a "shared conformance vector" cannot mean
"each team produces some id" — it must mean **one envelope → one id under all three builders**, which
requires a single **locked field set** (PR #63's is the candidate).

The check also operationalizes Correctover's *deterministic-construction assertion*: the failure mode
is a non-deterministic preimage (a float, whose JCS number form is implementation-specific). The
restricted profile **fails closed on floats before hashing**, so a non-deterministic id can't enter
the chain.

### Cross-check against a live anchor

The locked-field-set id for the sample action is `sha256:4dcb76be5284d539…486c3` — byte-identical to
the `action_ref` published on-chain in rgiskard's Argentum trail `4b1f62ff…` (Arbitrum tx
`05a168c0…`), independently recomputed from their public endpoint. So the locked preimage here isn't
hypothetical: it reproduces a real production identifier.

```
python3 check_action_id.py      # zero-dependency, offline
```

Exit `0` iff construction is deterministic + order-independent + float-rejecting, **and** the
cross-builder divergence is exactly the declared `timestamp` field-set delta (no hidden drift).
