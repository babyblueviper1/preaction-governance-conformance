# ERC-8309 mesh-sync conformance: enumerate, per-origin convergence, signed envelope, envelope completeness

Four conformance rules proposed for the [8309-vantage companion](https://github.com/damonzwicker/erc8309-companion-drafts) §10,
from findings by **Echo** in the receiptos thread (damon group, topic 16, 2026-10-05/06): a page silently clamped to 500 that read as the
whole set, a namespace the default view did not show, a convergence check that compared node totals, and `nodeType` served outside the
signed envelope. R3b is a boundary **Pavlo** raised on the same thread (2026-10-06) before ratification: R3 only checks fields an
adapter *declares* in `acted_on`, so it cannot by itself prove that declaration is complete.

| Rule | Statement | Vectors |
|---|---|---|
| R1 ENUMERATE | A sync check reads every node through its cursor to the end. A page that still carries a cursor is a sample, and a sample cannot pass or fail a conformance check. A repeating or dangling cursor fails closed. | E1-E3 |
| R2 PER-ORIGIN | Convergence is checked per origin and per namespace the origin declares: every participating node holds the complete set that origin produced there. Node totals are not a valid predicate. | C1-C4 |
| R3 ENVELOPE | Every field DECLARED in `acted_on` is inside the signed envelope. A declared behaviour-affecting field outside it is an unverifiable claim; a served value that differs from the signed one is a mismatch. **This is a narrower claim than "every field the peer acts on is signed"** -- see R3b. | N1-N4 |
| R3b COMPLETE | `acted_on` must cover the implementation's real `decision_surface` (the fields it actually branches on), bound separately from this fixture -- e.g. by code review or static extraction, not derived from `acted_on` itself. A surface field missing from `acted_on` is its own `NONCONFORMANT`, distinct from R3's signed-ness verdict. No `decision_surface` bound reads `UNVERIFIABLE`, never `COMPLETE`: absence of a binding is not evidence the declaration is complete. | N5-N7 |

C1 and C4 use Echo's enumerated counts: origin 419 / 413 per namespace, Railway 1725 in `:wyriwe` of which 1312 are its own
locally-originated records, NAS 0.7.0 at 299 of 413 before the retention fix. C1 is converged even though the node totals differ; C2 is
not converged even though they match.

N5 reproduces Pavlo's exact counterexample: an adapter that declares `acted_on: ["nodeId"]` while its real decision surface also
branches on `nodeType` reads `CONFORMANT` under R3 alone (nothing it declared is unsigned) and `NONCONFORMANT:acted_on_incomplete:nodeType`
under R3b -- the structural checker conforming while the implementation still acts on an unsigned field, exactly the gap flagged.

```
python3 build_vectors.py              # regenerates vectors.json
python3 check_mesh_sync.py            # 14/14 vectors match
python3 check_mesh_sync.py --mutants  # M1 single-page read, M2 totals predicate, M3 unsigned field accepted, M4 completeness ignored: all KILLED
```

**Scope.** The vectors are structural: they test the four rules over record ids and declared field sets. They do not test a signature
scheme, the retention key, or the equivocation detector (signature-keyed retention is a base-8309 change; the divergence/equivocation
boundary is already test-locked in ccip-router#3). R3b's `decision_surface` is itself a declared input to the fixture, not something
this checker extracts from real code -- binding it to an actual implementation's control flow is a separate, acknowledged obligation
(the same dependency-completeness boundary as the guarantee-preservation discussion on the same thread: checking every listed
dependency does not prove none was omitted). Stdlib only.
