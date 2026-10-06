# ERC-8309 mesh-sync conformance: enumerate, per-origin convergence, signed envelope

Three conformance rules proposed for the [8309-vantage companion](https://github.com/damonzwicker/erc8309-companion-drafts) §10,
from findings by **Echo** in the receiptos thread (damon group, topic 16, 2026-10-05/06): a page silently clamped to 500 that read as the
whole set, a namespace the default view did not show, a convergence check that compared node totals, and `nodeType` served outside the
signed envelope.

| Rule | Statement | Vectors |
|---|---|---|
| R1 ENUMERATE | A sync check reads every node through its cursor to the end. A page that still carries a cursor is a sample, and a sample cannot pass or fail a conformance check. A repeating or dangling cursor fails closed. | E1-E3 |
| R2 PER-ORIGIN | Convergence is checked per origin and per namespace the origin declares: every participating node holds the complete set that origin produced there. Node totals are not a valid predicate. | C1-C4 |
| R3 ENVELOPE | Every field a peer acts on, `nodeType` included, is inside the signed envelope. A behaviour-affecting field outside it is an unverifiable claim; a served value that differs from the signed one is a mismatch. | N1-N4 |

C1 and C4 use Echo's enumerated counts: origin 419 / 413 per namespace, Railway 1725 in `:wyriwe` of which 1312 are its own
locally-originated records, NAS 0.7.0 at 299 of 413 before the retention fix. C1 is converged even though the node totals differ; C2 is
not converged even though they match.

```
python3 build_vectors.py              # regenerates vectors.json
python3 check_mesh_sync.py            # 11/11 vectors match
python3 check_mesh_sync.py --mutants  # M1 single-page read, M2 totals predicate, M3 unsigned field accepted: all KILLED
```

**Scope.** The vectors are structural: they test the three rules over record ids and declared field sets. They do not test a signature
scheme, the retention key, or the equivocation detector (signature-keyed retention is a base-8309 change; the divergence/equivocation
boundary is already test-locked in ccip-router#3). Stdlib only.
