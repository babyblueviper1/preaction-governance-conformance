# ERC-8309 mesh-sync conformance: enumerate, per-origin convergence, signed envelope

Three conformance rules proposed for the [8309-vantage companion](https://github.com/damonzwicker/erc8309-companion-drafts) §10,
from findings by **Echo** in the receiptos thread (damon group, topic 16, 2026-10-05/06): a page silently clamped to 500 that read as the
whole set, a namespace the default view did not show, a convergence check that compared node totals, and `nodeType` served outside the
signed envelope.

| Rule | Statement | Vectors |
|---|---|---|
| R1 ENUMERATE | A sync check reads every node through its cursor to the end. A page that still carries a cursor is a sample, and a sample cannot pass or fail a conformance check. A repeating or dangling cursor fails closed. | E1-E3 |
| R2 PER-ORIGIN | Convergence is checked per origin and per namespace the origin declares: every participating node holds the complete set that origin produced there. Node totals are not a valid predicate. | C1-C4 |
| R3 ENVELOPE | Every field **declared** behaviour-affecting is inside the signed envelope; a served value differing from the signed one is a mismatch; and every served field outside the envelope is declared, either in `acted_on` or as `inert`. | N1-N7 |

C1 and C4 use Echo's enumerated counts: origin 419 / 413 per namespace, Railway 1725 in `:wyriwe` of which 1312 are its own
locally-originated records, NAS 0.7.0 at 299 of 413 before the retention fix. C1 is converged even though the node totals differ; C2 is
not converged even though they match.

```
python3 build_vectors.py              # regenerates vectors.json
python3 check_mesh_sync.py            # 14/14 vectors match
python3 check_mesh_sync.py --mutants  # M1 single-page read, M2 totals predicate, M3 unsigned field
                                      # accepted, M4 undeclared field accepted: all KILLED
```

**What R3 does not establish.** Raised by Pavlo on 3281703 (topic 16, 2026-10-06): the checker reads `acted_on`, a list the subject
supplies. It therefore establishes that every **declared** behaviour-affecting field is signed — not that the declaration is complete with
respect to the fields the implementation really uses. An adapter that simply leaves `nodeType` out of `acted_on` conformed under R3 as
first written, while still acting on an unsigned `nodeType`: the case R3 exists to catch, defeated one level up by a declaration that is
itself unverified.

That completeness is **not** structurally checkable, and the suite's own vectors show why. N4's `displayName` is served, unsigned and
outside `acted_on`, and is legitimately conformant. Structurally it is indistinguishable from an undeclared `nodeType`; the difference
lives in the implementation, not the document. So "flag every served-but-unsigned field" is not available as a fix.

What the `inert` requirement buys is narrower and worth stating exactly: a served field outside the envelope must now be declared, so it
can no longer conform by **omission** — only by asserting it is inert (N6). That converts a silent gap into an accountable claim. Its
truthfulness remains a code-binding / provenance obligation, outside this suite. M4 — the old R3, unchanged — is killed by N5, so the
requirement is load-bearing rather than decorative.

**Scope.** The vectors are structural: they test the three rules over record ids and declared field sets. They do not test a signature
scheme, the retention key, or the equivocation detector (signature-keyed retention is a base-8309 change; the divergence/equivocation
boundary is already test-locked in ccip-router#3). Stdlib only.
