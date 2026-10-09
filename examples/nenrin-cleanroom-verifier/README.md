# nenrin-cleanroom-verifier

A NENRIN provenance-v0 verifier written from the normative procedure alone:
[`provenance-v0/VERIFIER.md`](https://github.com/ogasurfproject-jpg/horizon-shield/blob/main/workers/hs-ledger/nenrin/provenance-v0/VERIFIER.md)
(Oga, T. (2026), DOI [10.5281/zenodo.23136978](https://doi.org/10.5281/zenodo.23136978)). Clean room: no NENRIN verifier source
(the reference, its Go and PyPI ports, or any other implementation) was read while writing it. One file, Python standard library
only, Ed25519 verification implemented in the file (RFC 8032, cofactorless as OpenSSL checks it, plus the s5 key rule: canonical
encoding of a prime-order-subgroup point, not the identity). MIT.

    python3 nenrin_cleanroom.py IN OUT      # TSUNAGI batch contract: IN = [{"name", "bundle"}], OUT = {name: verdict signature}

or as a module: `verify(bundle).signature()` returns `{"verdict", "refusals", "findings"}` (VERIFIER.md section 4).

## Results, refereed by `nenrin-tsunagi` (nenrin-verify 0.4.9), first run, no changes after it

| corpus | reproduced |
|---|---|
| nenrin-interop-v0 | 5/5 |
| nenrin-interop-v0.1 | 13/13 |
| nenrin-interop-v0.2-edge | 36/36 |

`musubi-v0/canonical_vectors.json`: 9/9 (sha256 and byte length).

Fresh edge bundles (`conformance-v0/gen_edge_bundles.mjs`, 40 bundles, new keys, run 2026-10-09): same verdict signature as the
reference on 40/40, compared as sets per section 4. On the two bundles where the board's 2026-10-08 differential shows a split,
`signed|gaction=null` and `signed|gaction missing both`, this verifier returns `refused [execution_invalid] [evidence_bound_unchecked]`,
reading section 5 ("If grant.action ... is missing, null, false, 0 or "", E1 ... fails with action_diverged"). The reference outputs
were produced by running the board's adapter, not by reading it.

## Reproduce

    pip install nenrin-verify
    nenrin-tsunagi run nenrin-interop-v0.2-edge -- "python3 nenrin_cleanroom.py {in} {out}"

CI runs all three corpora through the same referee on every push.
