# What counts as an independent second-issuer run (trace-spec #397 / #398)

The TRACE-core bar for the vantage_limitation and related_claims markers is that an **independent** second issuer passes the checker **unchanged**. This file defines both words ahead of time, so a run can't be disputed after the fact and can't be settled by a proxy.

We (the proposer) do not decide whether an issuer qualifies. The TRACE maintainers adjudicate that. What we provide is a mechanical check that a claimed run is real and reproducible.

## 1. Independence: disqualifying relationships

An issuer does **not** count if any of these holds:

- the proposer (babyblueviper1 / invinoveritas) controls, operates or co-maintains it, or holds its signing keys;
- the proposer paid, funded or compensated the issuer for this run or for adopting the marker;
- it is operated by, or created at the request of, a TRACE maintainer;
- its records were produced by the proposer's software or signing service rather than the issuer's own emission path;
- it came into existence only to make this run (a nominally separate shell).

The issuer declares each point in its run attestation (the `independence` block). Declarations can be false, and the maintainers may ask for provenance: repository history, prior public activity, operator identity. A dispute is settled on #397 / #398 by the maintainers.

## 2. Unchanged and reproducible: the run attestation

The issuer publishes, **itself**, at an https URL it controls, a `trace-issuer-run.v1` attestation:

| field | meaning |
|---|---|
| `checker` | `vantage_limitation` or `related_claims` |
| `checker_commit` | the commit of this repository whose checker was run (b403534 or a later commit that leaves the checker unchanged) |
| `profile` | `{path, sha256}` of the issuer's `trace-issuer-profile.v1` |
| `inputs` | `[{path, sha256}]` of every record, and of the claims file for related_claims |
| `argv` | the exact arguments, which must pass the declared profile with `--profile` |
| `exit_code`, `output_sha256` | what the issuer got: exit 0 and the sha256 of stdout |
| `environment` | Python version and OS, for the record |
| `independence` | `not_controlled_by_proposer`, `not_funded_by_proposer`, `not_maintainer_affiliated`, `records_emitted_by_issuer_own_software`, `published_by_issuer`, each `true` |
| `published_at_url` | where the issuer published this attestation |

The issuer's profile and records are added to this repository by PR, without modification, so anyone can rerun the check.

## 3. The mechanical check

    python3 tools/issuer_run_check.py <attestation.json>

It confirms, from the repository rather than from the attestation:

- the checker commit exists;
- the checker and everything it loads are byte-identical to that commit;
- every file matches its declared hash;
- a fresh rerun gives the declared exit code and output hash;
- the result is a pass;
- every independence declaration is made and the attestation URL is https.

A PASS means **the run reproduces and the declarations were made**. It does not mean the declarations are true; that judgement is the maintainers' (section 1).

## The demonstration attestation fails, on purpose

`run_attestation.demo.json` is our own demonstration issuer. Its run reproduces exactly: the commit, the unchanged checker, the hashes, the exit code and the output all pass. It then **fails** the independence line and the publication line. That is the correct result: a proposer-built issuer must never be able to settle the bar.
