# horizon-shield#51 acceptance set

Four work-acceptance records issued by the invinoveritas checker for the
[horizon-shield#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51) pilot, published with the consent of both
counterparties on that thread (aeoess and HORIZON SHIELD, 2026-10-22). Each file is the full issuer response exactly as sent to
them on 2026-10-22: the signed record, its timestamp tokens, the criteria file, the key set and the bindings sidecar.
`SHA256SUMS` lists the sha256 of each file's bytes.

| file | verdict | execution receipt | request occurrence |
|---|---|---|---|
| `hs51-musubi-2-A.json` | pass | `a8fe39e0…` | `329a112e…` |
| `hs51-musubi-2-B.json` | fail | `66facb13…` | `c13a8c64…` |
| `hs51-aps-A.json` | pass | `2430a67c…` | `456eddc8…` |
| `hs51-aps-B.json` | fail | `5949b2ce…` | `eb82701a…` |

All four are against criteria `6d62ca38…` (committed 2026-10-18 by RFC 3161, before the check) under checker key
`invinoveritas-checker-a4cecab2`. Each record's bindings sidecar names its own execution receipt and request occurrence, so no
record can be moved to another call. The B audits fail three of four criteria: the audit names fixture `1f75bcab…` instead of
`c2ed811e…`, omits the 高圧洗浄 line, and totals 792,000 against the fixture's 837,000. The A audits pass all four.

## Checking them yourself

The reference verifier is `maximusrufus/work-acceptance-record` at `6b2f730` (`verifier/war_verify.py`, standard library only).
It reads its own vector layout, so wrap a file's fields as `inputs`:
`criteria_file_base64`, `criteria_tsr_base64`, `keys`, `receipt` (= the file's `record`), `receipt_tsr_base64`, and
`tsa_roots_base64` taken from that repository's vectors 31 (FreeTSA) and 32 (DigiCert). Then
`python3 war_verify.py --outcome <vector>.json`.

Our run on 2026-10-24, on these exact bytes: for all four, `signature_valid` true, `independence` independent,
`criteria_committed_before_check` yes, `receipt_timestamp` imprint_match, `tsa_signature` verified for both the criteria and the
receipt tokens, no problem or warning codes; the verdict recomputes to the stated one (A pass, B fail). That is our run; the
counterparties have not repeated it.
