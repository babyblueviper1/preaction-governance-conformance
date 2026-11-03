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

## Under profile 1.4.2 and later: the producer's key (2026-11-04)

Profile 1.4.2 (`maximusrufus/work-acceptance-record@31c6f6b`, step 10, vectors 80 and 81) added a rule these records predate:
when a record claims `independence: independent` and names a producer `key_id`, that `key_id` must be listed in the key set the
verifier uses. Each file's `keys` lists only our checker key, so under 1.4.2+ all four give `INDEPENDENCE_INCONSISTENT`, as
@robertolocatelli81-dev found with war-verify 0.7.0 ([horizon-shield#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6608111351)).
We reran the reference verifier at `6bb7d0b` on the same bytes, and it agrees:

| key set used | all four records |
|---|---|
| as shipped (checker key only) | `INDEPENDENCE_INCONSISTENT`; signature, both RFC 3161 tokens, commit-before-check and the verdicts (A pass, B fail) unchanged |
| plus the producer's key | no problem codes |

The files are unchanged (`SHA256SUMS` still holds). Take the producer's key from the producer, not from us: a checker that listed
a producer key itself could name a key it holds and certify its own independence. The producer published it
(`7b1ada68cd366c70a79544b6d719d685fd37e01f26549e08bf388768cc7d0ffe`, Ed25519) at its own endpoint,
`https://hs-pilot.oga-surf-project.workers.dev/.well-known/pilot.json` (`responder`), and in
[its comment on #51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51#issuecomment-6246756476). Add it to the
`keys.keys` you pass the verifier as `{"key_id": "7b1ada68…0ffe", "alg": "Ed25519", "public_key_base64":
"exraaM02bHCnlUS21xnWhf034B8mVJ4IvziHaMx9D/4=", "status": "active"}`.

Records issued from 2026-11-04 carry this themselves when the producer co-signs: once a producer adds its Ed25519 signature over
`receipt_sha256` (`bindings_sidecar.producer`), the record we serve lists that key under the record's own producer `key_id`.
Nothing we signed changes, and we list no producer key the producer has not signed with.
