# Independent work-acceptance records: a live issued example

invinoveritas issues work-acceptance records in Trilatic's format
([maximusrufus/work-acceptance-record](https://github.com/maximusrufus/work-acceptance-record)), signed by its own checker key,
never the producer's. The flow:

1. `POST https://api.babyblueviper.com/work-acceptance/criteria` (free): commit the criteria BEFORE the work exists. You get
   two RFC 3161 tokens (FreeTSA, DigiCert) and an OpenTimestamps proof over sha256(criteria). The first commitment of a hash is
   permanent.
2. `POST https://api.babyblueviper.com/work-acceptance/check` (2500 sats, or x402 USDC on Base): the delivered file is checked
   against each criterion (pass / fail / not-evaluated / error; anything that cannot be judged from the file is not-evaluated,
   never a guessed pass), the verdict is recomputed, and the record is signed and timestamped. The file is hashed, never stored.
3. Anyone verifies offline. The checker key is at `https://api.babyblueviper.com/.well-known/invinoveritas-checker-keys.json`.

`selftest-pass.json` is a real record from the live endpoint (2026-10-18; our own sample refund policy, not a real job), laid out
like Trilatic's vectors. The clean-room verifier in [`../work-acceptance-record-cold`](../work-acceptance-record-cold), written from
his README alone, reproduces the `expected` object with no problems and no warnings:

```
python3 ../work-acceptance-record-cold/war_check.py selftest-pass.json
```

What a record attests: our check of that file against those committed criteria. It is a model judgment per criterion (the record's
`tools` field names it), not a warranty that the work is fit for every purpose.

## Reference verifier at profile 1.4.1 (2026-10-22)

All three records here pass Trilatic's own reference verifier at
[maximusrufus/work-acceptance-record @ 6b2f730](https://github.com/maximusrufus/work-acceptance-record/tree/6b2f730) (profile 1.4.1,
55 vectors), including the profile 1.4 time-stamp-authority signature step, with the FreeTSA and DigiCert roots copied unmodified
from upstream vectors 31 and 32 (`tsa_roots/`):

```
python3 war_verify.py --tsa-roots tsa_roots/freetsa_root.pem --tsa-roots tsa_roots/digicert_root.pem --outcome selftest-pass.json
```

Every record: `signature_valid` true, `independence` independent, `tsa_signature` {criteria: verified, receipt: verified}, verdict
recomputed = stated, no problem or warning codes. Full output: `reference_verifier_6b2f730_run.txt`.

## horizon-shield#51 rehearsal (2026-10-18)

Two real records for case A of the three-record pilot in
[ogasurfproject-jpg/horizon-shield#51](https://github.com/ogasurfproject-jpg/horizon-shield/issues/51), issued on the smoke-call
bytes its organiser published at `rehearsal/live_smoke/` (commit `dcbdc5d`, test keys). **Neither is the pilot record**; that one is
issued only on the first logged call. Both are against the committed criteria `6d62ca38…`, and the signed bindings sidecar ties
each one to the responder's execution receipt (`1c01ea21…`) and the request occurrence (`69546501…`, `live-smoke-0`).

- `hs51-rehearsal-caseA-audit-only.json`: the audit judged alone. Criterion c2 (one entry per fixture line) is **not-evaluated**:
  the judge could not see the fixture. The verdict is `incomplete`, not a guessed pass.
- `hs51-rehearsal-caseA-with-fixture.json`: the same audit with the frozen fixture given as a **reference input**. A reference is
  accepted only when its sha256 appears in the committed criteria (here c1 names `c2ed811e…`), so it was fixed before the work.
  All four criteria pass. The reference is named in the receipt's `tools` and in the sidecar.

```
python3 ../work-acceptance-record-cold/war_check.py hs51-rehearsal-caseA-audit-only.json hs51-rehearsal-caseA-with-fixture.json
```
