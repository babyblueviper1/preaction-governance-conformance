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
