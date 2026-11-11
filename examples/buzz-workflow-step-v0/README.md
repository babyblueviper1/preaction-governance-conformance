# Buzz workflow-step fixture: signed approval + exact release digest + checker receipt (v0)

For block/buzz#4179 (StevenMih): the checker gets the **signed approval event bytes** and the **digest of the exact proposed release**, checks both before anything else, and our **signed receipt** references both, so any checker can run on the same bytes.

| file | proposed release | approval names | result |
|---|---|---|---|
| `positive.json` | buzz-agent 1.4.0 (`9b6e839c...`) | the same digest | RELEASE |
| `negative_release_not_approved.json` | buzz-agent 1.4.1 (`86de75b3...`) | the 1.4.0 digest | HOLD (approval not bound to this release) |

- `approval_event`: a NIP-01 / BIP-340 event signed by a **test approver key generated for this fixture** (`3dbfc780...`; a real gate pins its approvers). Its content carries `approves_release_sha256`.
- `proposed_release_canonical`: the release action as sorted-key compact JSON; its sha256 is the release digest.
- `receipt`: our verdict, signed by the invinoveritas production key `6786e18a...fbb7`, over `{approval_event_id, release_sha256}` (`receipt_artifact_canonical`). Both receipts also verify at `POST https://api.babyblueviper.com/verify-proof`.

## Check (offline, stdlib only)

```
python3 check.py positive.json negative_release_not_approved.json
```

Order: (1) approval id + signature, (2) approval names this release, (3) receipt id + signature + pinned key, (4) receipt bound to that approval + release, then the verdict. The negative fails at (2), before the receipt is read.
