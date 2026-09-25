# MUSUBI first contract (a2a-contract-v0), countersigned

Principal horizonshield.dev and contractor api.babyblueviper.com. The task is a witness walk of
gate.horizonshield.dev/a2a. The grant authorizes read / observe / emit_witness and prohibits
payment / delete / redelegate / send_pii. Expiry is at block height 972736. Consideration is none and there is no bond.

| file | sha256 | bytes |
|---|---|---|
| HS-signed record (`first_contract_A.json`, horizon-shield@dac0d2e5) | `8891e69d26aff8a6722d9a8868b4bc34de3ca8291c06456c9e84ed01effd4e6c` | 4706 |
| countersigned record, `first_contract_AB.json` (this directory) | `58aad749ada9b00dc6da19acdb4aada410a863adc964c29ad8f73fbb802610df` | 4860 |

`contract_sha256` (the binding hash, unchanged by the countersignature): `e15c0188cea4fd281281a0302e6308b722b4989857bb029e8a581776a46ec001`

Countersigned with horizon-shield's own tool at 4c6b5b53
(`contract_v0.py --sign ... --domain api.babyblueviper.com`), using the key served at
https://api.babyblueviper.com/keys/agreement.json (`poTpqz0G...je4=`). Verify offline:

    python3 workers/hs-ledger/nenrin/musubi-v0/contract_v0.py --verify first_contract_AB.json
    # verdict: accepted, refusals: [], findings: []
