# A live work-acceptance record bound to the x402 payment it concerns

One record from the invinoveritas checker (`invinoveritas-checker-a4cecab2`), issued 2026-10-21, for a deliverable that was
bought with a real x402 payment on Base mainnet. It is offered as input for a payment-anchored vector
(x402-foundation/tsc#4: a phase-one record type "carries or references the x402 payment it concerns").

## The chain, in order

| Step | What | Evidence in this folder | Time |
|---|---|---|---|
| 1 | Criteria committed before the work | `criteria.json`, `criteria.tsr` (FreeTSA; DigiCert token in `record_input.json`) | 2026-10-21T16:08:10Z |
| 2 | x402 payment: 0.10725 USDC, payer `0x89eA…55c2` -> payTo `0x161D…7Fb9`, EIP-3009 nonce `0xc22d545f…3acbe257` | `x402_payment.json` | settled in tx `0x7c3cde41…48e87ff`, Base block 52904784 |
| 3 | Deliverable served for that payment (the `/reason` response body) | `deliverable_reason_response.json` (sha256 `810a94e8…74c37b`) | |
| 4 | Work-acceptance record (Trilatic 1.2 shape), verdict `pass` | `record.json`, `receipt.tsr` | 2026-10-21T16:09:34Z |
| 5 | Payment reference, joined to the record by digest | `bindings_sidecar.json`: `receipt_sha256` + `bindings.x402_authorization_nonce`, Ed25519 by the checker key | |

## Check it from bytes and the public chain

1. Record: `war_check.py` (../work-acceptance-record-cold) on `record_input.json` -> signature valid, criteria hash match,
   criteria committed before the check, receipt imprint match, verdict recomputed `pass`, no problem codes.
2. Join: `sha256(JCS(record.receipt)) == bindings_sidecar.receipt_sha256` (`39dbf4db…005498f`); the sidecar signature is Ed25519
   with the same checker key over the JCS sidecar without its `signature` and `producer` fields.
3. Payment: on Base, tx `0x7c3cde41d3ead1a391ad3114f0096359c0b99f740ada9514356e7277048e87ff` emits USDC
   `AuthorizationUsed(authorizer = 0x89eA40a908505aA15Ee50eE3a9Fa0399716755c2, nonce = 0xc22d545f0ad374247fb544bdacf62b2bc9856eab8cce801f440c630c3acbe257)`
   and `Transfer(0x89eA…55c2 -> 0x161D…7Fb9, 107250)`. `(asset, payer, nonce)` is the payment's identity, so the nonce in the
   sidecar names exactly one settlement.
4. Deliverable: `sha256(deliverable_reason_response.json) == record.receipt.files.remediated.sha256`.

## What this does not show

- **Independence is key-based only.** The producer (`/reason`, payTo `0x161D…7Fb9`) and the checker are both operated by
  invinoveritas. The record's `"independence": "independent"` is the profile's key comparison (checker key != producer key);
  it is not organisational independence. The vector is about the payment anchor, not independence.
- **The payment reference is outside the signed receipt.** Trilatic 1.2 has no field for it, so it lives in a sidecar
  signed by the checker and joined by receipt digest. If the profile gains a payment field (for example an x402 settlement
  anchor inside `receipt`), the reference moves inside the signed and timestamped bytes; until then the sidecar is not
  timestamped on its own.
- The criteria were judged by a model; the results are the checker's findings, not a ruling.
