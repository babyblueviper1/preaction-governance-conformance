# x402 receipt + AP2 mandate: `x402-receipt-ap2-mandate/0` (draft, CC0)

Settlement proves payment. A mandate proves consent. This kit checks that they are about the same payment: the user
consented to this cart and this payment, and the authorization the user consented to is the one that settled.

## What already links them
AP2's embedded x402 flow ([google-agentic-commerce/a2a-x402](https://github.com/google-agentic-commerce/a2a-x402) spec v0.2,
sec 4) chains three signatures through one value:
- **The merchant signs the cart.** `CartMandate.merchant_authorization` is a JWT whose `cart_hash` covers the `CartContents`.
- **The user signs consent.** `PaymentMandate.user_authorization` is an SD-JWT VC. Its key-binding JWT carries
  `transaction_data`, the hashes of the `CartMandate` and the `PaymentMandateContents`.
- **The consent embeds the payment.** The `PaymentMandateContents` embed the x402 `PaymentPayload`, which is the signed
  ERC-3009 authorization with its `nonce`.

An x402 receipt v2 ([x402#3827](https://github.com/x402-foundation/x402/pull/3827)) carries `authorizationCommitment`, a
salted commitment to that same nonce (the construction is in
[`../x402-receipt-authorization-commitment`](../x402-receipt-authorization-commitment)). So whoever holds the receipt, its
salt and the two mandates can follow the chain from consent to settlement without trusting the seller, the buyer's agent
or us.

## What `check()` verifies, in order
The first link that fails names the result.

| link | result if it fails |
|---|---|
| The trusted issuer vouches for the user's key (`cnf`), and that key signs the key-binding JWT (`sd_hash` included). | `consent_invalid` |
| The consent's `transaction_data` holds the hashes of this `CartMandate` and these `PaymentMandateContents`. | `consent_not_bound` |
| The merchant's JWT signs the hash of these cart contents. | `cart_not_merchant_signed` |
| The consented authorization pays the cart's x402 `payTo`, on its network and scheme, no more than `maxAmountRequired`. | `terms_mismatch` |
| The receipt's signed `payer` is the authorization's `from`, and its commitment opens to the authorization's nonce with the salt. | `receipt_not_this_authorization` |
| That nonce was consumed on chain (`AuthorizationUsed`), and the transaction moved the consented amount to the consented payee. | `no_settlement` / `settlement_terms_mismatch` |
| If the log query failed, or the transfers could not be read, the result is an incomplete check, never "no settlement" (x402#3827 sec 5.6.4). | `incomplete_check` |

All links hold: `consented_and_settled`.

## Data
The positive vector uses a real settlement, the same one the two sibling kits use:
- **Transaction:** Base Sepolia USDC, tx `0x1345479a…de88`, block 48163177.
- **Authorization:** read from the transaction's own calldata. `transferWithAuthorization(from 0x87f3…6ee1, to 0x2888…ec26, value 1000, validAfter 0, validBefore 1792094854, nonce 0xc012…0c83)`, with its real v/r/s.
- **Logs:** `AuthorizationUsed` at logIndex 180, `Transfer` at 181.
- **Receipt:** its commitment (`0x905370…1438`) is the one in the private-opening kit's receipt.

The cart, the mandates and the issuer, merchant and user keys are **public test keys** derived from fixed seeds, so
everything runs offline.

Each negative vector breaks one link:
- consent signed by another key;
- an untrusted issuer;
- consent to another cart;
- a cart the merchant did not sign;
- an authorization paying another wallet;
- an authorization above the cart price;
- a receipt naming another of the payer's settled nonces;
- consent to a nonce never consumed;
- a failed log query;
- unread transfers;
- a settled amount that differs.

Seven lax checkers each fail at least one vector.

```
$ python3 run_vectors.py
  PASS consented-and-settled
  ... 12/12 vectors
  caught skips_consent_signature: consent-signed-by-another-key, consent-issuer-untrusted
  caught skips_cart_binding: consent-for-another-cart
  caught skips_merchant_signature: cart-not-what-merchant-signed
  caught trusts_mandate_terms: authorization-pays-another-wallet, authorization-above-cart-price
  caught skips_receipt_link: receipt-names-another-authorization
  caught consent_is_settlement: consented-but-never-settled, chain-unavailable, settlement-transfers-unread, settled-amount-differs
  caught unavailable_as_no_settlement: chain-unavailable, settlement-transfers-unread
  PASS vectors.json reproduces from build_vectors.py
ALL PASS
```
Standard library only (Python 3.9+). Ed25519 comes from the sibling kit's `ed25519_ref.py`.

## What it does not claim
- **The ERC-3009 signature.** The kit does not re-check it. The USDC contract checked it when it consumed the nonce, and that consumption is the chain leg here.
- **AP2's hash encoding.** AP2 does not pin the encoding of `cart_hash` and `transaction_data` yet. This kit uses `base64url(sha256(canonical JSON))`, which is a choice to settle with AP2, not a claim about it.
- **Expiry windows, selective disclosures, key resolution.** Trusted issuer and merchant keys are inputs; the user credential here discloses nothing.
- **AP2's own format.** The JWTs are EdDSA (RFC 8037) and the SD-JWT has no disclosures, so this is a worked example of the binding, not a conformance test of AP2.
- **Privacy.** The mandate carries the nonce, so whoever holds it can find the settlement. To keep the payment private,
  open it to one verifier, which signs the result without the nonce, as in
  [`../x402-receipt-private-opening`](../x402-receipt-private-opening).

## Files
| file | what |
|---|---|
| `mandate_check.py` | `check(bundle, chain, trusted)`, JWT (EdDSA) helpers, the hash used for `cart_hash` and `transaction_data` |
| `build_vectors.py` / `vectors.json` | the 12 vectors (1 real positive, 11 one-link-broken) |
| `run_vectors.py` | checks the vectors, the 7 lax checkers, and that the file reproduces |
