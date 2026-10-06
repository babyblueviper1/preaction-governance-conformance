# x402 payment fingerprint — `x402-payment-fingerprint/0` (draft, CC0)

A worked recipe plus vectors for the "Evidence lane" idea in [x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4): buyer and seller each derive the **same** digest from the payment they both saw, so their records join without either side minting a reference number.

```
fp = sha256( JCS({ "v": "x402-payment-fingerprint/0",
                   "network": CAIP-2 ("eip155:<chainId>"; v1 aliases such as "base" are mapped),
                   "asset":   token contract, lowercase,
                   "from":    authorization.from, lowercase,
                   "to":      authorization.to, lowercase,
                   "value":   authorization.value, canonical decimal string,
                   "nonce":   authorization.nonce, lowercase bytes32 hex }) )
```

Input is the EIP-3009 `exact` authorization both parties hold, from a v1 `PaymentPayload` or the v2 equivalent, plus the requirement's network and asset.

## Why it normalizes: the failure it prevents
A naive recipe, sha256 over the JSON each party holds, gives **4 different digests for 4 honest copies of one payment** (`vectors.json` P1). The copies differ in:
- the v1 vs v2 envelope;
- `"base"` vs `"eip155:8453"`;
- checksummed vs lowercase addresses;
- object key order;
- the signature itself: ECDSA is malleable, and `(r, s)` and `(r, n−s)` both verify.

Under a naive digest, the join fails and the payment looks missing from one side, which is the dispute the lane is meant to prevent. The recipe gives one digest for all four.

**Excluded on purpose:** the signature, `validAfter`/`validBefore`, and the envelope (`x402Version`, `resource`, `extra`). On EVM the token marks `(from, nonce)` as used (`AuthorizationUsed`). So `(network, asset, from, nonce)` identifies at most one settlement, and anyone can check a fingerprinted record against the chain ("only settled payments count"). `to` and `value` bind the record to its content.

## Vectors
`vectors.json` holds 11 vectors.

| group | what it pins |
|---|---|
| `same-1-*` (×4) | buyer v1 / seller v2 / malleated signature / reordered keys → **one** fingerprint |
| `diff-*` (×3) | new nonce (a repeat purchase), other value, other network → different fingerprints |
| `bad-*` (×4) | value as a JSON number, value with a leading zero, unknown network alias, short nonce → `malformed` with a named condition (never a guess) |

To check them:
- `python3 run_vectors.py`: every expectation matches, copies of one `payment_id` share one fingerprint, and different payments differ.
- `python3 build_vectors.py`: regenerates `vectors.json` byte-identically.

## Open questions (for the group, not settled here)
- **Other schemes:** non-EVM and non-`exact` schemes need their own input mapping. The recipe is EVM `exact` only.
- **Nonce derivation:** if #3220/#3226 settle on one way to derive the nonce, the recipe is unaffected. It consumes the nonce as signed.
- **Version string:** the recipe string is versioned so a later shape change cannot claim `/0` (the x402ev/1 lesson in this thread).
