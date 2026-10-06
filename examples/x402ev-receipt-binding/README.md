# x402ev/1 receipt binding: vectors for x402 PR #3682

These vectors are for `execution_evidence.md` in [x402-foundation/x402#3682](https://github.com/x402-foundation/x402/pull/3682), at head `6456f98`. Two implementations must agree on two things byte for byte, and the draft leaves both open.

**1. What `evidenceRef` hashes.** The example's `evidenceRef` carries the same hex as `delivery.contentDigest`. Under that reading, two different paid calls that return the same bytes get the same `evidenceRef`, for example a cached price served twice. The reference then names a response, not a paid delivery.

**2. Which bytes `signer.signature` covers.** The draft says to canonicalize "the receipt body". But `info` also holds the signature itself, and it holds `transparency`, the inclusion proof, which only exists after the receipt is logged.

## Proposed rule (one way to close both; not adopted anywhere)

```
body        = info minus {evidenceRef, signer.signature, transparency}
evidenceRef = "x402ev/1:sha256:" + hex(sha256(JCS(body)))
signature   = Ed25519 over JCS(body)
payment.fingerprint = x402-payment-fingerprint/0 (tsc#4) of the EIP-3009 authorization
```

The payment fingerprint lets the delivery receipt join the buyer's, the seller's and the acceptance record on one shared key. That works even before a `txHash` exists. The recipe and its vectors are in [`../x402-payment-fingerprint`](../x402-payment-fingerprint).

`python x402ev_binding.py` builds `vectors.json` deterministically and runs these checks:
- Under the example's reading, two paid calls collide on one `evidenceRef`; under the rule they do not.
- Both receipts verify against the response bytes the client holds.
- Adding the transparency proof after signing changes neither the `evidenceRef` nor the signature check.
- A delivery field changed after signing fails both the `evidenceRef` and the signature.
- Different response bytes fail `contentDigest`.
- The payment fingerprint matches across the records.

The signing key is a test-only Ed25519 key (seed `00 01 .. 1f`). The checks need the `cryptography` package.

## A concrete example for the spec (`spec_example.py` -> `spec_example.json`)

PR #3682's example at `e7b7c607` uses placeholder values (`0x1234...abcd`, `sha256:b5a2c6d8e0f1...`), so its stated `evidenceRef` does not
recompute under its own Receipt Body rule. `spec_example.json` is the same shape with every value real: the payment is the EIP-3009
authorization of fingerprint vector P1 (so `payment.fingerprint` recomputes), the request and response digests are over the bytes in the
script, and the signature is by the test key. `python spec_example.py` re-derives `evidenceRef`, verifies the signature, and checks that
attaching `transparency` changes neither. Deterministic.
