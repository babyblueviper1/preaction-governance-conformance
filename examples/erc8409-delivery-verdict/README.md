# ERC-8409 delivery verdict: a receipt field that ties a disputed API response back to the quote

[ERC-8409](https://github.com/ethereum/ERCs/pull/1990) signs what was priced (`quoteDigest` over issuer, payer, amount, `requestHash`, ...).
It does not say what was delivered. This example adds one optional receipt field: an independent signed verdict on
"does this response deliver what the quoted request asked for", bound to the quote digest and to the exact response bytes.
A gateway outcome such as *paid, not delivered* then carries evidence from a party with no stake in the payment.

## The receipt field

```jsonc
"deliveryVerdict": {
  "scheme": "invinoveritas.delivery-verdict/1",
  "quoteDigest": "0x…",            // ERC-8409 EIP-712 digest of the paid quote
  "deliveryRecordSha256": "…",      // sha256(RFC 8785 JCS(deliveryRecord))
  "verdict": "approve | reject",    // approve = delivered as quoted, reject = paid, not delivered
  "proofEventId": "…",
  "proof": { "id", "pubkey", "created_at", "kind", "tags", "content", "sig" }   // signed verdict (NIP-01 / BIP-340)
}
```

The `deliveryRecord` is what was judged: the quote reference, the canonical request, and the response (status, content type, body, `bodySha256`).
The proof's signed `artifact_hash` is `sha256(JCS(deliveryRecord))`, so the verdict cannot be moved to another quote or another response.

## Checking it (`check.py`, offline, trusts neither the presenter nor our API)

1. **quote:** recompute `quoteDigest` from the 8409 envelope and recover the issuer from the signature.
2. **request:** `keccak256(canonical request bytes) == quote.requestHash`.
3. **record:** the record names that quote; `sha256(response bytes you hold) == response.bodySha256`.
4. **binding:** `sha256(JCS(deliveryRecord)) ==` the proof's signed `artifact_hash`.
5. **proof:** the NIP-01 id recomputes, the BIP-340 signature verifies, and the pubkey is the published key ([verifier-keys.json](https://api.babyblueviper.com/.well-known/verifier-keys.json)).
6. **verdict:** the receipt's `verdict` equals the signed one.

The same proof also checks online, free, with no auth: `POST https://api.babyblueviper.com/verify-proof {"event": …, "expect_artifact_hash": deliveryRecordSha256}`.

## Vectors (`vectors.json`)

The quote is signed with the ERC's public test key (`0x…01`) on chain 8453 for 1 USDC. It is the ERC's canonical structure, with a real
`requestHash` over an example request scheme. `quoteDigest = 0x48f1be2181771208981ebac78f2c01a5f224c7942e6149085c3e0f05dc81948f`.

| case | response | signed verdict |
|---|---|---|
| `delivered` | HTTP 200, 7 forecast entries | `approve` |
| `paid_not_delivered` | HTTP 200, `"forecast": []` | `reject` |

Both verdicts are real `/review` calls with `sign=true` (policy `invinoveritas.review.v22`); the data is synthetic and no payment was made.
`check.py` also runs 6 mutations, each failing exactly the step it targets: amount changed after signing (1), a different request (2),
different response bytes (3), the approve proof moved onto the not-delivered record (4), the signed verdict edited (5),
and a receipt claiming approve over a signed reject (6).

    pip install eth-account            # rfc8785 optional
    python check.py                    # ALL PASS

The ERC-8409 digest code (`q8409.py`) reproduces the ERC's own canonical vector exactly: `quoteDigest` `0xc80f6a3d…`,
the RFC 6979 signature byte-for-byte, the recovered issuer, and all four mutation digests.

## What it does not establish, and how to close it

The verdict judges the bytes it was given. With `source_class: agent_reported`, it does not prove those bytes are what the provider actually
sent. A gateway already sits in the path, so it can capture the response itself and sign the review request with its own key
(`mediator_attestation`, bound into the proof as `mediator_attestation_hash`). The record then also says who captured the bytes.
That attests key control at capture time, not independence. The example request scheme is for this vector only; a real binding would use
the gateway's own request scheme.
