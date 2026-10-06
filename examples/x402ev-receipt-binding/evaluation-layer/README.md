# CORRECT_DELIVERY over x402ev/1: an evaluation record bound to the receipt

PR #3682's claim ceiling keeps `VALID_x402ev != CORRECT_DELIVERY`: a valid receipt proves the server signed a delivery of these bytes
for this paid call, not that the bytes answer the request. This folder is one worked shape for the next tier, built on the spec's own
example receipt (`receipts.json["delivered"]` is byte-identical to the spec example at `8acbe49`, `evidenceRef de717d35…`).

The evaluation record names the receipt by `evidenceRef` (the paid delivery event) and carries the bytes behind its digests:

```json
{"scheme": "invinoveritas.delivery-evaluation/1", "evidenceRef": "x402ev/1:sha256:…", "contentDigest": "sha256:…",
 "request": {"method", "urlHash", "payloadHash"}, "request_payload": "…", "response_body": "…", "question": "…"}
```

An independent evaluator signs a verdict over `sha256(JCS(record))`. It stays separate from the receipt's validity rules, as discussed
on the PR, so the receipt never inherits the evaluator's correctness claim.

| case | response | signed verdict |
|---|---|---|
| `delivered` | the spec example's one-sentence answer | approve |
| `empty` | `{"output":""}` for the same paid request | reject |

`python check.py` verifies offline, trusting neither the presenter nor the evaluator's API:
1. receipt: `evidenceRef` recomputes and the server's signature verifies;
2. subject: the record names that receipt, and both digests recompute from the bytes it carries;
3. binding: the record hash is the verdict's signed `artifact_hash`;
4. proof: NIP-01 id, BIP-340 signature, the evaluator's published key.

Five mutations each fail the step they target: a receipt edited after signing, the approve evaluation presented for the other receipt,
the record swapped to the delivered bytes, the approve proof moved onto the empty record, and a signed reject edited to approve.
Verdicts are real `/review` calls (`sign=true`); the data is synthetic and no payment was made. `build_records.py` rebuilds the
receipts and the unsigned records deterministically.
