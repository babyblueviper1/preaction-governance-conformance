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
`vectors.json` holds 15 vectors.

| group | what it pins |
|---|---|
| `same-1-*` (×4) | buyer v1 / seller v2 / malleated signature / reordered keys → **one** fingerprint |
| `diff-*` (×3) | new nonce (a repeat purchase), other value, other network → different fingerprints |
| `bad-*` (×8) | value as a JSON number, value with a leading zero, unknown network alias, short nonce, trailing newline on value, trailing newline on nonce, `scheme` other than `exact`, value past `uint256` max → `malformed` with a named condition (never a guess) |

**Fixed 2026-10-06**, after an independent clean-room re-implementation + differential fuzz against this recipe (x402-foundation/tsc#4, robertolocatelli81-dev/Noûs) found two real acceptance bugs: the four field regexes anchored on a trailing `$`, which in Python also matches just before a final `"\n"`, so `value`/`nonce`/`network`/`asset` with a trailing newline were silently accepted and hashed as a distinct, valid fingerprint instead of being refused; and `scheme` was carried in the payment but never checked, so a Permit2 `upto` authorization (EIP-3009 `transferWithAuthorization` is not supported for `upto` on EVM) fingerprinted identically to an `exact` one. Both are fixed (hard end-of-string regex anchors; `scheme` must be `"exact"` or the result is `malformed`/`scheme_not_exact` — `scheme` is validated, never hashed, so no existing vector's fingerprint changed) and pinned with 4 new vectors. Also added: a `value_exceeds_uint256` check (ERC-3009 `value` is a `uint256`), and `run_vectors.py` now returns `malformed`/`envelope_unreadable` on an unreadable envelope instead of raising.

To check them:
- `python3 run_vectors.py`: every expectation matches, copies of one `payment_id` share one fingerprint, and different payments differ.
- `python3 build_vectors.py`: regenerates `vectors.json` byte-identically.

## Open questions (for the group, not settled here)
- **Other schemes:** non-EVM and non-`exact` schemes need their own input mapping. The recipe is EVM `exact` only (now enforced: a non-`exact` scheme is refused as `malformed`, not silently fingerprinted).
- **Nonce derivation:** if #3220/#3226 settle on one way to derive the nonce, the recipe is unaffected. It consumes the nonce as signed.
- **Version string:** the recipe string is versioned so a later shape change cannot claim `/0` (the x402ev/1 lesson in this thread).
- **Network alias table:** `NETWORK_ALIASES` has 8 entries; the x402 v1 TS `NetworkSchema` has 15 EVM entries and the Go v1 table disagrees with it on 9 aliases (e.g. `ethereum` is Go-only). Either this table becomes normative for `/0`, or `/0` accepts CAIP-2 only and leaves alias mapping to the caller.

`fingerprint.py` imports the vendored RFC 8785 canonicalizer at `../../tools/_rfc8785.py` — the folder is not standalone; run it from a clone of this repo.
