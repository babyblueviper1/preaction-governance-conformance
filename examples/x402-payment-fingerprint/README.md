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
`vectors.json` holds 55 vectors.

| group | what it pins |
|---|---|
| `same-1-*` (×4) | buyer v1 / seller v2 / malleated signature / reordered keys → **one** fingerprint |
| `diff-*` (×6) | new nonce (a repeat purchase), other value, other network, value `2^256−1` (the bound is inclusive), nonce in uppercase hex (lowercased in the preimage), a 32-character CAIP-2 reference (the CAIP-2 maximum) → different fingerprints |
| `bad-*` (×43) | value as a JSON number, value with a leading zero, unknown network alias, short nonce, trailing newline on value, trailing newline on nonce, `scheme` other than `exact`, value past `uint256` max, no `scheme`; trailing newline on an address, `eip155:0`, a 33-character CAIP-2 reference, trailing newline on network, network as a JSON number, a non-`eip155` CAIP-2 id, a hex chain id (`eip155:0x2105`), an alias in another case (`Base`), asset with 41 hex digits, address with 39 hex digits, address with `0X`, address without `0x`, address with a leading space, nonce with 63 / 65 hex digits, nonce with `0X`, negative value, value of 79 digits, value of 5000 digits (refused before `int()`), `scheme` `EXACT`, `scheme` with a trailing newline, `authorization` that is not an object, `authorization` without `from` / `to` / `value` / `nonce` (each refused with that field's condition, not as an unreadable envelope), a non-hex character in an address and in a nonce, nonce without `0x`, nonce as a JSON number, value and chain-id reference in Arabic-Indic digits, value with an underscore, `EIP155:` in uppercase → `malformed` with a named condition (never a guess) |
| `alias-*` (×2) | a TS-only alias (`abstract`) and a Go-only alias (`celo`), neither in the old 8-entry table → `ok`, pinning the normative table resolution below |

**Fixed 2026-10-06**, after an independent clean-room re-implementation + differential fuzz against this recipe (x402-foundation/tsc#4, robertolocatelli81-dev/Noûs) found two real acceptance bugs: the four field regexes anchored on a trailing `$`, which in Python also matches just before a final `"\n"`, so `value`/`nonce`/`network`/`asset` with a trailing newline were silently accepted and hashed as a distinct, valid fingerprint instead of being refused; and `scheme` was carried in the payment but never checked, so a Permit2 `upto` authorization (EIP-3009 `transferWithAuthorization` is not supported for `upto` on EVM) fingerprinted identically to an `exact` one. Both are fixed (hard end-of-string regex anchors; `scheme` must be `"exact"` or the result is `malformed`/`scheme_not_exact` — `scheme` is validated, never hashed, so no existing vector's fingerprint changed) and pinned with 4 new vectors. Also added: a `value_exceeds_uint256` check (ERC-3009 `value` is a `uint256`), and `run_vectors.py` now returns `malformed`/`envelope_unreadable` on an unreadable envelope instead of raising.

To check them:
- `python3 run_vectors.py`: every expectation matches, copies of one `payment_id` share one fingerprint, and different payments differ.
- `python3 build_vectors.py`: regenerates `vectors.json` byte-identically.

## Open questions (for the group, not settled here)
- **Other schemes:** non-EVM and non-`exact` schemes need their own input mapping. The recipe is EVM `exact` only (now enforced: a non-`exact` scheme is refused as `malformed`, not silently fingerprinted).
- **Nonce derivation:** if #3220/#3226 settle on one way to derive the nonce, the recipe is unaffected. It consumes the nonce as signed.
- **Version string:** the recipe string is versioned so a later shape change cannot claim `/0` (the x402ev/1 lesson in this thread).

## Settled: network alias table is now normative (2026-10-06)
The group raised two options: `robertolocatelli81-dev`/Noûs argued for a closed table embedded in the recipe so every implementation maps one alias to one CAIP-2 id; `magentixai` preferred CAIP-2-only at `/0`, leaving alias mapping to the caller (matching v2). Resolved in favor of the table: CAIP-2-only would refuse this recipe's own motivating example — vector `same-1-buyer-v1`/`same-1-seller-v2` (payment `P1`) exists specifically to show a v1 record holding `"base"` and a v2 record holding `"eip155:8453"` fingerprint identically; without a normative table, `/0` could never join a v1-originated record, which reintroduces the same per-caller mapping-disagreement risk Noûs raised, one layer up.

`NETWORK_ALIASES` is now the verified **union** of the x402 v1 TS `NetworkSchema`/`EvmNetworkToChainId` (15 EVM entries) and the Go `NetworkChainIDs` (those 15 plus 9 more — `ethereum`, `sepolia`, `megaeth`, `monad`, `monad-testnet`, `stable`, `stable-testnet`, `celo`, `flare`), 24 entries total — independently re-read from both files at `x402-foundation/x402@10b2d06b`, not taken from the thread's numbers alone: the two tables agree on every chain id they share, so the union is conflict-free. Append-only going forward: the preimage holds the CAIP-2 form, not the alias, so adding an alias never changes any existing fingerprint (`same-1-*`/`diff-2…4-*` are all byte-identical to before this change); changing or removing an entry would, and needs a new recipe version (`/1`).

`fingerprint.py` imports the vendored RFC 8785 canonicalizer at `../../tools/_rfc8785.py` — the folder is not standalone; run it from a clone of this repo.
