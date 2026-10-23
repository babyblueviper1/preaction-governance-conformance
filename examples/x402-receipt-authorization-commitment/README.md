# x402 receipt authorization commitment — `x402-receipt-authorization-commitment/0` (draft, CC0)

A worked construction, vectors and a live checker for the receipt field discussed in
[x402-foundation/x402#2887](https://github.com/x402-foundation/x402/issues/2887) (with holistis): the signed receipt in
[`extension-offer-and-receipt.md`](https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md)
commits to the payment authorization's on-chain identifier, salted, so the holder of the salt can recompute the link to
exactly one settlement and nobody else can.

```
authorizationCommitment = sha256( "x402-receipt-authorization/0" || 0x00 || method || 0x00
                                  || asset(20) || authorizer(20) || nonce(32) || salt(32) )
```

`method` is `"eip3009"` here: the identifier is the ERC-3009 `nonce`, consumed once per `(asset, authorizer)` and
logged as `AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)`. Every field after `method` has a fixed
length, so the preimage is unambiguous. The seller has the nonce before settlement runs, so the field does not depend on
the settlement result reaching the receipt signer (the `transaction` field does; see #3824 / #3826).

## Why it is needed: the case that motivated it
Two real Base Sepolia payments, same payer, payee and amount, settled in consecutive blocks
(`0x1345479a…`, block 48163177; `0x1a49341e…`, block 48163178). With `transaction` empty, their receipts are identical
apart from `issuedAt`. Had they landed in the same block, nothing on chain would order them. The nonce is the only thing
that tells them apart.

## Why the salt carries all of the strength
The receipt already names `payer`, and `AuthorizationUsed` indexes the authorizer, so one log query returns every
nonce that payer ever consumed. For the payer above that is **12 nonces, in its whole history**
(`candidates_snapshot.json`). An attacker is not guessing a 256-bit nonce; he is testing a list of 12. So:

| construction | result for a receipt holder without the salt | vector |
|---|---|---|
| `sha256(nonce)` | recovered in ≤ 12 hashes | `attack-unsalted` |
| salt derived from public data (`sha256(payer)`, zero, the nonce itself) | recovered; looks protected, isn't | `attack-payer-derived-salt` |
| 32-byte CSPRNG salt, per payment | the same 60-hash search (5 lazy rules × 12 candidates) finds nothing | `attack-csprng-salt` |

## What it claims, and what it does not
Honest claim: **no new pinpointing.** A receipt plus its offer already carry `payer`, `resourceUrl`, `payTo` and
`amount`, which narrow the candidates on chain. The commitment does not narrow them further. A `transaction` hash
does: it turns the narrowed set into a single row. The commitment is not unlinkability.

## Proposed text (for discussion in #2887)
§5.2, receipt payload version 2, two fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `authorizationMethod` | string | Optional | Identifier family the commitment covers. `"eip3009"` is defined. |
| `authorizationCommitment` | string | Optional | `0x`-prefixed hex of the sha256 above. |

- The salt MUST be 32 bytes from a cryptographically secure random source, generated per payment. It MUST NOT be
  derived from the nonce, the payer, or any other field of the receipt, offer or payment.
- The salt is returned to the buyer outside the signed payload, at `extensions["offer-receipt"].info.authorizationSalt`,
  and is never a field of the receipt object, signed or unsigned: forwarding the receipt must not forward the link
  (placement made explicit after holistis's review of x402#3827).
- The receipt does not carry `asset`. A later verifier needs the offer, the paid `accepts` entry, or the `asset` stored
  with the salt; the receipt and the salt alone do not link.
- A rail with no identifier the seller holds before settlement omits both fields. It does not reuse them with another
  meaning.
- §5.3: the version-2 EIP-712 `Receipt` type appends `authorizationMethod` and `authorizationCommitment` (`string`),
  with the existing empty-string rule for unused optional fields.
- §5.5 (both formats): the authorizer is the receipt's signed `payer`, never a value supplied with the salt (so a commitment to
  another party's authorization opens to nothing; vector `link-commit-other-authorizer`, from holistis's review). A verifier holding the salt MAY query `AuthorizationUsed(payer, *)` on the asset, MUST find
  exactly one nonce whose commitment matches, and MAY confirm `authorizationState(payer, nonce)` is true.
- §11: add the "no new pinpointing" statement above, and that a commitment without a CSPRNG salt is equivalent to
  publishing the nonce.

Not covered here: Permit2 and the non-EVM rails. holistis notes that `scheme_exact_svm`'s seller-chosen `extra.memo` is
the same shape (an identifier that exists before settlement), and that a plaintext memo already leaks the link. The
same construction would fit it. That still needs its own `method` value and vectors.

## Files
| file | what |
|---|---|
| `commitment.py` | `commit()` and the holder-side `link()`; malformed input is refused with a named condition; an unimplemented method is `not_attempted`, never malformed |
| `vectors.json` | 20 vectors: 4 commit (incl. the x402 spec §5.4 example), 5 link (incl. swapped salt, other asset, other authorizer), 3 attack, 6 malformed, 2 not_attempted (a method this checker does not implement: not malformed, per §5.3 / §5.6.4) |
| `candidates_snapshot.json` | the payer's 12 consumed nonces (Blockscout, 2026-10-15), so the vectors run offline |
| `build_vectors.py` / `run_vectors.py` | regenerate / check (`python3 run_vectors.py` → 20/20) |
| `check_live.py` | same check against the live chain: Blockscout logs + `authorizationState` over JSON-RPC |

Independently re-run by holistis on 2026-10-15 (18/18, `check_live.py` against the chain), who also contributed the
normative salt requirement and the other-authorizer case.

Test salts are `sha256("x402-rac-test-salt/<label>")` so anyone can regenerate them. They are not valid production salts.

```
$ python3 check_live.py <commitment-A> <salt-A>
12 nonces consumed by 0x87f344b6ec48a936373d774d3de8649deeb66ee1 on 0x036cbd53842c5426634e7929541ec2318f3dcf7e
linked: nonce 0xc01225fc79db19be6ea2afdbbbc195968e121184e39df0b4f62d7f8f5df40c83
  settlement tx 0x1345479a7c529962b1c71138d961b834547ab4e27e43a535f88e148e24f2de88
  authorizationState = True
```

## Second rail: `svm-memo` cross-check

`svm_memo_crosscheck.py` is an independent, stdlib-only implementation of the `svm-memo` method that holistis proposed in
[x402#3830](https://github.com/x402-foundation/x402/pull/3830), written from the spec text alone. It agrees with the
proposer's kit ([holistis/tokenizen@5bad82c](https://github.com/holistis/tokenizen/tree/5bad82c/examples/x402-svm-memo-commitment), 22/22)
on both commit vectors: `python3 svm_memo_crosscheck.py` gives 2/2.

## Opened privately to one verifier

[`../x402-receipt-private-opening`](../x402-receipt-private-opening) is the middle tier: the rater opens the commitment to one named
verifier instead of publishing the salt, and the verifier signs what it found without the nonce, transaction or salt.

## Consent: an AP2 mandate (2026-10-17)

[`../x402-receipt-ap2-mandate`](../x402-receipt-ap2-mandate) follows the same settlement back to the user's consent. In AP2's
embedded x402 flow the user-signed PaymentMandate contains this authorization, so the nonce the user consented to is the
nonce the commitment names. One check covers user consent, merchant cart, terms, receipt and settlement (12 vectors).

## Settlement leg on Arc mainnet (2026-10-17)

The chain leg runs unchanged on Arc mainnet (`eip155:5042`; `eth_chainId` returns `0x13b2`). The payment is a real x402 settlement
through Circle's facilitator, shared by Marce (Lupa): tx `0x5f34e350…01f8d`, block 26020802, status 1. It calls
`transferWithAuthorization` (the `bytes` signature form, selector `0xcf092995`) on Arc's USDC at `0x3600…0000`. In the same transaction:

- `AuthorizationUsed(authorizer 0x933c…501c, nonce 0xece747ce…95f4)` at logIndex 2;
- `Transfer(0x933c…501c -> 0x5b61…9c28, 10000)` at logIndex 4, i.e. 0.01 USDC at 6 decimals. Arc also logs the same movement in its
  native 18-decimal unit (logIndex 3, from `0xff…fe`, 1e16).

The receipt is v1, so there is no commitment to open: the result stops at "settled". One property matters for a v2 receipt on Arc.
The public RPC limits `eth_getLogs` to 10,000 blocks, and blocks are fast (about 26 million since mainnet opened on 2026-09-16), while the
explorer API sits behind a bot challenge. A verifier given only the salt therefore cannot cheaply list the payer's consumed nonces, and
under §5.6.4 it reports an incomplete check, not "does not link". A block locator in the receipt (as in holistis's v2 emitter) makes
the opening a one-block query.

## Live interop with a v2 emitter (2026-10-17)

holistis runs a seller that signs payload version 2 receipts over HTTP (`https://api.tokenizen.nl/api/paid/verify-ownership`)
and published three real Base Sepolia receipts in [holistis/agent-receipt-verify@5719e7a](https://github.com/holistis/agent-receipt-verify/tree/5719e7a/examples).
They carry only what §5.6.4 says a later verifier has: the receipt, its salt and the asset. The three payments have the same
payer, payee, amount and resource, minutes apart. `check_live.py`, which shares no code with his JavaScript verifier,
resolves each one to the settlement he listed, from the payer's full set of 15 consumed nonces:

| receipt | settlement our check reached |
|---|---|
| `receipt-live-base-sepolia.json` | `0xed87b09b…dfeb30` |
| `receipt-live-base-sepolia-2.json` | `0x2898d0ce…acfe36b` |
| `receipt-live-base-sepolia-3.json` | `0x2a9e95d6…8d7199` |

Exit codes follow §5.6.4 as amended in x402#3827 (faa611f): `0` linked, `1` the candidate set was obtained and nothing
matched, `2` incomplete check (the candidate set or `authorizationState` could not be obtained). A rate-limited or failed
log query is never reported as "does not link".

## Receipt-level vectors and a third checker (2026-10-23)

Contributed by magentixai, as offered on [x402#3827](https://github.com/x402-foundation/x402/pull/3827). The 20 vectors above
test commit and link on their own; these 29 start from a **signed receipt** and run it through section 5.5 (format, payload
version selects the EIP-712 types, signature, signer) and then section 5.6.4, with the six result names at
[`fe777a4`](https://github.com/babyblueviper1/x402/blob/fe777a4e02f3b55e76a246f17bc3ddc616ba3a9c/specs/extensions/extension-offer-and-receipt.md).

`receipt_check.py` was written from the specification text alone, without reading `commitment.py`, `build_vectors.py`,
`run_vectors.py`, `check_live.py` or holistis's verifier, so it is independent of both existing checkers. Standard library
only: it carries its own keccak-256 and secp256k1, because `hashlib` has neither.

| file | what |
|---|---|
| `receipt_vectors.json` | 29 vectors (CC0): 2 linked, 1 inconsistent, 6 no_match, 2 incomplete, 5 not_attempted, 2 malformed, 5 receipt rejections, 3 JWS (ES256K), 3 proposed |
| `receipt_check.py` | the checker; `python3 receipt_check.py` gives 29/29 |
| `build_receipt_vectors.py` | regenerates the vectors byte for byte (RFC 6979 signatures, test key from a public label) |
| `candidates_snapshot_2026-10-23.json` | the same payer's consumed nonces, now 19; the first 12 equal `candidates_snapshot.json` |

The settlement side is real: link vectors run against the 12-nonce snapshot, and the committed nonces are settlements A and B
(blocks 48163177 and 48163178). Only the receipt signer is a test key.

Covered, beyond the six results:

- `receipt-v2-signed-with-v1-types` and `receipt-v1-signature-relabelled-v2`: a version 2 receipt never verifies through the
  version 1 types, and a version 1 signature cannot carry a commitment added afterwards. The compatibility argument rests on this.
- `receipt-v2-incomplete-rate-limited` against `receipt-v2-no-match-empty-set`: a failed query that returns `[]` is incomplete;
  a query that succeeded and returned nothing is a finished check.
- `receipt-v2-no-match-two-candidates`: an identifier that appears twice fails closed.
- `receipt-v2-not-attempted-unsupported-method`: the receipt-level form of 935e3e5.

**Three vectors are marked `"proposed": true`** because the text does not settle them. Each states the result I think is right;
please accept or change it:

1. `receipt-v1-carrying-commitment-fields`: a version 1 payload with the two fields present. The version 1 types do not cover
   them, so the signature verifies without signing them. Proposed: `not_attempted`, because a verifier must not link on
   unsigned fields.
2. `receipt-v2-commitment-not-32-byte-hex`: both fields set, commitment not 32 bytes. Proposed: `malformed`, not `no_match`.
3. `receipt-v2-salt-inside-payload`: the salt placed inside the payload, which 5.6.3 prohibits. EIP-712 ignores the extra key, so
   the signature still verifies. Proposed: the verifier never takes a salt from the receipt, so with none held otherwise the
   result is `not_attempted`.

Cross-checks run before submitting (not needed to run the vectors): every signature verdict agrees with eth-account
(EIP-712) and with `cryptography` (ES256K), 28/28; the checker reproduces the 9 commit and link vectors above whose expected
values are commitments or link results; it reproduces the section 5.4 version 2 example commitment.

Live receipts: run over holistis's three Base Sepolia receipts
([holistis/agent-receipt-verify@5719e7a](https://github.com/holistis/agent-receipt-verify/tree/5719e7a/examples)), each one
verifies under the same signer (`0x4e1174b7…159a`) and links to the settlement in the table above, from 19 candidates:

```
$ python3 receipt_check.py --live receipt-live-base-sepolia.json
receipt valid, signer 0x4e1174b774643b6ad9ee966a81ea1e3665d1159a (authorisation not checked)
link linked against 19 candidates: nonce 0x1120412c…4d5dfe, settlement tx 0xed87b09b…dfeb30
```

For readers mapping to the four verification states of wg-identity #21: `linked` is verified, `incomplete` is indeterminate,
`not_attempted` is not evaluated. `no_match` is a determinate negative about the salt and asset used, not a judgement of the
signer.
