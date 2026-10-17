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
| `commitment.py` | `commit()` and the holder-side `link()`; malformed input is refused with a named condition |
| `vectors.json` | 20 vectors: 4 commit (incl. the x402 spec §5.4 example), 5 link (incl. swapped salt, other asset, other authorizer), 3 attack, 8 malformed |
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
