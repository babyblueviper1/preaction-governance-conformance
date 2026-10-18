# x402 receipt private opening: `x402-receipt-private-opening/1` (draft, CC0)

A verifier's signed statement about a receipt commitment that a rater opened **privately**, so grounded feedback
doesn't have to publish the payment. This is the middle tier discussed on ethereum-magicians
([t/25098 #422](https://ethereum-magicians.org/t/25098/422), predge-ai; [#423](https://ethereum-magicians.org/t/25098/423)):
- opened in public: anyone recomputes the settlement;
- **opened to one named verifier: that verifier signs what it found;**
- unopened: an interested-party statement.

The receipt field it builds on is `authorizationCommitment` from x402 receipt payload v2
([x402#3827](https://github.com/x402-foundation/x402/pull/3827)). The construction and the public-opening check are
in the sibling kit [`../x402-receipt-authorization-commitment`](../x402-receipt-authorization-commitment).

## What a statement attests
For one receipt, privately opened with its salt, the verifier checks three things:
1. The commitment opens to a consumed ERC-3009 authorization of the receipt's signed `payer` (§5.5: the authorizer
   is the receipt's `payer`, never a value supplied with the salt).
2. That `payer` is the rater.
3. The settlement's transfer paid a wallet bound to the rated agent.

The finding is one of `opens_to_settlement`, `no_settlement`, `payer_is_not_rater`, `payto_not_bound_to_agent` or
`incomplete_check`. The last means the verifier could not read the chain (a failed or rate-limited log query, or a
settlement whose transfers it could not read). It is never reported as `no_settlement`, and it counts toward nothing
(x402#3827 §5.6.4 as amended). Vector `assess-chain-unavailable`; mutant `unavailable_as_no_settlement`.

```
{ type, receipt_sha256, commitment, method, network, asset, rater, agent, result, checked_at, read_at, seq, prev, verifier, signature }
```
Ed25519 over the canonical JSON of every other field. `receipt_sha256` is sha256 of the canonical receipt that was
opened. `read_at` is `{number, hash}` of the chain head the verifier read `AuthorizationUsed` through (the `toBlock` of
its log query). `seq` and `prev` chain each statement to the one before it in the verifier's append-only log.

## Read point (`/1`)
`/1` adds `read_at` (requested by predge-ai on [erc-8004-contracts#99](https://github.com/erc-8004/erc-8004-contracts/issues/99),
whose grounded-feedback method table counts a private opening only when the statement binds the block it was read at).
A challenger who finds that block is no longer canonical reports `reorged`: the finding is re-checked, never counted as
a wrong answer. Vector `challenge-reorged`; mutant `ignores_read_at`.

It is the **head**, never the settlement block. The rater is public, so the settlement block would point at the
settlement transaction. A reorg that removes the settlement block also removes every later block, so binding the head
is enough to detect it. Vector `statement-no-leak` now also checks the settlement block hash; mutant
`binds_settlement_block` fails it. A `/0` statement (no `read_at`) is not counted under `/1` (vector `pairs`, mutant
`counts_unanchored`). `/0` is at `c267825`.

## Three properties
- **Privacy.** The statement never carries the nonce, the settlement transaction, its block or the salt. Vector
  `statement-no-leak` checks this, and the `leaks_nonce` mutant (a verifier that records which settlement it found)
  fails it.
- **Counted per (rater, agent) pair, not per rating.** Duplicates collapse on the public pair. A payment can't ground
  a second agent, because payTo binds it to one. A Sybil still pays once per fake rater. So no verifier needs a
  cross-verifier "not seen before" store. Such a store would have to be keyed on the public `(asset, payer, nonce)`
  tuple, which re-links the rating to its settlement. Vector `pairs`; mutant `counts_ratings`.
- **Challengeable.**
  - The statement binds the receipt it opened, so it can't be replayed onto another receipt (`challenge-not-bound`).
  - If the rater later opens in public, anyone can recompute the finding: `challenge-upheld`, `challenge-refuted`.
  - Editing a past statement breaks the log (`log-tampered`).
  - Mutants `unbound_statement` and `trusts_statement` each fail a vector.

## What it does not claim
- That the service was any good, or that the rating is honest. It establishes only that the rater paid the agent.
- The seller's receipt signature (§5 of the receipt spec) is taken as already verified. This kit doesn't re-check it.
- The log isn't anchored to an external clock here. A deployment would anchor the daily log head (for example with
  OpenTimestamps), so a statement can be shown to predate its use.
- Only the `eip3009` method is covered.

## Data
Settlement A is real: Base Sepolia USDC, payer `0x87f3…6ee1`, transaction `0x1345479a…`, block 48163177. Its receipt
logs carry `AuthorizationUsed(payer, nonce A)` at logIndex 180 and `Transfer(payer → 0x2888…ec26, 1000)` at 181, in the
same transaction. `read_at` is block 48164856 (`0x75f13f14…bb98`, timestamp 2026-10-15T21:00:00Z, the snapshot time),
read from sepolia.base.org. The payer's other 11 consumed nonces come from the sibling kit's `candidates_snapshot.json`, so
everything runs offline. Salts are the sibling kit's public test salts. The verifier key is a **public test key**
derived from a fixed seed.

## Files
| file | what |
|---|---|
| `statement.py` | `assess`, `make_statement`, `signature_ok`, `leaks`, `log_ok`, `challenge`, `grounded_pairs` |
| `ed25519_ref.py` | Ed25519 (RFC 8032 §5.1), pure Python; not constant-time, for checking only |
| `vectors.json` | 13 vectors: 5 assess, 1 privacy, 4 challenge, 2 log, 1 count |
| `build_vectors.py` / `run_vectors.py` | regenerate / check |

```
$ python3 run_vectors.py
  PASS ed25519 RFC 8032 TEST 1
  ... 13/13 vectors
  caught counts_unanchored: pairs
  caught binds_settlement_block: statement-no-leak
  caught ignores_read_at: challenge-reorged
  caught unavailable_as_no_settlement: assess-chain-unavailable
  caught skips_rater_check: assess-rater-not-payer
  caught leaks_nonce: statement-no-leak
  caught unbound_statement: challenge-not-bound, challenge-reorged
  caught trusts_statement: challenge-refuted, challenge-not-bound, challenge-reorged
  caught counts_ratings: pairs
  PASS vectors.json reproduces from build_vectors.py
ALL PASS
```
Standard library only (Python 3.9+).
