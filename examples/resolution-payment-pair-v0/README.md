# resolution-payment-pair-v0

Vectors for the claim "payment P executed under the authority of verdict V", written against the Resolution invariant
discussed at [ethereum-magicians t/29846](https://ethereum-magicians.org/t/29846) (AUTHORIZED | UNAUTHORIZED | UNRESOLVED; validity
does not imply authority).

Two cases are real: our own Base mainnet USDC payments by EIP-3009 `transferWithAuthorization`, each preceded by a signed
invinoveritas review verdict over the same action arguments. The pinned receipts are what Base returns; `check.py --live` re-reads
them and their block hashes. All other cases are labelled **synthetic** (verdicts signed by a public TEST key from a fixed seed,
receipts constructed, no transaction exists) or **negative** (one field of a real case altered).

The checker evaluates three edges, each from bytes:

| edge | holds when | missing |
|---|---|---|
| covers | V verifies (NIP-01 id, BIP-340 signature under the expected key, decision_ref recomputes) and binds sha256(JCS(args)); the receipt shows that exact transfer, authorized by args.from | `verdict_does_not_cover_payment` |
| carried | the receipt's `AuthorizationUsed` nonce equals V's `decision_ref`, so the authorization could not exist before V | `payment_does_not_carry_verdict` |
| policy | the bound args declare `proceed_on`, so which verdicts permit execution was fixed before the payment | `execution_policy_not_committed` |

AUTHORIZED needs all three and V's verdict in `proceed_on`. A carried verdict outside the declared policy is UNAUTHORIZED.
Everything else is UNRESOLVED with each missing edge named. A receipt that cannot be obtained is UNRESOLVED `evidence_unavailable`,
a different kind: fetching can fix it, while nothing fetched can supply an edge the producer never committed.

| case | class | outcome | reasons |
|---|---|---|---|
| exhibit-2-random-nonce | real, tx [`0xd105a8f5…d112`](https://basescan.org/tx/0xd105a8f5290fbe841da419db402659d07bafa21070be370d81d19b1e29d9d112) | UNRESOLVED | payment_does_not_carry_verdict, execution_policy_not_committed |
| exhibit-3-nonce-is-decision-ref | real, tx [`0x2afb35e2…c4a7`](https://basescan.org/tx/0x2afb35e24a20fdee74c35937feb59b86358d45c8029a91d065d59825c3e7c4a7) | UNRESOLVED | execution_policy_not_committed |
| s1-approve-carried-policy-permits | synthetic | AUTHORIZED | |
| s2-reject-carried-as-nonce | synthetic | UNAUTHORIZED | executed_on_verdict_outside_policy |
| s3-random-nonce-policy-permits | synthetic | UNRESOLVED | payment_does_not_carry_verdict |
| n1-args-amount-altered | negative | UNRESOLVED | verdict_does_not_cover_payment |
| n2-verdict-content-altered | negative | UNRESOLVED | verdict_does_not_cover_payment |
| n3-policy-added-after-verdict | negative | UNRESOLVED | verdict_does_not_cover_payment |
| n4-verdict-signed-by-another-key | negative | UNRESOLVED | verdict_does_not_cover_payment |
| n5-receipt-unavailable | negative | UNRESOLVED | evidence_unavailable |

Exhibit 2: the authorization's nonce is 32 random bytes from the x402 Python SDK (`create_nonce`, `os.urandom(32)`). The verdict's
bound args contain that signed authorization, nonce included, so V names this exact payment; but the payment does not name V, and
the same authorization would have settled whatever V said. Exhibit 3: the authorization was signed after the verdict with nonce = its
`decision_ref`. Neither declared `proceed_on`, so neither reaches AUTHORIZED. Both edge results agree with the live
`POST https://api.babyblueviper.com/verify-execution` (`nonce_is_verdict` false / true; `declared_execution_policy` "none declared").

```
python3 check.py --mutants   # 10/10 cases, 5/5 wrong checkers caught (stdlib only)
python3 check.py --live      # also re-reads both real receipts and block hashes from a public Base RPC
python3 build.py             # regenerates vectors.json byte-identically from fixtures/real.json
```

Mutants: M1 reads temporal order (verified_at before the block) as binding; M2 lets binding alone authorize; M3 skips verdict
verification; M4 treats an unavailable receipt as a rejection; M5 trusts args without the bound hash. The synthetic key is a public
test key; never use it for anything else.
