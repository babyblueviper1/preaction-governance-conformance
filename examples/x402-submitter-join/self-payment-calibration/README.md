# Self-payment calibration: a second labelled payee

Follows [x402#2887](https://github.com/x402-foundation/x402/issues/2887). stillmarcus24's rules were validated on one labelled payee, his own. This directory scores them against ours, `0x161DbdD73D025E9aEdd4918a67c28e5bf9A87Fb9`. We hold ground truth for every payer on it: our own keys, plus the internal/external classification in our revenue ledger. It covers the same 50-transfer window he sampled, 2026-07-02 → 2026-09-17.

```
python3 calibrate.py      # stdlib only, offline; writes results.json and asserts the pinned numbers
```

## Results

| | |
|---|---|
| inbound USDC transfers in the window | 50 |
| settlements (anything except a plain transfer) | **48**: 38 external, 10 ours |
| not settlements | 2: 0.00003 USDC poisoning dust, pushed by contract `0x75161fd5…` |

**`PAYEE_FUNDED`** flags 12. Ten are true (our buyer wallet `0x1611cf65…`, recall 10/10). **Two are false.** `0x4fabc1df…` is not ours and was never funded by us. Its "30 USDC from the payee" transfers are a fake token, `0xa1eb5cb9…`, with symbol `UႽD‬C` and a single holder. Any contract can emit `Transfer(from=payee)`. The address imitates `0x4faba751…`, which we really paid 30 USDC minutes before. It is address poisoning, and the rule reads it as self-funding. Restricted to canonical USDC funding edges and to real settlements, the rule scores **10/10, 0 false positives**.

**Out-degree** (population from stillmarcus24/x402-submitter-join@3e4c955):

| threshold | confirmed external | ours wrongly confirmed external | external left unclassified |
|---|---|---|---|
| ≥2 | 29 | **0** | 9 |
| ≥3 | 29 | **0** | 9 |
| ≥5 | 23 | **0** | 15 |
| ≥10 | 22 | **0** | 16 |

All 10 of our self-paid settlements come from a degree-1 wallet, so no threshold confirms them as external. The signal holds on a second payee in the direction it is used. The cost is real external buyers left unclassified. One genuine repeat buyer (`0x65c85bdf…`, 925 paid calls with us) is also degree 1, which is why degree must never classify in the other direction.

## Pinned vectors

`address_poisoning_vectors.json` holds two real rows. Any self-payment rule should handle both before its numbers go into v4:
1. A funding edge counts only in canonical USDC (`0x833589fc…`). Token contracts can forge the sender.
2. A plain `transfer` is not a settlement. Poisoning dust would otherwise enter both the self-payment sample and the uncovered-submitter count.

Our inputs are pinned in `inputs/` with `SHA256SUMS`. stillmarcus24's `market_join.json` is not vendored, because his repo has no licence. `calibrate.py` fetches it at commit `3e4c955` and refuses any file whose sha256 is not `d37f6011…`. CC0, like the rest of `examples/x402-submitter-join`.
