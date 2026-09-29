# x402 facilitator-registry coverage, keyed by settlement submitter

This is a second implementation of the coverage question in [x402-foundation/x402#2887](https://github.com/x402-foundation/x402/issues/2887). It asks: what share of live x402 settlements does the public 105-address facilitator registry (the one the Tektonic settlement archive is built on) actually attribute?

The first measurement ([RayR-audit registry-gap ledger](https://github.com/RayR-audit/x402-settlement-audit/tree/_registry_gap_landing/registry_gap), v3) joined each host's `payTo` against the registry and found 0 of 357. In the `exact` scheme on EVM, though, `payTo` is the merchant: it's the USDC Transfer's `to`. The facilitator is whoever submits `transferWithAuthorization`, which is the transaction's `from`. A payee is never a facilitator address, so that join returns 0 by construction. RayR-audit re-verified this and adopted the submitter-keyed join as their v4 methodology (x402#2887).

## Method (Base, no keys)

For each distinct payee in RayR-audit's `probe_results_v3.csv` (`A_out` rows; 357 hosts reduce to 192 distinct payees):

1. Blockscout v2 lists the payee's most recent inbound USDC transfers (the first page, up to 50).
2. Plain `transfer()` calls (`0xa9059cbb`), where the payer submits its own payment, are dropped. The rest are facilitator-style, mostly `transferWithAuthorization` (`0xe3ee160e`).
3. For up to 5 of those per payee, the script fetches the transaction's `from` (the submitter) and `to` (the called contract). Rows where the submitter is the payer are dropped.
4. A settlement counts as **covered** when either the submitter or the called contract is one of the 105 registry addresses.

The test vectors from #2887 reproduce. Payee `0x161D…7Fb9` (ours) shows settlement `0xe4bda99f…40f59` as covered (the registry's `coinbase` signer) and `0x879360e6…aedfe` / `0x55f77844…2b31` as not covered.

```
python3 submitter_join.py probe_results_v3.csv base_facilitators.csv   # resumable, polite rate
python3 submitter_join.py --summary
```

## Result (sampled 2026-09-29, results.jsonl sha256 273befe512ee0dde…)

| | |
|---|---|
| distinct payees | 192 (4 fetch errors, 7 with no Base USDC inflow) |
| payees with facilitator-style settlements | 181 |
| payees with at least one settlement the registry covers | **132 of 181 (73%)** |
| sampled settlements covered | **229 of 896 (25.6%)** |
| covered by | coinbase 223, payai 6 |
| uncovered settlements | 667, from only **22 distinct submitter addresses** (`unregistered_submitters.csv`) |

What this shows:

- The registry is not blind to the live market. Most payees do settle through a facilitator it knows, so 0% was an artifact of the join.
- It still misses about three in four sampled settlements. That gap is concentrated: 22 submitter addresses account for all 667, and the top five hold 45 to 50 settlements each. This fits a small pool of rotated signer keys (goun7's point in #2887) better than a long tail of unknown facilitators. Attributing those 22 addresses would close most of the measured gap. That is a registry-maintenance fix, not a spec fix.

## Limits

- Base only. Payees settling on other networks show up as "no Base USDC inflow", not as uncovered.
- The sample is the 5 most recent facilitator-style settlements per payee: recent activity, not lifetime volume.
- The 22 addresses are **not attributed** here. Mapping each one to a facilitator (funding source, deployer, operator disclosure) is the next step, and it is exactly what the registry would need.
- The registry file is RayR-audit's `registries/base_facilitators.csv` as of 2026-09-27. Addresses added after that are missing by construction.
