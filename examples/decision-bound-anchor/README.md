# Decision-bound anchor run (2026-10-18)

This is our run record for the anchor extension to `decision-bound-output-v1`, submitted upstream as
[giskard09/execution-join-ref-remora-bridge#1](https://github.com/giskard09/execution-join-ref-remora-bridge/pull/1).
The verifier, the 20 synthetic vectors and the mutation battery live in that repository. This directory keeps a copy of the real anchors.

- `anchor_live/decision.json`: the decision preimage and its `decision_id`, anchored at 11:57:26Z. The OTS proof is in Bitcoin block 971996.
- `anchor_live/write-1.json`: written 98 s after the decision, in the same block, so the order is `WITNESS_ORDER_UNRESOLVED`.
- `anchor_live/write-2.json`: written after the decision's proof was in a block, so the decision is `DECISION_WITNESSED_FIRST` on RFC 3161 (18,914 s apart). Its own OTS proof was pending at bind time.
- `vectors_anchor_live.json`: both cases as bound.

The anchors came from `POST https://api.babyblueviper.com/work-acceptance/criteria` (free). Checking them needs no call to us: the tokens are FreeTSA's and DigiCert's own, and the proofs replay to Bitcoin headers.
