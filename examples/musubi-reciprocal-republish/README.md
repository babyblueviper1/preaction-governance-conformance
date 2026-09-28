# Reciprocal-walk agreement, republished for record-privacy-v1 (2026-09-28)

`agreement_c2e27ca8_AB.json`: HORIZON SHIELD's republish of the 2026-09-24 reciprocal-walk agreement
(`121ce3d2d0ab20897f5ef60dc898466a`) as `c2e27ca89e7a6211fb66aa97adb95c24`, signed by horizonshield.dev
(horizon-shield@9a703a7d `ops/republish_121ce3d2/signed_A.json`, sha256 `d91c8a4c...`) and countersigned by api.babyblueviper.com
with `agreement_sign.py`. `agreement_verify.py` -> `accepted` (no refusals; findings `conduct_self_measured` on both parties, declared).
File sha256 `5d3e62f1f0b139992dd15db07b4abc6288a8a824effc31da8300ebe1d6ae6e6c`.

Checked before signing, against our own copy of 121ce3d2 (captured by our NENRIN mirror run, object 3eb0a7b1...):
exactly four keys differ, `agreed_at`, `agreement_id`, `lower_bound` (Bitcoin block 968955, hash confirmed against mempool.space)
and `publication: "public"`, plus the signatures. `parties`, `terms`, `establishes`, `does_not_establish`, `record_paid_by`,
`recorder` and `schema` are byte-identical. We sign the `publication: "public"` consent on purpose: both walks are public already,
and a public, two-signed record is the point of the exercise.
