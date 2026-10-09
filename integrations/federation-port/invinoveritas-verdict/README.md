# invinoveritas verdict component for federation-port/v0

A project-owned `federation-port/v0` adapter, written against the published contract only, with role `action_evaluation`.
It lets a runtime require an independent invinoveritas verdict on the **exact action** it is about to dispatch, and checks it
offline. There is no network access (`data_destinations: []`), no dependencies, no secrets and no privileges.

The caller presents, as this component's evidence, the signed verdict proof that `POST /review` returns with `sign=true`. That
proof is a NIP-01 event, kind 30078, tagged `schema=invinoveritas.verdict_proof.v1` and signed BIP-340. The `/review` call
reviewed the action's sorted-key JSON. The component reports four claims, so a policy can require exactly what it needs:

| claim | established when |
|---|---|
| `invinoveritas.verdict_authentic` | the event id recomputes from its fields, it is a verdict proof, and the BIP-340 signature verifies under the pinned key `6786e18a…6922fbb7` (published at `api.babyblueviper.com/.well-known/nostr.json`) |
| `invinoveritas.verdict_covers_action` | `content.artifact_hash == sha256(sortedKeyJson(action))`: the verdict was issued on this action and no other |
| `invinoveritas.verdict_permits_action` | it covers this action, the verdict is in `accept_verdicts` (default `["approve"]`), and it is no older than `max_age_s` (default 900). `valid_until` is set to signing time + `max_age_s`, so the runtime's admission deadline enforces freshness |
| `invinoveritas.verdict_covers_target` | it covers this action, the dispatch target is a member of the hashed action (`args[target_field]`, default `target`), and it equals the runtime's dispatch target, exact string: `CheckInput.target` when the runtime passes one (proposed for v1 in [#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177)), otherwise `declared_target` in config, the v0 stand-in |

Malformed input (bytes that are not JSON, not an event, or content that is not JSON) is reported as `failed`. Anything else that
does not hold is `not_established`, each with a specific reason: `no_verdict_presented`, `event_id_does_not_recompute`,
`signer_is_not_the_pinned_key`, `signature_invalid`, `verdict_is_for_a_different_action`, `verdict_<value>`,
`verdict_older_than_max_age`, `target_not_in_hashed_action`, `no_runtime_target`, `verdict_target_is_not_the_runtime_target` or `verdict_target_is_not_the_declared_target`.

**Subject.** The subject is read from the bytes the verdict was issued on, never from config: `subject:action_sha256=<hex>` on an
established `verdict_covers_action`, and `subject:target=<target>` on an established `verdict_covers_target`. v0 has no subject
field, so both travel as the established claim's reason code. A target that is not inside the hashed action is never reported:
the verdict says nothing about where the action is sent unless the target was part of what was reviewed. A verdict issued for
target A fails coverage on an action sent to target B, because the action hash differs.

**Limits.**
- **Not a correctness guarantee.** A verdict is an independent judgement, not a guarantee that the action is correct.
- **Binds the action only.** It does not bind the tenant, approval id or operation id. It binds the target only when the target is inside the action.
- **Not single-use.** The same verdict can be presented again for the same action; single use is the approval's job.
- **No key rotation or revocation** in v0.1.
- **No trusted time.** Freshness uses the signed `created_at` and the runtime's clock.

## Config

```json
{ "accept_verdicts": ["approve"], "max_age_s": 900, "pubkey": "<optional override of the pinned key>",
  "declared_target": "<the dispatch target, exact string>", "target_field": "target" }
```

## Getting a verdict

```bash
curl -s https://api.babyblueviper.com/review -H 'Authorization: Bearer ivv_...' -H 'Content-Type: application/json' -d '{
  "artifact": "{\"args\":{\"amount_minor\":4000,\"currency\":\"EUR\",\"payment_id\":\"pay_A\"},\"tool\":\"refund\"}",
  "artifact_type": "general", "sign": true, "context": "why this refund is being made"}' | jq .proof.event
```

## Verified

Run `./reproduce.sh`. It clones `aeoess/federation-port` at `3a2f6ce` (re-pinned 2026-10-08 after the runtime changes merged that day;
first run at `92d5078`, 51/51), adds this component without touching `src/`, seals it with
the repo's own `scripts/seal.ts`, and runs the full suite: **66/66 (the 54 existing tests plus 12 here)**. It then runs BIP-340's
official test vectors through `bip340.ts`: **15/15** (the 4 vectors with non-32-byte messages are skipped, since event ids are
always 32 bytes). The repo's `tsc -p tsconfig.json` reports 0 errors. Sealed digests (0.3.0): artifact
`sha256:126160033d88056f16ec2f67c6bf3ee8c4d66fcef11303b34642955b3a16281f`, manifest
`sha256:41499a39d17f760e6da004811b299091beed89fce249a9d10e1e4445c6298199`.

I01-I07 run on two real verdict proofs from the live API (`test/fixtures/verdicts.json`, issued 2026-10-07):
- **The sim's approved refund:** verdict `approve_with_concerns`.
- **The same refund for EUR 4,000,000:** verdict `reject`.

Cases covered: admitted with all three action claims established; refused under the default `approve`-only policy; a genuine verdict on
another action refused on coverage; the reject verdict refused on the verdict; an edited verdict, a foreign signer and a flipped
signature bit each refused on authenticity; no verdict, malformed bytes and a stale verdict each refused with their own reason;
and, as an optional component, never blocking. In every refused case the provider receives no request.

I08-I12 cover the target. The runtime's refund workflow has no target, so they call `check()` directly, on verdicts signed in the
test with a BIP-340 test key (same event shape, `pubkey` override): target inside the hashed action and equal to the declared
target is established with both subject fields; a target outside the hashed action is `target_not_in_hashed_action` (and
`no_runtime_target` when there is neither a runtime target nor a declared one); a verdict issued for target A on an action sent to target B fails
`verdict_covers_action`; an action and verdict naming A under a declared B fail `verdict_covers_target`; a runtime target passed as `CheckInput.target` is compared instead of config and wins over a disagreeing config (`verdict_target_is_not_the_runtime_target`).

MIT. invinoveritas (Invinoveritas SpA).
