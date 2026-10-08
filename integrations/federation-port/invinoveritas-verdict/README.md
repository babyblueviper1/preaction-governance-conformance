# invinoveritas verdict component for federation-port/v0

A project-owned `federation-port/v0` adapter, written against the published contract only, with role `action_evaluation`.
It lets a runtime require an independent invinoveritas verdict on the **exact action** it is about to dispatch, and checks it
offline. There is no network access (`data_destinations: []`), no dependencies, no secrets and no privileges.

The caller presents, as this component's evidence, the signed verdict proof that `POST /review` returns with `sign=true`. That
proof is a NIP-01 event, kind 30078, tagged `schema=invinoveritas.verdict_proof.v1` and signed BIP-340. The `/review` call
reviewed the action's sorted-key JSON. The component reports three claims, so a policy can require exactly what it needs:

| claim | established when |
|---|---|
| `invinoveritas.verdict_authentic` | the event id recomputes from its fields, it is a verdict proof, and the BIP-340 signature verifies under the pinned key `6786e18a…6922fbb7` (published at `api.babyblueviper.com/.well-known/nostr.json`) |
| `invinoveritas.verdict_covers_action` | `content.artifact_hash == sha256(sortedKeyJson(action))`: the verdict was issued on this action and no other |
| `invinoveritas.verdict_permits_action` | it covers this action, the verdict is in `accept_verdicts` (default `["approve"]`), and it is no older than `max_age_s` (default 900). `valid_until` is set to signing time + `max_age_s`, so the runtime's admission deadline enforces freshness |

Malformed input (bytes that are not JSON, not an event, or content that is not JSON) is reported as `failed`. Anything else that
does not hold is `not_established`, each with a specific reason: `no_verdict_presented`, `event_id_does_not_recompute`,
`signer_is_not_the_pinned_key`, `signature_invalid`, `verdict_is_for_a_different_action`, `verdict_<value>` or
`verdict_older_than_max_age`.

**Limits.**
- **Not a correctness guarantee.** A verdict is an independent judgement, not a guarantee that the action is correct.
- **Binds the action only.** It does not bind the tenant, approval id or operation id.
- **Not single-use.** The same verdict can be presented again for the same action; single use is the approval's job.
- **No key rotation or revocation** in v0.1.
- **No trusted time.** Freshness uses the signed `created_at` and the runtime's clock.

## Config

```json
{ "accept_verdicts": ["approve"], "max_age_s": 900, "pubkey": "<optional override of the pinned key>" }
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
the repo's own `scripts/seal.ts`, and runs the full suite: **61/61 (the 54 existing tests plus 7 here)**. It then runs BIP-340's
official test vectors through `bip340.ts`: **15/15** (the 4 vectors with non-32-byte messages are skipped, since event ids are
always 32 bytes). The repo's `tsc -p tsconfig.json` reports 0 errors. Sealed digests: artifact
`sha256:9c11769fd9f4e1d42584ae1f79ba4c77334db11222643185f36edd28fc9ba6d3`, manifest
`sha256:4bf6dcd47894c7e18cc29295c9420e947546f62d73634d5aebcf8718ee644dc0`.

The tests run on two real verdict proofs from the live API (`test/fixtures/verdicts.json`, issued 2026-10-07):
- **The sim's approved refund:** verdict `approve_with_concerns`.
- **The same refund for EUR 4,000,000:** verdict `reject`.

Cases covered: admitted with all three claims established; refused under the default `approve`-only policy; a genuine verdict on
another action refused on coverage; the reject verdict refused on the verdict; an edited verdict, a foreign signer and a flipped
signature bit each refused on authenticity; no verdict, malformed bytes and a stale verdict each refused with their own reason;
and, as an optional component, never blocking. In every refused case the provider receives no request.

MIT. invinoveritas (Invinoveritas SpA).
