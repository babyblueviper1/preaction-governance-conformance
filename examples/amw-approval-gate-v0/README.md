# Approval-gate fixtures: a signed APPROVE and REJECT for an irreversible tool call (v0)

Two real verdicts, signed by the invinoveritas production key, for a Stripe refund call. Test charge ids only; nothing here touches Stripe.

| file | call | verdict | gate result |
|---|---|---|---|
| `approve.json` | first refund of `ch_test_amw_fixture_0001` ($50.00) | approve | ALLOW |
| `reject.json` | the same refund retried after a timeout with a **fresh idempotency key**, the charge already refunded in full | reject | BLOCK |

Each file holds the call's canonical bytes (`artifact_canonical`, sorted-key compact JSON), their sha256, and the signed verdict (`proof.event`, a NIP-01 / BIP-340 event, kind 30078).

## Check (offline, stdlib only)

```
python3 check.py approve.json reject.json
python3 check.py approve.json --call my_call.json   # a verdict against the call the agent is actually about to make
```

`check.py` recomputes the event id, verifies the Schnorr signature against the pinned key `6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7`, and checks that sha256 of the call equals the signed `artifact_hash`. It returns ALLOW only for a valid, bound `approve`; anything else is BLOCK. The receipt digest is the verdict event id.

Expected:
- approve.json: ALLOW; reject.json: BLOCK
- approve.json against the same call with `amount` changed: BLOCK (not bound to this call)
- approve.json against the identical call (a retry with the same arguments): ALLOW, same digest

The same events also verify at `POST https://api.babyblueviper.com/verify-proof` (`{"event": ..., "artifact": ...}`), but the gate never needs to call it.

Scope: a verdict is an independent model judgment against the stated facts, not a warranty. The gate decides what to do with it.
