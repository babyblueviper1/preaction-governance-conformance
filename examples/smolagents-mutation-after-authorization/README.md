# mutation-after-authorization recompute

Executable conformance for the case named in
[huggingface/smolagents#2117](https://github.com/huggingface/smolagents/issues/2117)
(Brodin2001, 2026-09-09): a `GuardrailProvider` can authorize `refund(customer=A, amount=100)`,
but nothing in the capability-allowlist design (see the sibling
[`smolagents-guardrail-recompute`](../smolagents-guardrail-recompute/) example) stops that
authorization from being replayed against `refund(customer=A, amount=1000)` or a changed target —
the tool name is identical either way.

## What this recomputes

invinoveritas's `/review` endpoint has a published `action_binding` parameter that binds a
verdict to a tool call via two **separate** hashed preimage fields, documented in the tool's own
schema:

```
action_binding_tool_hash = sha256(tool)
action_binding_args_hash = sha256(RFC-8785-JCS(args))
```

`action_binding_recompute.py` **independently reimplements** this hash scheme from that published
spec — zero dependencies, never imports invinoveritas or smolagents — and runs it against
Brodin2001's exact scenario plus two adjacent cases:

| Vector | Args | Expected vs. `authorize_refund_100` |
|---|---|---|
| `authorize_refund_100` | `{customer: A, amount: 100}` | — (the authorized receipt) |
| `attempt_replay_amount_mutated` | `{customer: A, amount: 1000}` | **different** hash (Brodin2001's case) |
| `attempt_replay_target_mutated` | `{customer: B, amount: 100}` | **different** hash, and different from the amount-mutated case too |
| `attempt_replay_key_order_reordered` | `{amount: 100, customer: A}` | **identical** hash — a harmless reserialization must not false-reject |

The last row matters as much as the first three: a binding that's *too* sensitive (breaks on key
reordering) is a different, real bug — the same false-positive failure mode this account's own
canonicalization work has hit repeatedly on a separate live product surface. `jcs()` here is a
minimal RFC 8785 implementation (sorted keys, compact separators) sufficient for these ASCII/
integer vectors — it does not attempt the harder cross-runtime edges (UTF-16 vs. code-point key
sort, ES6 vs. Python number formatting at the extremes), which is a real, separate, disclosed gap
elsewhere, not silently assumed solved here.

```bash
python3 action_binding_recompute.py
```

## Why this is the answer to "how does this map onto `MultiStepAgent.step()`"

A verifier sitting at the protected execution point in `step()` doesn't need to trust the calling
agent's claim that "this is the same call I was authorized for." It holds the `action_binding_*`
hashes from the original authorization, recomputes the same two hashes over the *actual* call
about to execute, and compares strings. Both of Brodin2001's mutation cases are caught by that one
comparison — no policy engine, no semantic understanding of what a "refund" is, just a hash
recomputed the same way twice.
