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

## Follow-up: the full adversarial matrix (Brodin2001's 2026-09-09 comment)

Brodin2001 asked how much enforcement comes from action binding alone vs. AgentGuard's broader
receipt (tool + args + target + agent identity + runtime identity + policy state + expiry +
single-use), and proposed 7 test cases. `full_receipt_adversarial_matrix.py` extends the recompute
to invinoveritas's real preimage fields (`tool`, `args`, `agent_id`, `policy_version`) plus a
consume-on-first-use ledger mirroring the real `consumed_decisions` table, and covers 5 of the 7:

| Case | Covered? | Mechanism |
|---|---|---|
| policy changes after authorization | yes | `policy_version` is in the same hashed preimage — a receipt issued under policy vN no longer matches a verifier recomputing against vN+1 |
| agent identity changes | yes (agent identity only) | `agent_id` is in the same preimage — a different agent presenting the same receipt breaks the hash. "Runtime identity" as a distinct axis from agent identity is NOT tracked — disclosed gap, not claimed coverage |
| receipt replay | yes | atomic consume-on-first-use (`PRIMARY KEY(decision_ref)` in the real table — the INSERT failing IS the check-and-consume, no read-then-write race) |
| expiry | **no, by design** | invinoveritas ships no hard TTL — the script demonstrates this explicitly (a receipt "issued" a year ago recomputes identically to one issued now), not silently |
| target / argument mutation | yes | already covered in `action_binding_recompute.py` above |
| alternate execution path bypassing the protected execution point | **not attempted** | see below |

The last case is deliberately not attempted here: it isn't a hash-comparison problem. A hash
comparison only matters if every tool-dispatch path in the calling framework actually routes
through the point where the comparison happens. If `MultiStepAgent.step()` (or a sub-agent
delegation path, a retry path, a tool-calling-a-tool path) has any way to invoke a tool without
going through wherever the guard is wired in, no receipt scheme — this one, AgentGuard, or
anything else — closes that gap, because the gap is upstream of verification entirely. Answering
it needs inspection of smolagents' real call-routing guarantees, not a standalone fixture.

```bash
python3 full_receipt_adversarial_matrix.py
```

## The bypass, demonstrated (Brodin2001's 2026-09-09 proposal)

A real, traced fresh-clone finding (huggingface/smolagents head `30bb1161`): `ToolCallingAgent` has
one canonical dispatch choke point, `execute_tool_call()` (agents.py:1453); `CodeAgent` has none —
its tools are registered as plain callables directly into the sandboxed Python executor's namespace
(`send_tools()`, agents.py:492) and invoked as ordinary function calls from LLM-generated code
(agents.py:1726). A guard wired at `execute_tool_call` — the obvious placement — protects
`ToolCallingAgent` completely and `CodeAgent` not at all.

`callable_boundary_vs_dispatch_boundary.py` doesn't just assert this — it simulates both dispatch
shapes and both guard placements, and runs the exact same mutated call through each:

| Guard placement | ToolCallingAgent-style call | CodeAgent-style call |
|---|---|---|
| Wrapped at `execute_tool_call()` | mutated call correctly DENIED | **same mutated call NOT denied — bypass confirmed, actually executes** |
| Wrapped at the callable itself, before either dispatch mechanism gets a reference | mutated call correctly DENIED | mutated call correctly DENIED — bypass closed |

The fix isn't "add a second hook" — it's placing the one hook at the right boundary (the tool
object, via `send_tools()`'s input) rather than at a dispatch method only one of the two agent
subclasses happens to call through.

```bash
python3 callable_boundary_vs_dispatch_boundary.py
```

## Same test, Brodin2001's real AgentGuard (not a toy substitute)

Brodin2001 asked to keep the harness as the source of truth and wire his real library —
[`Agentguard`](https://github.com/Brodin2001/Agentguard), branch `v0.2-action-bound-authorization`,
commit `8e126c62` — into the same two placements, running the identical mutation/replay sequence,
and to report the result honestly even if something failed rather than adapt the harness around it.
Nothing failed unexpectedly; `agentguard_dispatch_test.py` runs clean:

| | ToolCallingAgent-style call | CodeAgent-style call |
|---|---|---|
| Guard wired at `execute_tool_call()` (via `guard.execute_receipt()`) | mutated call DENIED, replay of the authorized call DENIED | **same mutated call bypasses AgentGuard entirely and executes** — matches AgentGuard's own docstring: *"Alternate direct calls to the underlying function remain outside this library's control boundary."* |
| Guard wired at the callable itself (wrapping the tool with `execute_receipt` once, before either dispatch mechanism gets a reference) | mutated call DENIED, replay DENIED | mutated call DENIED, replay DENIED — bypass closed |

**Classification, as requested** — what AgentGuard's own receipt logic catches vs. what's a
placement question: mutation, replay, and (present in the code, not separately exercised here)
expiry and live policy-hash staleness are receipt-shape properties AgentGuard's `verify_and_consume()`
catches regardless of placement. Whether `verify_and_consume()` gets called AT ALL for a given call
site is purely a placement question — this harness reproduces the disclosed limitation concretely
against a real CodeAgent-shaped call path, using AgentGuard's real API. One real capability AgentGuard
has that invinoveritas's action_binding-shaped check in the fixture above does not: a genuine
TTL-based expiry and a live re-check of the CURRENT policy hash at consume time, not just a value
bound at issue time — see the disclosed expiry gap in `full_receipt_adversarial_matrix.py` above.

Setup (source not vendored here — no LICENSE file on that branch as of this test, so it's installed,
not redistributed):
```bash
pip install "git+https://github.com/Brodin2001/Agentguard.git@v0.2-action-bound-authorization"
python3 agentguard_dispatch_test.py
```
