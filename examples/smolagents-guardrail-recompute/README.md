# smolagents guardrail-decision recompute

Executable conformance for smolagents' `GuardrailProvider` protocol
([huggingface/smolagents#2117](https://github.com/huggingface/smolagents/issues/2117), PR
[#2126](https://github.com/huggingface/smolagents/pull/2126), open as of 2026-07-30) — a
`before_tool_call(tool_name, arguments) -> GuardrailDecision{allowed, reason}` check evaluated
before every tool invocation.

Promised as a follow-up on #2117 (2026-07-06): *"a small, language-agnostic JSON vector set ...
plus a zero-dependency checker script, independent of #2126 landing or which GuardrailProvider
implementation exists."* This is that fixture.

## What gets recomputed

`vectors.json` pins 10 cases against the exact behavior PR #2126 documents for its three built-in
guardrails:

| Guardrail | Rule |
|---|---|
| `AllowlistGuardrail` | exact-name membership; `final_answer` always permitted regardless of the allowlist |
| `BlocklistGuardrail` | exact-name membership; denies listed tools, permits everything else |
| `CompositeGuardrail` | evaluates providers in order — **first denial wins**; an empty provider list permits everything |

`check_guardrail_decision.py` **independently reimplements** this logic from the PR's own
documented semantics — it never imports smolagents — so a provider (theirs, ours, or a future
one) has something concrete to recompute against instead of the interface staying
descriptive-only.

## The adversarial case

`adversarial_deliberately_wrong_obvious_answer_substring_tool_name`: a naive checker doing
substring/prefix matching on `tool_name` instead of exact set membership would incorrectly
**allow** `web_search_v2` against an allowlist naming only `web_search` — the allowlist names an
exact tool, not a prefix family. Needed to prove the checker genuinely re-derives from the exact-
membership rule, not a shape that only happens to look right on the simpler cases.

```bash
python3 check_guardrail_decision.py
```
