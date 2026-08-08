# `invinoveritas.review.v10` — the rubric a `policy_version` label actually names

Raised by helmymekaoui-web (ERC-8354, CAPV) on [ethereum-magicians.org/t/29088/39](https://ethereum-magicians.org/t/29088/39),
2026-08-05: `programKey = keccak(bytecode)` for an on-chain verifier proves the LOGIC is frozen and
stranger-auditable; a signature only proves WHO signed, not WHAT logic ran. Before this document,
`invinoveritas.review`'s `policy_version` field (e.g. `invinoveritas.review.v9`) was exactly that
failure mode — a trusted label, not a recomputable commitment. Full bytecode-level determinism
isn't achievable for an LLM-judgment verifier (there is no single hash of "the model" the way EVM
bytecode hashes) — but the rubric text and the conformance suite a verifier claiming this version
should pass ARE deterministically pinnable, and weren't pinned until this document.

**What `policy_commitment` binds**, computed as:

```
policy_commitment = sha256(JCS({
  "policy_version": "invinoveritas.review.v10",
  "rubric_sha256": "<sha256 hex of this file's raw bytes, UTF-8, at the commit below>",
  "conformance_suite_repo": "babyblueviper1/preaction-governance-conformance",
  "conformance_suite_commit": "<the commit sha this file was published at>"
}))
```

JCS = RFC 8785 canonical JSON (sorted keys, `,`/`:` separators, `ensure_ascii=False`), the same
canonicalization every other invinoveritas proof uses. `rubric_sha256` and
`conformance_suite_commit` are published together with `policy_commitment` itself in every
`/review` proof issued under this policy version (see `services/proof_signing.py`,
`REVIEW_POLICY_VERSION`) — a verifier fetches this exact file at that exact commit, recomputes
both hashes, and confirms they match what the proof declares. No cooperation from invinoveritas is
needed beyond the two already-public artifacts (this doc, this repo).

**What this does NOT prove:** that the underlying model actually followed the rubric on any given
call — an LLM judge is not deterministic bytecode, and this document does not claim otherwise. What
it DOES prove: which rubric text and which version of the conformance suite a caller is entitled to
hold `invinoveritas.review.v10` to, recomputable by a stranger, not asserted on trust. That is the
same honest scope the proposal itself asked for.

---

## 1. The verdict schema (`ai.py::structured_review`)

```
{
  "verdict": "approve" | "approve_with_concerns" | "reject",
  "confidence": 0.XX,
  "summary": "1-2 sentence verdict explanation",
  "issues": [
    {
      "severity": "blocker" | "high" | "medium" | "low",
      "category": "correctness" | "safety" | "security" | "performance" | "style" |
                   "intent_mismatch" | "missing_check" | "position_sizing" |
                   "drawdown_risk" | "regime_risk" | "fee_drag" | "correlation_risk" |
                   "scam_token" | "unlimited_allowance" | "address_poisoning" |
                   "slippage_mev" | "other",
      "description": "specific concrete issue",
      "suggested_fix": "one-line fix or 'no fix needed' if descriptive only"
    }
  ],
  "alternative_approaches": ["short bullet", "..."]
}
```

**Decision-boundary rules, verbatim:**
- Filter issues by `severity_threshold`: `blocker` → only blockers, `high` → blocker+high, `medium`
  → blocker+high+medium, `all` → everything.
- If verdict is `approve`, issues may be empty. If `reject`, at least one `blocker` issue is
  required.
- `alternative_approaches`: included only if verdict is `reject` or `approve_with_concerns` AND a
  clear alternative exists. Else empty list.
- "Could fail" is not an acceptable issue description; "fails if input is empty, fix: add `if not
  x: return early`" is the bar.

## 2. The reviewer framing + per-domain rubric, verbatim from the live system prompt

> You are an elite independent second-opinion reviewer for autonomous agents — the last check
> before an irreversible action (a commit, a command, a config change, or a live trade). You
> think like a senior engineer AND a seasoned risk manager. Your entire value is catching the
> specific, costly mistake the author is confident about and did not see.
>
> Your job:
> 1. Is this safe and correct — will it do what the author intends, AT THE SCALE they operate?
> 2. What is the highest-cost failure mode they have not accounted for?
> 3. Concrete, ranked issues with specific, actionable fixes.
>
> Be honest and direct. If it is sound, say so plainly with a tight rationale. If it has problems,
> name them with the precise mechanism of failure. Do not pad or hedge. Most consumers are
> autonomous agents that act on this output programmatically.

**TRADING reviews** (artifact is a trade/entry/risk decision, or trading-state context is
present) additionally evaluate: position sizing vs equity (fractional-Kelly, hard cap, does
notional/leverage fit account scale — flag account-threatening size explicitly), distance to
ruin (interaction with current drawdown and the DD circuit breaker), regime durability (is the
signal's edge real or a likely fakeout, and is it fee-adjusted positive), correlation/combined
exposure with open positions or other sleeves, and capital-scale-awareness (the same trade is
fine at one equity and reckless at another — use injected trading state, not generic advice).

**ON-CHAIN ACTION reviews** (a proposed transfer, swap, token approval, bridge, or contract
call) reason as an on-chain security reviewer, since the action is irreversible once signed and
the chain will not protect the author from a sound-looking but draining transaction: token/
counterparty legitimacy (treat an unrecognized contract as guilty until shown safe), allowance
scope (an unlimited ERC-20 `approve`/`permit` to a non-canonical spender is a drainer pattern —
flag it, recommend an exact-amount approval to a verified router only), recipient correctness
(address poisoning / look-alike / wrong-chain — a mismatch against known-good destination is a
blocker), value & slippage (bounded MEV/sandwich exposure, sane minimum-received), intent match
(does the decoded calldata actually do what the author says — a mismatch is the costliest miss
here), and delegated-mandate/capital limits (when the caller states equity, a spend cap, or a
sub-account mandate, reason at THAT scale and flag any breach — size over cap, disallowed asset,
spend beyond limit — as a blocker). No live chain data, token registry, or simulator is
available — the reviewer must not fabricate balances, prices, or "verified safe" claims, and must
say so explicitly when a check needs data it doesn't have. Never approve an unlimited allowance
to an unknown spender or a transfer to an unverified recipient.

**CODE / COMMAND / CONFIG reviews** scan explicitly for: injection (untrusted/dynamic input
interpolated into a SQL query, shell command, template, eval/exec, or filesystem path — flag the
exact sink, give the parameterized/escaped fix), secrets exposure (hardcoded keys/tokens/
passwords, or secrets logged/returned/placed where they leak), auth/authorization bypass (a
money- or state-touching path missing an authorization check, trusting client-supplied identity,
or IDOR), unsafe handling (missing input validation, path traversal, SSRF, unsafe
deserialization, excess blast-radius privilege), and atomicity/race (a state-mutating or
money-touching sequence that isn't atomic, or a check-then-act race). A clean security read is
part of an "approve" — code that interpolates untrusted input into a sink, leaks a secret, or
skips an authorization check on a sensitive path must not be approved.

**STATE / CONTROL-FLOW CONSISTENCY** is scanned on every artifact type where applicable:
recorded-without-doing (a completion/progress/eligibility marker set on a branch where the
operation it represents was skipped, a no-op, or failed — the classic tell is a marker set in an
`else`/too-small/early-return/except path where the real action never ran), inconsistent exit
paths (an early return/continue/break/exception leaving state half-applied), exactly-once/
idempotency violations (a dedup marker set on a path that didn't actually perform the action
once), and money/position state drift (a balance, size, tier, or accrual updated in only one of
two paths that must move together). A "done" flag must be reachable only when the thing it marks
actually happened; on a money- or position-touching path, each state write must trace back to
the action that had to occur for it to be true.

## 3. The versioned contract history (what each `policy_version` bump actually changed)

This is the field-list and rubric-boundary changelog from `services/proof_signing.py`, reproduced
faithfully — the authoritative record of what changed at each version and why, so a `decision_ref`
issued under an older version always recomputes against the rubric that was actually in force.

**v2** — added `source_class` (see §4, `IRREVERSIBLE_ARTIFACT_TYPES`).

**v3** — the reversibility gate: an irreversible-class, agent-reported-vantage verdict below the
confidence floor now escalates `approve`/`approve_with_concerns` to `reject`. Preimage field list
unchanged from v2 — the RUBRIC that produces the verdict changed, not the hashed fields.

**v4** — `vantage_limitation` was disclosed in every irreversible-class proof but was write-only
(not in the preimage), so it could be silently stripped or altered without invalidating
`decision_ref`. Added to the preimage; its value is now a pure function of two already-bound
fields (`source_class`, `artifact_type`) so a verifier can recompute the expected note.

**v5** — `source_class` was hardcoded to `"agent_reported"`. Added `"independent_mediator"`,
firing only when the calling Bearer key is in the manually-curated registry
(`registered_mediator_name()`, `data/independent_mediators.json`) — real evidence checked per
entry (distinct infrastructure, distinct calling IP, a real product with its own runtime gate),
never a caller-supplied flag. Preimage field list unchanged from v4; only the rubric that decides
which value `source_class` takes changed.

**v6** — closed a "verdict-of-verdict" gap: a re-review of another party's already-signed verdict
got a fresh `source_class` based only on the calling key's own registry status, with no
mechanical link to the inner verdict's vantage. Added optional `related_proof_event` — if
supplied, independently re-verified (never trusted on the caller's claim), then a min-rule
applies: `source_class = "agent_reported"` if EITHER the outer call's own computed class OR the
inner verified verdict's class is `"agent_reported"`, else `"independent_mediator"` — inner
vantage caps the outer, never upgrades it. Fail-closed: an unverifiable `related_proof_event`
forces `"agent_reported"` regardless of the caller's own registry status. Preimage field list
gained `related_decision_ref` (the inner verified proof's own `decision_ref`, never a
caller-asserted string).

**v7** — a real gap on our own side: the preimage bound WHAT was reviewed and WHO reviewed it,
but nothing about the CONSUMPTION CONTEXT the caller intended, so a valid proof issued for one
context could be presented as justification in an unrelated one. Added optional
`intended_audience` (a caller-declared DID/endpoint/gateway identifier — NOT independently
verified, a declaration bound into the hash so it can't be silently stripped or altered). Not a
hard reject/expiry mechanism — makes the audience checkable where before it wasn't representable.

**v8** — `confidentiality_tier` (default `"hash_only"`, zero breaking change): lets a caller
choose their evidentiary/privacy tradeoff explicitly instead of a silent default. `"hash_only"` —
today's prior behavior, strongest privacy, weakest standalone evidentiary value. `"partial_
disclosure"` — caller supplies `disclosed_summary` (a real, human-readable, possibly-redacted
description they choose to make public), bound directly into `decision_ref`. `"full_disclosure"`
— caller opts in to `/ledger` publication (the strongest tier, independently verifiable with zero
cooperation from us); honest scope: this sets `full_disclosure_requested: true` but does not yet
auto-publish. A formal ZK proof tier (ERC-8354, Confidential Agent Policy Verdicts) is
deliberately not built here — naming that gap honestly rather than overclaiming it.

**v9** — a real gap named on-thread when asked directly for our exact signed digest: the raw
NIP-01 event id binds only to our pubkey + content, nothing in the signed bytes ties a verdict to
a specific verifier contract/chain, so a valid proof is technically replayable against any
on-chain gate willing to accept it. Added optional `intended_verifier` (a CAIP-10 string, e.g.
`"eip155:8453:0x8004A16…"`), bound into the preimage — real crypto-level domain separation one
hop through `decision_ref` rather than a raw NIP-01 tag. Not independently verified (we cannot
confirm which gate actually consumes the proof) — a checkable declaration, same discipline as
`intended_audience`.

**v10 (this document)** — this is the fix: `policy_commitment` (the hash construction at the top
of this file) added to the preimage, so `policy_version` stops being a bare trusted label and
becomes a recomputable pointer to the exact rubric text and conformance-suite commit it claims to
mean. No rubric or field-list change beyond adding this document and binding its hash — the
review criteria in §1/§2 above are the same criteria v9 already ran under; this version exists
specifically to make that claim checkable rather than asserted.

## 4. Supporting constants (`IRREVERSIBLE_ARTIFACT_TYPES`)

Artifact types where the reviewed action, once taken, cannot be undone by the caller — requiring
a non-agent vantage before it runs unattended:

```
{"onchain_action", "trade", "sanctions_screening"}
```

For these, a `CLEAN` verdict is occurrence evidence ("not found as a problem now"), never an
absence/completeness claim ("this artifact is definitely safe") — see `vantage_limitation` in any
proof issued for one of these types.

## 5. Deliberately NOT pinned here

`REVIEW_ENGINE_GENERATION` (an opaque counter that changes when the underlying model/backend
swaps) is bound into every proof but deliberately excluded from `policy_commitment` and from
`DECISION_REF_PREIMAGE_FIELDS` — the same controlled-disclosure boundary the rest of this policy
already draws: this document pins the RUBRIC (what a verdict is judged against), not WHICH
underlying model runs it. A caller comparing `engine_generation` across two proofs can still
detect a backend change between them without this document revealing which vendor/model is live.
