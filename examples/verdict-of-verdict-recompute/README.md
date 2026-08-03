# verdict-of-verdict recompute — a re-review's vantage is capped, never upgraded

Follow-up to [`decision-ref-recompute/`](../decision-ref-recompute/), on the same discussion
([a2aproject/A2A#1734](https://github.com/a2aproject/A2A/discussions/1734), giskard09).

`decision_ref` makes a single verdict recomputable, not asserted. But nothing stopped a **chain**
of verdicts from silently amplifying trust: if Gateway B calls `/review` on an artifact that IS
Gateway A's already-signed verdict (a re-review, not a fresh action), `source_class` used to be
computed purely from the OUTER caller's own registry status — zero mechanical link to the INNER
verdict's vantage. A chain of `agent_reported` re-reviews could each independently claim
`independent_mediator` with nothing structurally preventing it.

invinoveritas `REVIEW_POLICY_VERSION` v6 closes it with a min-rule, bound into `decision_ref` the
same way every other field is — recomputable, not asserted:

```
outer.source_class = "agent_reported" if (own_computed == "agent_reported"
                                           or inner.source_class == "agent_reported")
                      else "independent_mediator"

outer.related_decision_ref = inner.decision_ref   # ONLY when inner independently re-verifies
```

`related_decision_ref` joins `decision_ref_preimage_fields` — the binding is cryptographic, not a
side-channel a downstream party has to trust on the outer caller's word.

## What this checks

Five real, cryptographically-signed vectors (produced through the actual production
`build_verdict_proof()` code path — real schnorr-signed Nostr events, not hand-built JSON):

| vector | outer caller | related inner verdict | resulting `source_class` |
|---|---|---|---|
| `inner_agent_reported` | — | — | `agent_reported` |
| `inner_independent_mediator` | — | — | `independent_mediator` |
| `outer_capped_by_agent_reported_inner` | mediator-class | `agent_reported` | `agent_reported` — **capped** |
| `outer_stays_elevated_with_mediator_inner` | mediator-class | `independent_mediator` | `independent_mediator` |
| `outer_fails_closed_on_tampered_inner` | mediator-class | tampered/unverifiable | `agent_reported` — **fail-closed** |

```
python3 check_verdict_of_verdict.py      # zero-dependency, offline
```

Three things get checked mechanically:

1. **Recompute** — each proof's `decision_ref` re-derives byte-for-byte from its own published
   `decision_ref_preimage_fields` (same discipline as `decision-ref-recompute/`).
2. **The min-rule** — a mediator-class caller re-reviewing an `agent_reported` verdict gets capped
   down; re-reviewing an `independent_mediator` verdict stays elevated (a matching inner class
   never blocks it, but nothing about the mechanism can produce an *upgrade*).
3. **Fail-closed** — a mediator-class caller citing a tampered/unverifiable `related_proof_event`
   is forced to `agent_reported` regardless of their own registry status. An unverifiable
   amplification claim gets the honest floor, not the benefit of the doubt.

A fourth check confirms an honest-disclosure fix caught during review before this shipped:
`mediator_name` (informational, names which registry entry matched) only appears when
`source_class` **actually ended up** `independent_mediator` — a proof that matched a registry
entry but got capped back down no longer shows `mediator_name`, which would otherwise misleadingly
imply the elevation held.

## Honest scope

This example recomputes hashes from published preimage fields and checks the min-rule / fail-closed
logic mechanically — the same scope boundary as `decision-ref-recompute/`. It does **not**
independently re-verify the schnorr signatures on the underlying Nostr events here (that's
`/verify-proof`'s job); the real signature-verification path is exercised by
`tests/test_verdict_of_verdict_binding.py` in the invinoveritas repo itself, with real nsec-signed
events end to end, plus a live production smoketest (real inner+outer `/review` calls,
`related_decision_ref` confirmed matching byte-for-byte, `POST /verify-proof` confirming
`decision_ref_recomputes: true` on the outer proof).

Separately, `related_decision_ref`'s presence proves the **cited proof's own authenticity** and
that its class was accounted for — it does **not** prove the cited verdict is actually, topically
what the outer artifact claims to be re-reviewing. Nothing here (or in the production code) checks
topical relatedness; only the cited event's cryptographic authenticity. Stated plainly rather than
left implicit, same standard as every other disclosure in this repo.

## Provenance

Real calls through the production `build_verdict_proof()` code path. The `agent_reported` vectors
use no registry match at all (the real, unmodified default path). The `independent_mediator`
vectors use a **locally simulated** registry match (`"ExampleMediator"`) rather than a real
external partner's live Bearer key — using a real partner's actual credentials for a public demo
wouldn't be appropriate. Everything else about the signing/re-verification path (the real nsec,
real schnorr signatures, the real `verify_proof_event` call inside `build_verdict_proof` itself
for the `related_proof_event` cases) is the genuine production code, not mocked.
