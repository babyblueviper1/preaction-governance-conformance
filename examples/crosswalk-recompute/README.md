# Crosswalk recompute — is a vocabulary mapping a valid transition-authority proof?

When two governance boards use different tier vocabularies (one says `terminal`/`bounded`, another
says `D3`/`D2`), a **crosswalk** claims they mean the same thing. But a crosswalk is itself a claim —
and by the referee-of-referees property it must **recompute** the same way the verdicts it maps do,
not be trusted from whoever published the mapping.

This implements the acceptance bar the crewAI#4877 thread converged on: *publish the mapping with the
source verdict bytes it binds, recompute the authority tuple on both sides, and fail closed if
`allowed_runtime_use`, `claim_ceiling`, or `permitted_next_transition` diverges.*

- **valid crosswalk** = a recomputation that **agrees** — same authority tuple, regardless of tier names.
- **collision** = a recomputation that **disagrees** — names may match, authority differs → **fail closed**.

It is taxonomy-agnostic: it doesn't care that one board says `terminal` and the other `D3`; it cares
only whether the two verdicts authorize the same next transition under the same ceiling, recomputed
from each verdict's own `source_bytes` (the record id is `sha256` of those bytes — bind the tuple to
bytes anyone can re-hash, or it's an assertion).

## Run it

```bash
python3 check_crosswalk.py            # bundled sample
python3 check_crosswalk.py --file your_crosswalk.json
```

## The bundled sample shows both outcomes

- `invinoveritas:terminal ↔ correctover:D3` → **VALID**: different names, identical authority tuple
  (`autonomous_commit` / `recomputable_independent_anchored` / `execute`). Interoperable by recompute.
- `invinoveritas:terminal ↔ selfsigned_demo:D3` → **COLLISION**: the names both read "top tier," but
  the self-signed verdict's authority is `audit_log_only` / `attested` / `require_approval`. Same
  label, different authority — exactly the vocabulary collision a naming agreement would hide. Fails closed.

The point: "compatible vocabularies" stops being something two parties agree to and becomes something
anyone re-runs over their verdict bytes. The standard forms at the behavioral layer, not the dictionary.
