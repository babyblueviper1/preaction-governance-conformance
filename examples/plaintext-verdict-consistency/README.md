# plaintext-verdict-consistency — a hash matching isn't the same as the label matching

Found live 2026-07-01 in [`Correctover/correctover-crewai`](https://github.com/Correctover/correctover-crewai)
(commit `88bc71c6`, `pip install correctover-crewai==0.1.0` — the real published package, not a
hypothetical), after STANDARDS.md invited feedback on their recomputable proof-package design.

## What was tested

`RecomputeEngine().verify_proof_package(pkg)` is documented as the trust-removal primitive: take a
proof package, recompute the verdict from its raw bytes, compare hashes, done — "no trust required."
Ran it end-to-end against a real package generated with their own `SixDimVerifier`:

| Test | Result |
|---|---|
| Untampered recompute | `valid: True` — the core claim holds |
| Tamper `tool_output` (content) | `valid: False`, hash changes — content tampering is caught |
| Tamper `expected_verdict` **only** (leave `expected_proof_hash` untouched) | **`valid: True`** |

## Why the third case matters

The proof package carries the same claim in two forms sitting side by side:

```json
{
  "expected_verdict": "partial",         // plaintext, human-readable
  "expected_proof_hash": "650f22cb..."   // SHA-256(input + rules + per-dim results + verdict)
}
```

`verify_proof_package`'s `valid` field is set purely from a hash comparison
([`recompute.py` lines 155-174](https://github.com/Correctover/correctover-crewai/blob/88bc71c6/src/correctover_crewai/recompute.py#L155-L174)).
It never checks that the plaintext `expected_verdict` — the field a caller would naturally read next
to `valid: True` — actually agrees with the freshly recomputed verdict. So a package's plaintext claim
can be edited independently of its hash, and the API's own trust signal (`valid: True`) won't catch it.

This is the same failure class as `verdict != f(controls)` in the presidio x402 fixture graded
elsewhere in this suite — a claim that hashes fine but doesn't recompute to what it says it does — one
layer sneakier here because the mismatched field is plaintext, not a derived value, so it *looks* like
ground truth sitting right next to a passing check.

## The fix

One additional assertion closes it: `valid = (hash matches) AND (expected_verdict == recomputed_verdict)`.
`check_plaintext_consistency.py` reproduces both the vulnerable check and the fixed one side by side —
the vulnerable check reports `valid: True` on the tampered package (reproducing the bug exactly), the
fixed check reports `valid: False` (closing it).

```
python3 check_plaintext_consistency.py      # zero-dependency, offline
```

Exit `0` iff the reproduction matches the live finding exactly: untampered passes both checks, content
tampering fails both, plaintext-only tampering fails only the vulnerable check and is caught by the fix.

Posted to the finding's source thread: [crewAI#4877](https://github.com/crewAIInc/crewAI/issues/4877#issuecomment-4849324962).
