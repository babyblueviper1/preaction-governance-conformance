# decision-ref recompute — the pre-execution decision, recomputable not asserted

The agent-governance threads ([crewAI#4877](https://github.com/crewAIInc/crewAI/issues/4877),
[autogen#7353](https://github.com/microsoft/autogen/issues/7353)) converged on a decision-provenance
contract: between the **payment** (the transfer happened) and the **action receipt** (the agent acted)
sits the **decision** — *was this allowed, under which policy, with what verdict* — and it only governs
autonomy if it is (1) signed by an identity **distinct from the runtime it governs**, and (2)
**recomputable from its cited inputs**, not trusted because it carries a signature.

invinoveritas `/review` emits exactly this, as `decision_ref` on every signed verdict proof:

```
decision_ref = sha256(JCS({artifact_hash, artifact_type, policy_version, verdict}))
```

This check recomputes the published `decision_ref` from **its own published preimage fields**
(`decision_ref_preimage_fields` travels in the proof, so a third party never guesses the preimage —
the self-describing-preimage discipline), and exercises the negatives that separate *recomputable*
from merely *attested*:

| property | how |
|---|---|
| **recompute** | re-derive `decision_ref` from the published fields → byte-for-byte match |
| **tamper-sensitive** | change the verdict / policy / artifact → the id must change |
| **signer ≠ runtime** (fail closed) | a decision whose signer is the actor it governs is self-approval, not a second opinion |
| **verdict = f(inputs)** (fail closed) | a signed verdict that doesn't re-derive from its policy + proposal is void |

The first two are checked here from bytes; the last two are the semantic negatives a full verifier
enforces against the signed proof (`/verify-proof` re-derives `decision_ref` and reports
`decision_ref_recomputes`, and authorship is gated to the published verifier key ≠ the agent's runtime).

```
python3 check_decision_ref.py      # zero-dependency, offline
```

The sample vector is a real `/review` verdict proof — its `decision_ref` was produced by the live
signing path, so this recomputes a production identifier, not a hand-built fixture.
