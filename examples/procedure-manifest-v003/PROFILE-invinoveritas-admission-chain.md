# Provenance-profile registry entry: `invinoveritas-admission-chain-v1` (and v2, in build)

Proposed for the v0.0.3 provenance-profile registry (formulary-systems/spec#5, "Provenance-profile registry and sufficiency"),
following the maintainer's invitation on formulary-systems/spec#3. It uses the registry's three declarations. Coverage is stated
as it is **today**, so the entry passes or fails the sufficiency rule on what is deployed now.

| | `invinoveritas-admission-chain-v1` (live) |
|---|---|
| **1. Eligibility terms it can establish** | `exact_request_binding`: **yes**. The receipt's `request_digest` is sha256 of the exact request, and a requester `submission_commitment` is bound by hash. `authorized_execution`: **ordering yes, slot no**. C16 ordering comes from the chain (row 3). Claim uniqueness is provider-enforced for commitment-bound requests: a replayed commitment `attempt_id` is refused with `duplicate_of_admission:<n>`. There is no pre-authorized `run_id` / `attempt_id` slot, so this term is `cannot_establish`. `unique_terminal_execution`: **no**. The terminal is a signed verdict proof, but the disposition is not in the chain. `sufficient_scope`: **no**. There is no `observed_scope` list. |
| **2. Records / lineage** | Admission receipt `receipt_hash = sha256(JCS{admission_index, accepted_at, request_digest, prev_receipt_hash[, submission_commitment_ref]})`, hash-chained from a fixed genesis. A periodic Merkle checkpoint covers each batch of receipts, and each checkpoint root is OpenTimestamps-stamped to Bitcoin. The terminal record is a BIP-340-signed verdict proof (`/verify-proof`, free, no auth). |
| **3. C16 ordering mechanism** | **Position in the admission chain, authenticated by checkpoint inclusion.** Each receipt commits its own `admission_index`. `GET https://api.babyblueviper.com/admission-chain/inclusion/<receipt_hash>` returns the Merkle path to that receipt's checkpoint root and the `.ots` proof. `ots verify` then checks the root against Bitcoin without calling us again. A dispute commitment admitted at index *i* (bound by `submission_commitment_ref`) precedes a claim admitted at index *j* iff *i* < *j*. No clock value is compared. **Limit:** proofs are served only when the receipt is alone in its checkpoint. A Merkle path through a shared checkpoint would hand out other callers' receipt hashes, which are derived from their artifacts, so those requests get `409` and the proof is withheld. Receipts used for a dispute need their own checkpoint until v2. |
| **Sufficiency** | **Refused at formation for an `llm_judge` today.** Only `exact_request_binding` is fully covered. `authorized_execution` has its ordering half but not slot authorization, and the other two terms are not covered. This is the outcome the rule exists for, and it is listed so the refusal is visible. |

## v2: the build that closes the remaining terms

`invinoveritas-admission-chain-v2` keeps every v1 receipt recomputing byte for byte. New keys enter the hash only when present, which is
the same rule already used for `submission_commitment_ref`.

| term | v2 mechanism |
|---|---|
| `authorized_execution` (slot) | An optional `slot` on the request (`manifest_hash, dispute_id, requirement_id, judge_id, run_index, attempt_index`). The service derives `run_id` / `attempt_id`, folds both into `receipt_hash`, and keeps a unique index on `attempt_id`, so a second claim for a slot is refused at admission. Because every admission is in the chain, a second claim that slipped through would be visible to any verifier rather than chosen silently (F1b). |
| `unique_terminal_execution` | A terminal record per admission (`claim_receipt_hash`, `terminal_status` RESULT / UNRESOLVED / NO_RESULT, `output_hash`, `observed_scope`), appended to the same hash chain under a one-terminal-per-index constraint and covered by the same OTS checkpoints. A second, conflicting terminal cannot be appended. An off-chain signed record that is not in the chain carries no authority. |
| ATTESTED_NO_RESULT (C20) | Signed and chained once the receipt's committed `response_deadline` passes with no verdict. A caller-side timeout is never accepted. |
| inclusion for every receipt | Salted leaves: `leaf = H(receipt_hash, salt)`, with the per-receipt salt returned only to the requester. A shared checkpoint then exposes only blinded siblings, so every proof can be served. |
| `sufficient_scope` | `observed_scope` is a flat token set derived from `review_policy_version` / `artifact_type`, and the predicate is fixed as `required_scope ⊆ observed_scope`. |

Executable conformance: the v0.0.3 vectors in this directory, mirrored in formulary-systems/spec#3. v2 will add real-object vectors
(R-*) whose `authorized_execution` resolves to `true` from a live slot-bound receipt plus its inclusion proof.
