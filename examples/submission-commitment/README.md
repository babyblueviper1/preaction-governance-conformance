# submission_commitment v0: requester-side evidence of an attempted submission

Implementation of the shape agreed on [agentrust-io/trace-spec#279 — Procedure Manifests RFC discussion, eth-magicians
t/29563](https://ethereum-magicians.org/t/rfc-procedure-manifests-mechanism-for-ai-agents-to-resolve-contractual-disputes/29563/13)
(@chugarchugarr, posts #13 and #15). Not a proposed TRACE requirement — implementation evidence for the discussion.

## The shape, and why it is a separate object

Two authority-bearing objects, never merged into one:

| object | who signs it | proves | exists even when |
|---|---|---|---|
| `submission_commitment` | the **requester** | "I attempted this exact submission" | no provider receipt was ever issued |
| `claim_receipt` (a provider's admission receipt) | the **provider** | "I accepted this exact submission" | — |

From #15: *"submission_commitment has to remain independently meaningful precisely when no claim_receipt ever
exists... never let the commitment alone imply admission."* If it were folded into the receipt as an attribute, the
pre-admission failure case (request sent, no receipt because the provider silently dropped it) would lose the
requester-side evidence entirely. Kept as its own typed object; a provider's receipt binds to it **by hash**
(`submission_commitment_ref`) when one was supplied and verified — never the reverse.

## The object

```json
{
  "type": "submission_commitment", "version": "v0",
  "request_digest": "<64-hex sha256 of the artifact text, exactly as the provider hashes it>",
  "attempt_id": "<8-128 chars [A-Za-z0-9_-], requester-chosen, unique per attempt>",
  "sent_at": "<int unix seconds, requester's own clock>",
  "requester_pubkey": "<64-hex BIP-340 x-only key>",
  "sig": "<128-hex BIP-340 signature over sha256(canonical({type,version,request_digest,attempt_id,sent_at,requester_pubkey}))>"
}
```
`submission_commitment_ref = sha256(canonical(full object including sig))`. Canonical form is JSON with sorted keys
and `(",", ":")` separators — every value here is an ASCII string or integer, so this is byte-identical to RFC 8785
(JCS) output.

## Verify (stdlib only, no pip install)

```
python3 tools/verify_submission_commitment.py examples/submission-commitment/events/valid_commitment.json
python3 tools/verify_submission_commitment.py examples/submission-commitment/events/tampered_commitment.json
```

`events/valid_commitment.json` and `events/tampered_commitment.json` (one field changed after signing) are fixtures;
`MANIFEST.sha256` holds their hashes. `tools/verify_submission_commitment.py` reuses the BIP-340 verifier already in
`_bip340_nostr.py` and cross-checks byte-for-byte against the production module
(`services/submission_commitment.py` in the invinoveritas repo) on both fixtures.

## Live reference implementation

invinoveritas's `/review` endpoint accepts an optional `submission_commitment` field. When it verifies and commits to
exactly the submitted artifact, the admission's `claim_receipt` (our hash-chained admission receipt, see
`examples/context-provenance-chain` and `agentbaseline/agentbaseline#26`) binds to it by hash — folded into
`receipt_hash`, and so into the periodic Merkle/OTS checkpoints. Verified live, 2026-09-21: a valid commitment ->
`submission_commitment_status: "verified"` and a bound `submission_commitment_ref` in the receipt; the same
`attempt_id` replayed -> `duplicate_of_admission:<n>` (one attempt binds to one admission, a replay is never
re-bound); a commitment for a different artifact -> `invalid:request_digest_mismatch`, and the request is still
admitted, unbound (a bad commitment never blocks the review it rides on).

Named states, never a shared null — no `submission_commitment_status` collapses into a generic pass: `absent` |
`verified` | `invalid:<reason>` | `duplicate_of_admission:<n>`.

## What this does not establish

A verifying `submission_commitment` proves the requester attempted exactly this submission at (or before) the
stated time. It does not prove the provider ever saw it, admitted it, or issued any result — that is what the
provider's own `claim_receipt` is for, and the two are bound by hash only when both exist.
