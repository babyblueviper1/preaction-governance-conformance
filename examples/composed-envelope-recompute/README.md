# composed-envelope-recompute — N independent signers, ONE artifact

The three-party example checks N artifacts with one checker. This example
checks N *signers* on one artifact: a `verification.v0.3+composed` envelope
carrying **three signatures from three independent issuers** — AgentOracle
(claim-verification gate), AgentTrust (capability screen), Presidio
(PII screen) — over the same canonical payload.

Same invariant, one level down: no key rides in the artifact, each signature
resolves from its signer's **own** published key set, and an examiner can
accept one signature while rejecting another on the same record.

## Run it

    python3 check_composed_envelope.py

Zero dependencies. The Ed25519 core and RFC 8785 (JCS) canonicalizer are
vendored (pure stdlib); a second verifier using any correct Ed25519 / JCS
implementation reaches the same result.

## What it recomputes (never trusts)

| Check | How |
|---|---|
| canonicalize-as-received | payload bytes must equal `JCS(parse(payload bytes))` — a payload that is not its own canonical form fails before any signature is checked |
| canonical hash | `sha256(payload_bytes)` recomputed, printed, never read from the artifact |
| every signature | JWS signing input rebuilt per signer (`protected_b64.payload_b64`), Ed25519-verified against the key whose `kid` resolves in that signer's own JWKS file — three signers, three separate key files |
| tamper sensitivity | one bit flipped in the payload → canonical recompute fails AND all three signatures fail; an unparseable payload fails closed rather than crashing the verifier |

## Composition semantics

`composed_decision` in the payload is `AND_PRESENT` across the sibling
verdicts (`v_gate`, `screen_ref`, …): absent siblings do not contribute;
any present-and-halt collapses the composed decision to halt. The point of
multi-issuer composition is that the composed verdict is checkable **per
signer**: a policy that trusts AgentTrust but not Presidio can verify
exactly the signatures it trusts, on the same bytes.

## Provenance (real signatures, published bytes — and one distinction worth naming)

- The envelope is `jws-005` from the published conformance suite of the
  verification.v0.3 spec (github.com/TKCollective/agentoracle-receipt-spec,
  `examples/v0.3-composed/`), unmodified. The three JWKS files are copied
  from the same suite.
- These are the **fixture-suite keys published in the spec repo** — not the
  issuers' production keys. The production AgentOracle JWKS lives at
  `agentoracle.co/.well-known/jwks.json`; live envelopes verify against it
  with the identical procedure. The distinction matters and is stated here
  rather than discovered.
- The same vector set was independently reimplemented by AgentTrust and
  verified **byte-identical** against the reference implementation
  (giskard09/argentum-core PR #33) — so "these bytes canonicalize and verify
  this way" is a claim two unrelated codebases already agree on, checkable
  in a third repo.
- Format: JCS (RFC 8785) canonical payload · Ed25519 JWS (RFC 7515/8037) ·
  `typ: application/vnd.verification.v0.3+composed+jws` · normative spec:
  IETF draft-krausz-verification-state (individual submission; a draft, not
  an adopted standard).

"Conformant" here means **recomputes** — never *we say so*.
