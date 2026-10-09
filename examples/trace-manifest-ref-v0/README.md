# trace-manifest-ref-v0

Vectors for the optional signed `manifest {id, digest, media_type}` proposed for TRACE v0.3 in
[agentrust-io/trace-spec#483](https://github.com/agentrust-io/trace-spec/issues/483). The question they pin: does the record
carry the verification result, or only the reference, leaving appraisal to the verifier?

The checker carries only the reference. It verifies the record signature first (v0.2 s3.3 step 1), then recomputes
sha256 over the manifest bytes the resolver returns for `manifest.id` and compares it with the signed digest. A
`verification_result` written by the producer is never read.

| case | record | manifest | what it pins |
|---|---|---|---|
| m1-digest-matches | VALID | ESTABLISHED | the signed digest recomputes over the resolved bytes |
| m2-digest-mismatch | VALID | MISMATCH | the id now resolves to a later deployment (1.5.0 adds `wire_transfer`); the record ran under 1.4.0 |
| m3-mismatch-with-asserted-result | VALID | MISMATCH | same as m2 with `verification_result: verified` in the record: an asserted result is not carried forward |
| m4-unresolvable | VALID | NOT_ESTABLISHED: manifest-unresolved | not a pass, and not a reason to reject the record (the s3.1.2 rule 3 posture) |
| m5-added-after-signing | REJECTED: signature-invalid | not evaluated | `manifest` outside the signed bytes fails before any field is trusted |
| m6-control-no-manifest | VALID | NOT_ESTABLISHED: no-manifest-named | a v0.2 record without the object verifies as today |

```
python3 check.py --mutants   # 6/6 cases, 4/4 mutants killed, signature control (needs: cryptography)
python3 build.py             # regenerates vectors.json byte-identically
```

Mutants: M1 trusts the asserted `verification_result` (killed by m3); M2 treats an unresolvable manifest as a pass (m4);
M3 appraises the manifest without checking the signature first (m5); M4 rejects the whole record when the manifest does
not resolve (m4). Records are TRACE v0.2 records (the fields of trace-spec `examples/signature-encoding/01`) plus the
proposed object, signed embedded per v0.2 s3.2.2 (Ed25519 over RFC 8785 JCS, `signature` absent, base64url no padding, key
in `cnf.jwk`). `iat` is fixed and freshness is out of scope here. The signing key is a public test key derived from a fixed seed.
