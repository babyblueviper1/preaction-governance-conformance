#!/usr/bin/env python3
"""Cold checker for trace-manifest-ref-v0 (agentrust-io/trace-spec#483). Imports nothing from build.py.

For each case: (1) the record signature verifies over RFC 8785 JCS of the record with `signature` absent, under
cnf.jwk, BEFORE any other field is read (TRACE v0.2 s3.3 step 1); (2) the manifest reference is appraised by
recomputing sha256 over the bytes the resolver returns for manifest.id and comparing with the signed digest.
A `verification_result` the producer wrote is never read. Outcomes:
  ESTABLISHED                           digest recomputes over the resolved bytes
  MISMATCH:manifest-digest-mismatch     resolved bytes differ from what the record names
  NOT_ESTABLISHED:manifest-unresolved   the id does not resolve (not a pass; the record is not rejected for it)
  NOT_ESTABLISHED:no-manifest-named     no manifest object
  --mutants   run four checker mutants; each must be killed by at least one case.
Exit 0 iff every case matches its "expect" (and, with --mutants, every mutant is killed).
"""
import base64, copy, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
from _rfc8785 import jcs

def ub(s):
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(b).rstrip(b"=").decode() != s: raise ValueError("non-canonical base64url")
    return b

def sig_ok(rec):
    try:
        body = {k: v for k, v in rec.items() if k != "signature"}
        jwk = rec["cnf"]["jwk"]
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519": return False
        Ed25519PublicKey.from_public_bytes(ub(jwk["x"])).verify(ub(rec["signature"]), jcs(body).encode("utf-8"))
        return True
    except Exception:
        return False

def check(case, mutant=None):
    rec, store = case["record"], case["resolver"]
    if mutant != "M3_manifest_before_signature" and not sig_ok(rec):
        return {"record": "REJECTED:signature-invalid", "manifest": "NOT_EVALUATED"}
    m = rec.get("manifest")
    if m is None: return {"record": "VALID", "manifest": "NOT_ESTABLISHED:no-manifest-named"}
    if mutant == "M1_trust_asserted_result" and m.get("verification_result") == "verified":
        return {"record": "VALID", "manifest": "ESTABLISHED"}
    if m.get("id") not in store:
        if mutant == "M2_unresolved_is_pass": return {"record": "VALID", "manifest": "ESTABLISHED"}
        if mutant == "M4_reject_record_on_unresolved": return {"record": "REJECTED:manifest-unresolved", "manifest": "NOT_EVALUATED"}
        return {"record": "VALID", "manifest": "NOT_ESTABLISHED:manifest-unresolved"}
    got = "sha256:" + hashlib.sha256(store[m["id"]].encode("utf-8")).hexdigest()
    if got != m.get("digest"): return {"record": "VALID", "manifest": "MISMATCH:manifest-digest-mismatch"}
    out = {"record": "VALID", "manifest": "ESTABLISHED"}
    return out

def main():
    V = json.load(open(os.path.join(HERE, "vectors.json")))
    ok = 0
    for c in V["cases"]:
        got = check(c); good = got == c["expect"]; ok += good
        print(f"{'ok  ' if good else 'FAIL'} {c['id']:36s} record={got['record']:28s} manifest={got['manifest']}")
    n = len(V["cases"]); print(f"{ok}/{n} cases match"); rc = 0 if ok == n else 1
    if "--mutants" in sys.argv:
        killed = 0
        for mu in ("M1_trust_asserted_result", "M2_unresolved_is_pass", "M3_manifest_before_signature", "M4_reject_record_on_unresolved"):
            by = [c["id"] for c in V["cases"] if check(c, mu) != c["expect"]]
            killed += bool(by); print(f"{'KILLED' if by else 'SURVIVED'} {mu:32s} by {', '.join(by) or '-'}")
        print(f"{killed}/4 mutants killed"); rc = rc or (0 if killed == 4 else 1)
    # mutation control: one byte of a signed field changed must fail the signature check
    t = copy.deepcopy(V["cases"][0]["record"]); t["manifest"]["digest"] = t["manifest"]["digest"][:-1] + ("0" if t["manifest"]["digest"][-1] != "0" else "1")
    ctrl = not sig_ok(t); print(f"{'ok  ' if ctrl else 'FAIL'} control: editing the signed manifest digest fails the signature"); rc = rc or (0 if ctrl else 1)
    sys.exit(rc)

if __name__ == "__main__":
    main()
