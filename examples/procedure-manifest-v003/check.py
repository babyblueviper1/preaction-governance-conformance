#!/usr/bin/env python3
"""Independent checker for Procedure Manifests v0.0.3 -- acquisition boundary and authority eligibility.

Written from the v0.0.3 draft text only (chugarchugarr/technocore-chat docs/procedure-manifest-v0.0.3-acquisition-boundary.md):
eligible(o) = authorized_execution AND exact_request_binding AND unique_terminal_execution AND sufficient_scope (Normative
boundary), rules C16-C21 (section 9), fixtures F1-F6 (section 10). Standard library only.

Where the draft leaves an encoding open, this checker makes the simplest faithful choice and says so (see README):
  H(x)            = sha256 over canonical JSON (sorted keys, (",", ":") separators; ASCII/int values -> JCS-identical)
  manifest_hash   = H(manifest)
  dispute_id      = H({manifest_hash, contract_id, dispute_nonce}) from dispute_state
  ordering        = C16 (formulary-systems/spec#5 hardened text): precedence of the dispute commitment over every claim is read
                    ONLY from the profile's ordering_proof -- a hash-chained ordering log whose head is attested by the
                    manifest-pinned ordering_anchor_pubkey (a stand-in for OTS / chain inclusion), position = order.
                    committed_at / accepted_at are carried as evidence and never compared.
  run_id          = H({manifest_hash, dispute_id, requirement_id, judge_id, run_index})                 (section 1)
  attempt_id      = H({run_id, attempt_index}), attempt_index < retry_policy.max_attempts            (section 5)
  request_hash    = H(requirement.request)  -- the manifest-committed outcome-relevant inputs          (section 3)
  claim_receipt_hash = H(claim)
  attestations    = BIP-340 Schnorr by the manifest-pinned provider key over H(record without "attestation")

Every eligibility term is reported as true / false / cannot_establish; anything but four trues maps the run to
UNRESOLVED (Normative boundary: "If any term is false or cannot be established ... map the run to UNRESOLVED").

    python3 check.py <package.json>        # prints the evaluation, exit 0
    python3 check.py --vectors vectors/    # every vector vs its expect block; exit 1 on any mismatch
"""
import hashlib, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
from _bip340_nostr import schnorr_verify  # noqa: E402  (stdlib BIP-340, already in this repo)

DISABLED = set()          # mutation_check.py switches single rules off to prove each one is load-bearing


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def H(o):
    return hashlib.sha256(canon(o)).hexdigest()


def _sig_ok(record, pubkey):
    body = {k: v for k, v in record.items() if k != "attestation"}
    try:
        return schnorr_verify(hashlib.sha256(canon(body)).digest(), bytes.fromhex(pubkey), bytes.fromhex(record["attestation"]))
    except Exception:
        return False


def commitment_ok(c):
    """submission_commitment v0 (requester-signed; the shape from t/29563 #13/#15 as implemented live)."""
    try:
        body = {k: c[k] for k in ("type", "version", "request_digest", "attempt_id", "sent_at", "requester_pubkey")}
        return c.get("type") == "submission_commitment" and schnorr_verify(
            hashlib.sha256(canon(body)).digest(), bytes.fromhex(c["requester_pubkey"]), bytes.fromhex(c["sig"]))
    except Exception:
        return False


def admission_receipt_recomputes(r):
    """invinoveritas admission-chain-v1 profile: receipt_hash = H({admission_index, accepted_at, request_digest,
    prev_receipt_hash[, submission_commitment_ref]}) -- the provider's attestation for that profile (chain + OTS anchor)."""
    p = {"admission_index": r["admission_index"], "accepted_at": r["accepted_at"], "request_digest": r["artifact_hash"],
         "prev_receipt_hash": r["prev_receipt_hash"]}
    if r.get("submission_commitment_ref") is not None:
        p["submission_commitment_ref"] = r["submission_commitment_ref"]
    return H(p) == r.get("receipt_hash")


ZERO = "0" * 64


def claim_core(c):
    return {"run_id": c.get("run_id"), "attempt_id": c.get("attempt_id"), "request_hash": c.get("request_hash")}


def ordering(pkg, acq, ds, claims):
    """C16 ordering under the fixture profile: 'true' / 'false' / 'cannot_establish'. Never reads a clock value."""
    log, anchor = pkg.get("ordering_log"), acq.get("ordering_anchor_pubkey")
    if not log or not anchor:
        return "cannot_establish", "no authoritative ordering mechanism: a bare committed_at cannot establish precedence (C16, F6b)"
    prev, by_hash = ZERO, {}
    for i, e in enumerate(log.get("entries", [])):
        if e.get("seq") != i or e.get("prev") != prev or e.get("entry_hash") != H({k: e.get(k) for k in ("seq", "kind", "ref", "prev")}):
            return "cannot_establish", f"ordering log entry {i} does not chain (C16)"
        prev = e["entry_hash"]; by_hash[prev] = e
    cp = log.get("checkpoint") or {}
    if cp.get("head") != prev or cp.get("seq") != len(log.get("entries", [])) - 1 or not _sig_ok(cp, anchor):
        return "cannot_establish", "ordering checkpoint is not attested by the manifest-pinned anchor over the log head (C16)"
    dseq = [e["seq"] for e in by_hash.values() if e["kind"] == "dispute_commitment" and e["ref"] == H(ds)]
    if not dseq:
        return "cannot_establish", "dispute state is not in the ordering log (C16)"
    cseq = []
    for c in claims:
        e = by_hash.get(c.get("ordering_proof"))
        if not e or e["kind"] != "claim" or e["ref"] != H(claim_core(c)):
            return "cannot_establish", "a claim's ordering_proof does not resolve to its own entry in the ordering log (C16)"
        cseq.append(e["seq"])
    if cseq and min(dseq) > min(cseq):
        return "false", "the ordering log places the dispute commitment AFTER a claim (C16)"
    return "true", None


def evaluate(pkg):
    m = pkg["manifest"]; acq = m["acquisition"]; req_def = m["requirements"][0]
    out = {"terms": {}, "reasons": [], "state": "AUTHORIZED", "evidence": {}}
    T = out["terms"]

    # ---- submission evidence (section 2): preserved, never admission
    subs = pkg.get("submission_commitments", [])
    out["evidence"]["submission_commitments_valid"] = [commitment_ok(c) for c in subs]

    # ---- real-object profile: our live admission receipt (no pre-authorized slots in this profile)
    if acq.get("provenance_profile") == "invinoveritas-admission-chain-v1":
        rec = pkg.get("admission_receipt")
        if not rec:
            T.update(authorized_execution="false", exact_request_binding="cannot_establish",
                     unique_terminal_execution="cannot_establish", sufficient_scope="cannot_establish")
            out["reasons"].append("not_claimed: no provider admission; a submission_commitment alone is not admission (C18)")
        else:
            ok = admission_receipt_recomputes(rec)
            out["state"] = "CLAIMED" if ok else "AUTHORIZED"
            T["authorized_execution"] = "cannot_establish"
            out["reasons"].append("slot authorization cannot be established: this profile has no pre-authorized run_id (C16)")
            want = hashlib.sha256(req_def["request_text"].encode()).hexdigest()
            T["exact_request_binding"] = "true" if (ok and rec["artifact_hash"] == want) or "C17" in DISABLED else "false"
            if T["exact_request_binding"] == "false":
                out["reasons"].append("request_hash differs from the manifest-committed request (C17)")
            T["unique_terminal_execution"] = "cannot_establish"; T["sufficient_scope"] = "cannot_establish"
        return _finish(out, None)

    manifest_hash = H(m)
    ds = pkg["dispute_state"]
    derived_dispute = H({"manifest_hash": manifest_hash, "contract_id": ds["contract_id"], "dispute_nonce": ds["dispute_nonce"]})
    claims = pkg.get("claims", [])
    derived_ok = pkg["dispute_id"] == derived_dispute
    run_id = H({"manifest_hash": manifest_hash, "dispute_id": pkg["dispute_id"], "requirement_id": req_def["requirement_id"],
                "judge_id": req_def["judge_id"], "run_index": 0})
    max_att = int(acq["retry_policy"]["max_attempts"])
    attempt_ids = [H({"run_id": run_id, "attempt_index": k}) for k in range(max_att)]
    prov = acq["provider_pubkey"]

    def claim_valid(c):
        return (c.get("run_id") == run_id and c.get("attempt_id") in attempt_ids
                and c.get("provenance_profile") == acq["provenance_profile"]
                and (_sig_ok(c, prov) or "C18" in DISABLED))

    valid_claims = sorted((c for c in claims if claim_valid(c)), key=lambda c: attempt_ids.index(c["attempt_id"]))
    order, why = ordering(pkg, acq, ds, valid_claims)
    if "C16" in DISABLED:
        derived_ok, order = True, "true"
    if not derived_ok:
        out["reasons"].append("dispute_id is not the derivation from committed dispute state (C16, F6)")
    if why:
        out["reasons"].append(why)
    auth16 = "false" if not derived_ok or order == "false" else order       # true / false / cannot_establish
    if not valid_claims:
        T.update(authorized_execution="false" if claims or not subs else "false", exact_request_binding="cannot_establish",
                 unique_terminal_execution="cannot_establish", sufficient_scope="cannot_establish")
        if subs and not claims:
            out["reasons"].append("not_claimed: submission preserved as evidence; no provider claim, so not CLAIMED (C18)")
        elif claims:
            out["reasons"].append("no claim is provider-attested for an enumerated attempt of the authorized slot (C18/C16)")
        return _finish(out, None)
    out["state"] = "CLAIMED"
    per_attempt = {}
    for c in valid_claims:
        per_attempt.setdefault(c["attempt_id"], set()).add(H(c))
    if any(len(v) > 1 for v in per_attempt.values()) and "C18" not in DISABLED:
        out["state"] = "EQUIVOCATION"
        T.update(authorized_execution="false", exact_request_binding="cannot_establish",
                 unique_terminal_execution="cannot_establish", sufficient_scope="cannot_establish")
        out["reasons"].append("two distinct authentic claims for one authorized attempt_id; neither may acquire authority (C18, F1b)")
        return _finish(out, None)

    def terminals_for(c):
        crh = H(c)
        return [t for t in pkg.get("terminals", []) if t.get("claim_receipt_hash") == crh and _sig_ok(t, prov)]

    # ---- walk attempts in order: retry only after an attested NO_RESULT (C20); consuming terminals end the run (section 5)
    chosen, retry_violation = None, False
    for k, c in enumerate(valid_claims):
        ts = terminals_for(c)
        distinct = {(t["terminal_status"], t.get("output_hash")) for t in ts}
        if len(distinct) > 1 and "C19" not in DISABLED:
            out["state"] = "EQUIVOCATION"
            T.update(authorized_execution=auth16, exact_request_binding="cannot_establish",
                     unique_terminal_execution="false", sufficient_scope="cannot_establish")
            out["reasons"].append("conflicting attested terminals for one claimed attempt; none may be chosen (C19)")
            return _finish(out, None)
        status = next(iter(distinct))[0] if distinct else None
        later = valid_claims[k + 1:]
        if status == "NO_RESULT":
            if not later:
                out["state"] = "ATTESTED_NO_RESULT"
            continue                                   # an attested absence is the only thing that opens the next attempt
        if later and "C20" not in DISABLED:
            retry_violation = True
            out["reasons"].append("retry after an attempt that was not provider-attested NO_RESULT: caller timeout or "
                                  "unfavorable result does not authorize another attempt (C20)")
        if later and status is None and "C20" in DISABLED:
            continue                                   # mutant: a naive implementation accepts the retry and moves on
        if status is None:
            if retry_violation:
                break                                  # the run's only authorized attempt has no attested terminal
            chosen = None
            out["reasons"].append("claimed attempt has no attested terminal record")
            break
        chosen = (c, next(t for t in ts), status)
        break

    T["authorized_execution"] = "false" if retry_violation else auth16
    if not chosen:
        T.setdefault("exact_request_binding", "cannot_establish"); T.setdefault("unique_terminal_execution", "cannot_establish")
        T.setdefault("sufficient_scope", "cannot_establish")
        return _finish(out, None)
    c, t, status = chosen
    out["state"] = "TERMINAL_" + status if status in ("RESULT", "UNRESOLVED") else status
    T["unique_terminal_execution"] = "true"
    T["exact_request_binding"] = "true" if c["request_hash"] == H(req_def["request"]) or "C17" in DISABLED else "false"
    if T["exact_request_binding"] == "false":
        out["reasons"].append("claim binds the right slot to a request_hash that differs from the committed request (C17)")
    need = set(req_def["required_scope"]); got = set(t.get("observed_scope") or [])
    T["sufficient_scope"] = "true" if need <= got or "C21" in DISABLED else "false"
    if T["sufficient_scope"] == "false":
        out["reasons"].append(f"observation scope {sorted(got)} does not cover required_scope {sorted(need)} (C21)")
    if status == "UNRESOLVED":
        out["reasons"].append("terminal is explicitly UNRESOLVED: consumes the run, carries no result")
        return _finish(out, None)
    return _finish(out, t.get("output_hash"))


def _finish(out, output_hash):
    eligible = all(v == "true" for v in out["terms"].values()) and len(out["terms"]) == 4
    out["eligible"] = eligible
    out["run_verdict"] = "RESULT" if eligible and output_hash else "UNRESOLVED"
    if out["run_verdict"] == "RESULT":
        out["output_hash"] = output_hash
    return out


def check_vectors(d):
    bad = 0
    for f in sorted(os.listdir(d)):
        if not f.endswith(".json"):
            continue
        pkg = json.load(open(os.path.join(d, f))); r = evaluate(pkg); e = pkg["expect"]
        ok = r["run_verdict"] == e["run_verdict"] and r["eligible"] == e["eligible"] and r["state"] == e["state"] \
            and all(r["terms"].get(k) == v for k, v in e.get("terms", {}).items())
        bad += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {f:44} {r['state']:20} {r['run_verdict']:10} {r['terms']}")
        if not ok:
            print(f"      expected {e}\n      reasons {r['reasons']}")
    print("ALL PASS" if not bad else f"{bad} FAIL")
    return bad


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--vectors":
        sys.exit(1 if check_vectors(sys.argv[2]) else 0)
    print(json.dumps(evaluate(json.load(open(sys.argv[1]))), indent=1))
