#!/usr/bin/env python3
"""Builds the v0.0.3 fixtures into vectors/ (deterministic keys; BIP-340 signing needs `coincurve` at BUILD time only --
check.py verifies with the stdlib BIP-340 in this repo). Real-object vectors are copied from live artifacts, not built."""
import hashlib, json, os, sys
import coincurve

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check import H, canon  # noqa: E402

OUT = os.path.join(HERE, "vectors"); os.makedirs(OUT, exist_ok=True)
KEYS = {n: coincurve.PrivateKey(hashlib.sha256(f"pm003-fixture-key:{n}".encode()).digest()) for n in ("provider", "requester", "anchor")}
PUB = {n: k.public_key_xonly.format().hex() for n, k in KEYS.items()}


def sign(rec, who):
    body = {k: v for k, v in rec.items() if k != "attestation"}
    aux = hashlib.sha256(canon(body)).digest()                       # deterministic aux -> byte-stable vectors
    rec["attestation"] = KEYS[who].sign_schnorr(hashlib.sha256(canon(body)).digest(), aux).hex()
    return rec


REQUEST = {"evidence_root": "sha256:" + "5a" * 32, "prompt_or_material_digest": "sha256:" + "c3" * 32,
           "judge_execution_profile": "pm003-judge-v1", "model_version_or_weights_pin": "judge-weights-2026-09",
           "sampling_parameters": {"temperature": 0, "top_p": 1, "seed": 7}}
ZERO = "0" * 64


def manifest(max_attempts=1, allowed_after=("ATTESTED_NO_RESULT",)):
    return {"spec": "procedure-manifest", "version": "0.0.3", "contract_id": "contract-pm003-fixture",
            "acquisition": {"dispute_id_rule": "H(manifest_hash, contract_id, dispute_nonce)",
                            "predecessor_authority_rule": "dispute_state committed as a dispute_commitment entry in the ordering log",
                            "ordering_proof_rule": "hash-chained ordering log; head attested by ordering_anchor_pubkey; log position = order; clock values never compared",
                            "ordering_anchor_pubkey": PUB["anchor"],
                            "run_id_rule": "manifest+dispute+requirement+judge+run_index",
                            "provenance_profile": "pm003-bip340-v0", "provider_pubkey": PUB["provider"],
                            "claim_semantics": "provider-attested single-use claim per enumerated attempt_id",
                            "terminal_semantics": "provider-attested terminal bound to claim_receipt_hash",
                            "retry_policy": {"allowed_after": list(allowed_after), "max_attempts": max_attempts}},
            "requirements": [{"requirement_id": "R1", "judge_id": "J1", "request": REQUEST,
                              "required_scope": ["criteria:R1", "evidence:full"]}]}


def slot(m, nonce="dispute-nonce-1"):
    mh = H(m)
    did = H({"manifest_hash": mh, "contract_id": m["contract_id"], "dispute_nonce": nonce})
    run_id = H({"manifest_hash": mh, "dispute_id": did, "requirement_id": "R1", "judge_id": "J1", "run_index": 0})
    return did, run_id


def claim(run_id, k, req=REQUEST, at=2000):
    """Unsigned claim; pkg() adds ordering_proof and the attestation once the ordering log exists."""
    return {"run_id": run_id, "attempt_id": H({"run_id": run_id, "attempt_index": k}), "request_hash": H(req),
            "accepted_at": at, "provenance_profile": "pm003-bip340-v0"}


DS = {"contract_id": "contract-pm003-fixture", "dispute_nonce": "dispute-nonce-1", "committed_at": 1000}


def ordering_log(ds, claims, dispute_pos=0, signer="anchor"):
    """Entries in log order: the dispute commitment at dispute_pos among the claims. Returns (log, [entry_hash per claim])."""
    items = [("claim", H({"run_id": c["run_id"], "attempt_id": c["attempt_id"], "request_hash": c["request_hash"]})) for c in claims]
    items.insert(dispute_pos, ("dispute_commitment", H(ds)))
    prev, entries = ZERO, []
    for i, (kind, ref) in enumerate(items):
        e = {"seq": i, "kind": kind, "ref": ref, "prev": prev}
        e["entry_hash"] = prev = H(e); entries.append(e)
    cp = sign({"seq": len(entries) - 1, "head": prev}, signer)
    proofs = [e["entry_hash"] for e in entries if e["kind"] == "claim"]
    return {"entries": entries, "checkpoint": cp}, proofs


def pkg(name, desc, m, did, claims=(), terms=(), subs=(), expect=None, dispute_state=None, assertions=(),
        dispute_pos=0, log=True, anchor="anchor", claim_signer="provider"):
    """terms: (claim_index, status, output, scope) -- built after the claims are final so claim_receipt_hash binds them."""
    ds = dispute_state or DS
    claims = [dict(c) for c in claims]
    p = {"name": name, "description": desc, "manifest": m, "dispute_id": did, "dispute_state": ds,
         "submission_commitments": list(subs), "executor_assertions": list(assertions), "expect": expect}
    if log:
        p["ordering_log"], proofs = ordering_log(ds, claims, dispute_pos, anchor)
        for c, op in zip(claims, proofs):
            c["ordering_proof"] = op
    claims = [sign(c, claim_signer) for c in claims]
    tl = []
    for ci, status, out, scope in terms:
        t = {"claim_receipt_hash": H(claims[ci]), "terminal_status": status, "observed_scope": list(scope)}
        if out:
            t["output_hash"] = H({"verdict": out})
        tl.append(sign(t, "provider"))
    p["claims"], p["terminals"] = claims, tl + ([dict(tl[0])] if name.startswith("P3") else [])
    json.dump(p, open(os.path.join(OUT, name + ".json"), "w"), indent=1, sort_keys=True)


def commitment(req, attempt="pm003-att-0001"):
    c = {"type": "submission_commitment", "version": "v0", "request_digest": H(req), "attempt_id": attempt,
         "sent_at": 1500, "requester_pubkey": PUB["requester"]}
    body = dict(c)
    c["sig"] = KEYS["requester"].sign_schnorr(hashlib.sha256(canon(body)).digest(), hashlib.sha256(canon(body)).digest()).hex()
    return c


FULL = ("criteria:R1", "evidence:full")
T4 = lambda **kv: {"authorized_execution": "true", "exact_request_binding": "true", "unique_terminal_execution": "true",
                   "sufficient_scope": "true", **kv}
UNRES = lambda state, **terms: {"run_verdict": "UNRESOLVED", "eligible": False, "state": state, "terms": terms}
m1, m2 = manifest(1), manifest(2)
d1, r1 = slot(m1); d2, r2 = slot(m2)
for f in os.listdir(OUT):                       # regenerate from scratch (renamed vectors must not linger)
    if f.endswith(".json") and not f.startswith("R-"):
        os.remove(os.path.join(OUT, f))

# ---- positive controls (the checker must not just reject everything)
pkg("P1-valid-result", "Authorized slot, dispute ordered before the claim in the attested log, exact request, one attested terminal, scope covers -> RESULT.",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})
pkg("P2-retry-after-attested-no-result", "Attempt 0 is provider-attested NO_RESULT, so attempt 1 is authorized (section 5, C20).",
    m2, d2, [claim(r2, 0), claim(r2, 1, at=2100)], [(0, "NO_RESULT", None, FULL), (1, "RESULT", "PASS", FULL)],
    expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})
pkg("P3-identical-duplicate-terminals", "The same terminal record delivered twice is not equivocation (C19: byte-identical duplicates are redundant copies).",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})
pkg("P4-terminal-unresolved", "An explicit TERMINAL_UNRESOLVED consumes the run and carries no result (section 4).",
    m1, d1, [claim(r1, 0)], [(0, "UNRESOLVED", None, FULL)], expect={"run_verdict": "UNRESOLVED", "eligible": True, "state": "TERMINAL_UNRESOLVED", "terms": T4()})
pkg("P5-log-order-not-clock", "committed_at (3000) is numerically LATER than the claim's accepted_at (2000), but the attested ordering log places the dispute commitment first. Clock values are evidence only (C16), so the log decides -> RESULT.",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], dispute_state=dict(DS, committed_at=3000),
    expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})

# ---- F1-F6 + F1b/F6b (spec/acquisition.md section 12 on formulary-systems/spec#5)
pkg("F1-authentic-double-terminal", "Same claimed attempt, two authentic conflicting terminals -> no silent choice; UNRESOLVED (C19).",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL), (0, "RESULT", "FAIL", FULL)], expect=UNRES("EQUIVOCATION", unique_terminal_execution="false"))
wrong = dict(REQUEST, sampling_parameters={"temperature": 0.7, "top_p": 1, "seed": 7})
pkg("F1b-authentic-double-claim", "Same authorized attempt_id, two distinct authentic provider claims (different request_hash). Neither may be ordered into authority (C18 claim uniqueness) -> UNRESOLVED.",
    m1, d1, [claim(r1, 0), claim(r1, 0, req=wrong, at=2001)], [(0, "RESULT", "PASS", FULL)],
    expect=UNRES("EQUIVOCATION", authorized_execution="false"))
pkg("F2-suppressed-unfavorable-result", "Attempt 0 claimed; executor asserts a local timeout (no provider NO_RESULT) and retries -> retry refused (C20); UNRESOLVED.",
    m2, d2, [claim(r2, 0), claim(r2, 1, at=2100)], [(1, "RESULT", "PASS", FULL)],
    assertions=[{"attempt_id": H({"run_id": r2, "attempt_index": 0}), "assertion": "local_timeout"}],
    expect=UNRES("CLAIMED", authorized_execution="false"))
pkg("F3-right-slot-wrong-request", "Authentic terminal for the authorized run_id, but request_hash covers temperature 0.7 vs committed 0 (C17).",
    m1, d1, [claim(r1, 0, req=wrong)], [(0, "RESULT", "PASS", FULL)], expect=UNRES("TERMINAL_RESULT", exact_request_binding="false"))
pkg("F4-authentic-insufficient-scope", "Unique authentic result whose observed_scope lacks evidence:full -> required_scope not a subset; ineligible (C21).",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", ("criteria:R1",))], expect=UNRES("TERMINAL_RESULT", sufficient_scope="false"))
pkg("F5-submission-without-admission", "Valid requester submission_commitment, no provider claim -> evidence preserved, not CLAIMED (section 4, C18).",
    m1, d1, subs=[commitment(REQUEST)], expect=UNRES("AUTHORIZED", authorized_execution="false"))
dfresh, rfresh = slot(m1, nonce="dispute-nonce-REGENERATED")
pkg("F6-namespace-regeneration", "Executor mints a fresh dispute_id after seeing a result; it is not the one derived from committed dispute state (C16).",
    m1, dfresh, [claim(rfresh, 0)], [(0, "RESULT", "PASS", FULL)], expect=UNRES("TERMINAL_RESULT", authorized_execution="false"))
pkg("F6b-unauthoritative-predecessor-ordering", "Derivation is consistent and committed_at (1000) numerically precedes accepted_at (2000), but there is no ordering proof. A timestamp comparison alone cannot establish precedence (C16) -> cannot_establish, UNRESOLVED.",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], log=False,
    expect=UNRES("TERMINAL_RESULT", authorized_execution="cannot_establish"))
pkg("F6c-log-orders-dispute-after-claim", "The clocks say the dispute came first (committed_at 1000 < accepted_at 2000), but the attested ordering log places the dispute commitment AFTER the claim -> false (C16).",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], dispute_pos=1,
    expect=UNRES("TERMINAL_RESULT", authorized_execution="false"))
# ---- section 7 retry predicate (formulary-systems/spec#5 final, 2026-10-06)
pkg("F7-retry-after-attested-unresolved", "Attempt 0 has a provider-attested TERMINAL_UNRESOLVED; attempt 1 is then claimed and returns RESULT. UNRESOLVED consumes the run and MUST NOT authorize another attempt (section 7, C20) -> UNRESOLVED.",
    m2, d2, [claim(r2, 0), claim(r2, 1, at=2100)], [(0, "UNRESOLVED", None, FULL), (1, "RESULT", "PASS", FULL)],
    expect=UNRES("TERMINAL_UNRESOLVED", authorized_execution="false"))
m2n = manifest(2, allowed_after=()); d2n, r2n = slot(m2n)
pkg("F8-retry-predicate-not-committed", "max_attempts is 2 but the manifest commits no retry predicate (allowed_after empty). Attempt 0 is attested NO_RESULT; the retry is not authorized because nothing committed NO_RESULT as a retry condition before execution (section 7, C20) -> UNRESOLVED.",
    m2n, d2n, [claim(r2n, 0), claim(r2n, 1, at=2100)], [(0, "NO_RESULT", None, FULL), (1, "RESULT", "PASS", FULL)],
    expect=UNRES("ATTESTED_NO_RESULT", authorized_execution="false"))
m2u = manifest(2, allowed_after=("ATTESTED_NO_RESULT", "TERMINAL_UNRESOLVED")); d2u, r2u = slot(m2u)
pkg("F9-manifest-commits-retry-after-unresolved", "The manifest's retry_policy lists TERMINAL_UNRESOLVED as a retry condition. That contradicts section 7 (UNRESOLVED consumes the run), so the manifest is refused at formation even though this run's single attempt returned RESULT (C20).",
    m2u, d2u, [claim(r2u, 0)], [(0, "RESULT", "PASS", FULL)],
    expect=UNRES("FORMATION_REFUSED", authorized_execution="false"))
pkg("N1-claim-signed-by-requester", "A 'claim' attested by the requester key is submission evidence, not admission (C18).",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], claim_signer="requester", expect=UNRES("AUTHORIZED", authorized_execution="false"))
pkg("N2-checkpoint-not-by-anchor", "The ordering log is well formed but its checkpoint is attested by the provider, not the manifest-pinned ordering anchor -> the order is the executor side's own assertion (C16) -> cannot_establish.",
    m1, d1, [claim(r1, 0)], [(0, "RESULT", "PASS", FULL)], anchor="provider",
    expect=UNRES("TERMINAL_RESULT", authorized_execution="cannot_establish"))
print("built", len([f for f in os.listdir(OUT) if f.endswith('.json') and not f.startswith('R-')]), "synthetic vectors")
