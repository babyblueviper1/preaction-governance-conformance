#!/usr/bin/env python3
"""Builds the v0.0.3 fixtures into vectors/ (deterministic keys; BIP-340 signing needs `coincurve` at BUILD time only --
check.py verifies with the stdlib BIP-340 in this repo). Real-object vectors are copied from live artifacts, not built."""
import hashlib, json, os, sys
import coincurve

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check import H, canon  # noqa: E402

OUT = os.path.join(HERE, "vectors"); os.makedirs(OUT, exist_ok=True)
KEYS = {n: coincurve.PrivateKey(hashlib.sha256(f"pm003-fixture-key:{n}".encode()).digest()) for n in ("provider", "requester")}
PUB = {n: k.public_key_xonly.format().hex() for n, k in KEYS.items()}


def sign(rec, who):
    body = {k: v for k, v in rec.items() if k != "attestation"}
    aux = hashlib.sha256(canon(body)).digest()                       # deterministic aux -> byte-stable vectors
    rec["attestation"] = KEYS[who].sign_schnorr(hashlib.sha256(canon(body)).digest(), aux).hex()
    return rec


REQUEST = {"evidence_root": "sha256:" + "5a" * 32, "prompt_or_material_digest": "sha256:" + "c3" * 32,
           "judge_execution_profile": "pm003-judge-v1", "model_version_or_weights_pin": "judge-weights-2026-09",
           "sampling_parameters": {"temperature": 0, "top_p": 1, "seed": 7}}


def manifest(max_attempts=1):
    return {"spec": "procedure-manifest", "version": "0.0.3", "contract_id": "contract-pm003-fixture",
            "acquisition": {"dispute_id_rule": "H(manifest_hash, contract_id, dispute_nonce)",
                            "run_id_rule": "manifest+dispute+requirement+judge+run_index",
                            "provenance_profile": "pm003-bip340-v0", "provider_pubkey": PUB["provider"],
                            "claim_semantics": "provider-attested single-use claim per enumerated attempt_id",
                            "terminal_semantics": "provider-attested terminal bound to claim_receipt_hash",
                            "retry_policy": {"allowed_after": ["NO_RESULT"], "max_attempts": max_attempts}},
            "requirements": [{"requirement_id": "R1", "judge_id": "J1", "request": REQUEST,
                              "required_scope": ["criteria:R1", "evidence:full"], "scope_predicate": "covers_all"}]}


def slot(m, nonce="dispute-nonce-1"):
    mh = H(m)
    did = H({"manifest_hash": mh, "contract_id": m["contract_id"], "dispute_nonce": nonce})
    run_id = H({"manifest_hash": mh, "dispute_id": did, "requirement_id": "R1", "judge_id": "J1", "run_index": 0})
    return did, run_id


def claim(run_id, k, req=REQUEST, at=2000, who="provider"):
    return sign({"run_id": run_id, "attempt_id": H({"run_id": run_id, "attempt_index": k}), "request_hash": H(req),
                 "accepted_at": at, "provenance_profile": "pm003-bip340-v0"}, who)


def terminal(c, status, out=None, scope=("criteria:R1", "evidence:full")):
    t = {"claim_receipt_hash": H(c), "terminal_status": status, "observation_scope": list(scope)}
    if out:
        t["output_hash"] = H({"verdict": out})
    return sign(t, "provider")


def pkg(name, desc, m, did, claims=(), terminals=(), subs=(), expect=None, dispute_state=None, assertions=()):
    p = {"name": name, "description": desc, "manifest": m, "dispute_id": did,
         "dispute_state": dispute_state or {"contract_id": m["contract_id"], "dispute_nonce": "dispute-nonce-1", "committed_at": 1000},
         "submission_commitments": list(subs), "claims": list(claims), "terminals": list(terminals),
         "executor_assertions": list(assertions), "expect": expect}
    json.dump(p, open(os.path.join(OUT, name + ".json"), "w"), indent=1, sort_keys=True)


def commitment(req, attempt="pm003-att-0001"):
    c = {"type": "submission_commitment", "version": "v0", "request_digest": H(req), "attempt_id": attempt,
         "sent_at": 1500, "requester_pubkey": PUB["requester"]}
    body = dict(c)
    c["sig"] = KEYS["requester"].sign_schnorr(hashlib.sha256(canon(body)).digest(), hashlib.sha256(canon(body)).digest()).hex()
    return c


T4 = lambda **kv: {"authorized_execution": "true", "exact_request_binding": "true", "unique_terminal_execution": "true",
                   "sufficient_scope": "true", **kv}
m1, m2 = manifest(1), manifest(2)
d1, r1 = slot(m1); d2, r2 = slot(m2)

# ---- positive controls (the checker must not just reject everything)
c = claim(r1, 0); pkg("P1-valid-result", "Authorized slot, exact request, one attested terminal, scope covers -> RESULT.",
                      m1, d1, [c], [terminal(c, "RESULT", "PASS")], expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})
c0, c1 = claim(r2, 0), claim(r2, 1, at=2100)
pkg("P2-retry-after-attested-no-result", "Attempt 0 is provider-attested NO_RESULT, so attempt 1 is authorized (section 5, C20).",
    m2, d2, [c0, c1], [terminal(c0, "NO_RESULT"), terminal(c1, "RESULT", "PASS")],
    expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})
c = claim(r1, 0); t = terminal(c, "RESULT", "PASS")
pkg("P3-identical-duplicate-terminals", "The same terminal record delivered twice is not equivocation (C19 concerns CONFLICTING terminals).",
    m1, d1, [c], [t, dict(t)], expect={"run_verdict": "RESULT", "eligible": True, "state": "TERMINAL_RESULT", "terms": T4()})
c = claim(r1, 0)
pkg("P4-terminal-unresolved", "An explicit TERMINAL_UNRESOLVED consumes the run and carries no result (section 4).",
    m1, d1, [c], [terminal(c, "UNRESOLVED")], expect={"run_verdict": "UNRESOLVED", "eligible": True, "state": "TERMINAL_UNRESOLVED", "terms": T4()})

# ---- F1-F6 (section 10)
c = claim(r1, 0)
pkg("F1-authentic-double-terminal", "Same claimed attempt, two authentic conflicting terminals -> no silent choice; UNRESOLVED (C19).",
    m1, d1, [c], [terminal(c, "RESULT", "PASS"), terminal(c, "RESULT", "FAIL")],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "EQUIVOCATION", "terms": {"unique_terminal_execution": "false"}})
c0, c1 = claim(r2, 0), claim(r2, 1, at=2100)
pkg("F2-suppressed-unfavorable-result", "Attempt 0 claimed; executor asserts a local timeout (no provider NO_RESULT) and retries -> retry refused (C20); UNRESOLVED.",
    m2, d2, [c0, c1], [terminal(c1, "RESULT", "PASS")], assertions=[{"attempt_id": c0["attempt_id"], "assertion": "local_timeout"}],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "CLAIMED", "terms": {"authorized_execution": "false"}})
wrong = dict(REQUEST, sampling_parameters={"temperature": 0.7, "top_p": 1, "seed": 7})
c = claim(r1, 0, req=wrong)
pkg("F3-right-slot-wrong-request", "Authentic terminal for the authorized run_id, but request_hash covers temperature 0.7 vs committed 0 (C17).",
    m1, d1, [c], [terminal(c, "RESULT", "PASS")],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "TERMINAL_RESULT", "terms": {"exact_request_binding": "false"}})
c = claim(r1, 0)
pkg("F4-authentic-insufficient-scope", "Unique authentic result whose scope lacks evidence:full -> ineligible (C21).",
    m1, d1, [c], [terminal(c, "RESULT", "PASS", scope=("criteria:R1",))],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "TERMINAL_RESULT", "terms": {"sufficient_scope": "false"}})
pkg("F5-submission-without-admission", "Valid requester submission_commitment, no provider claim -> evidence preserved, not CLAIMED (section 2, C18).",
    m1, d1, subs=[commitment(REQUEST)], expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "AUTHORIZED",
                                                  "terms": {"authorized_execution": "false"}})
dfresh, rfresh = slot(m1, nonce="dispute-nonce-REGENERATED")
c = claim(rfresh, 0)
pkg("F6-namespace-regeneration", "Executor mints a fresh dispute_id after seeing a result; it is not the one derived from committed dispute state (C16).",
    m1, dfresh, [c], [terminal(c, "RESULT", "PASS")],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "TERMINAL_RESULT", "terms": {"authorized_execution": "false"}})
c = claim(r1, 0, at=900)
pkg("F6b-dispute-committed-after-claim", "dispute_id derivation is right but its commitment postdates the claim (C16: committed BEFORE results exist).",
    m1, d1, [c], [terminal(c, "RESULT", "PASS")],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "TERMINAL_RESULT", "terms": {"authorized_execution": "false"}})
c = claim(r1, 0, who="requester")
pkg("N1-claim-signed-by-requester", "A 'claim' attested by the requester key is submission evidence, not admission (C18).",
    m1, d1, [c], [terminal(c, "RESULT", "PASS")],
    expect={"run_verdict": "UNRESOLVED", "eligible": False, "state": "AUTHORIZED", "terms": {"authorized_execution": "false"}})
print("built", len([f for f in os.listdir(OUT) if f.endswith('.json')]), "vectors")
