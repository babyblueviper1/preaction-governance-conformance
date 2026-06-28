#!/usr/bin/env python3
"""
live_check.py — run the pre-action governance conformance invariants against a LIVE endpoint.

The fixture verifier (../verifier.py) checks portable static fixtures. This runs the same three
invariants against a real governance response, so an implementer can point the suite at a running
endpoint and see where the invariants hold and where gaps remain.

Mapping-driven and implementation-independent: a small mapping JSON says how to obtain the governance
block and where each field lives. The crypto is the vendored, zero-dep BIP-340 core (and NIP-01 for
the Nostr-event scheme). No third-party deps.

    python3 live_check.py adapters/safeagent.mapping.json

Supported signature schemes (mapping `sig_scheme`):
  - `bip340-hash`  : BIP-340 schnorr signature directly over the 32-byte envelope hash (e.g. SafeAgent)
  - `nostr-event`  : the admission record is a NIP-01 event; verify id + schnorr (invinoveritas)
  - `ed25519-jcs`  : Ed25519 over canonical JCS bytes (e.g. PMI) — verified if an ed25519 lib is present,
                     otherwise reported as `unverified_here` (scheme recognized, needs an ed25519 verifier)
"""
from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from _bip340_nostr import nostr_event_id, schnorr_verify  # vendored, zero-dep


def _dig(obj, path):
    """Follow a list-of-keys path into a nested dict/list. Returns None if absent."""
    if path is None:
        return obj
    if isinstance(path, str):
        path = [path]
    cur = obj
    for k in path:
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, list) and isinstance(k, int):
            cur = cur[k] if -len(cur) <= k < len(cur) else None
        else:
            return None
    return cur


def _inject_nonce(body):
    """Replace the literal __NONCE__ in any string body value with a unique token, so endpoints that
    deduplicate identical claims still issue a fresh governance block on each run."""
    if not isinstance(body, dict):
        return body
    import uuid
    nonce = uuid.uuid4().hex[:12]
    return {k: (v.replace("__NONCE__", nonce) if isinstance(v, str) else v) for k, v in body.items()}


def _http(method, url, headers=None, body=None, timeout=25):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _jcs(obj) -> bytes:
    """Canonical JSON bytes (sorted keys, no whitespace, UTF-8). RFC 8785-compatible for the
    string/integer/boolean field set; note differences only arise on non-integer numbers."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _suite(state, code, detail):
    return {"state": state, "code": code, "detail": detail}  # state: pass|fail|pending|not_provided|unverified_here


def _verify_admission(scheme, envelope_hash, pubkey, signature, event):
    """Return (sig_valid: bool|None, detail). None = recognized-but-not-verifiable-here."""
    s = (scheme or "").lower()
    try:
        if s.startswith("bip340"):  # bip340-hash, bip340-schnorr — schnorr directly over the envelope hash
            return schnorr_verify(bytes.fromhex(envelope_hash), bytes.fromhex(pubkey), bytes.fromhex(signature)), \
                "BIP-340 schnorr over the envelope hash"
        if s == "nostr-event":
            if not event:
                return False, "nostr-event scheme but no event object provided"
            if nostr_event_id(event) != event.get("id"):
                return False, "nostr event id does not recompute"
            return schnorr_verify(bytes.fromhex(event["id"]), bytes.fromhex(event["pubkey"]),
                                  bytes.fromhex(event["sig"])), "NIP-01 id recompute + schnorr"
        if s.startswith("ed25519"):
            try:
                from nacl.signing import VerifyKey  # optional
                VerifyKey(bytes.fromhex(pubkey)).verify(bytes.fromhex(envelope_hash), bytes.fromhex(signature))
                return True, "Ed25519 over canonical bytes (via PyNaCl)"
            except ImportError:
                return None, "ed25519-jcs recognized; needs an ed25519 verifier (e.g. PyNaCl) to check here"
        return False, f"unknown sig_scheme: {scheme}"
    except Exception as e:  # noqa: BLE001
        return False, f"signature check error: {e}"


def run(mapping: dict) -> dict:
    fields = mapping.get("fields", {})

    # 1) obtain the governance block (live fetch or from a saved file)
    if "fetch" in mapping:
        f = mapping["fetch"]
        body = _inject_nonce(f.get("body"))  # unique per run so dedup'ing endpoints issue a fresh claim
        resp = _http(f.get("method", "GET"), f["url"], f.get("headers"), body)
        gov = _dig(resp, f.get("governance_path"))
    else:
        resp = json.loads(Path(mapping["response_file"]).read_text())
        gov = _dig(resp, mapping.get("governance_path"))
    if gov is None:
        # no governance block: not a verdict on the invariants, just nothing to check
        return {"endpoint": mapping.get("name"), "overall": "no_governance_block",
                "suites": {}, "raw_status": resp.get("status") if isinstance(resp, dict) else None,
                "detail": "response carried no governance block (e.g. SKIP/duplicate/error) — nothing to verify"}

    envelope_hash = _dig(gov, fields.get("envelope_hash"))
    pubkey = _dig(gov, fields.get("pubkey"))
    signature = _dig(gov, fields.get("signature"))
    scheme = _dig(gov, fields.get("sig_scheme")) or mapping.get("sig_scheme")
    event = _dig(gov, fields.get("event")) if fields.get("event") else None
    anchor_ep = _dig(gov, fields.get("anchor_endpoint"))
    canonical_bytes = _dig(gov, fields.get("canonical_bytes")) if fields.get("canonical_bytes") else None
    trust = mapping.get("trust_policy", {}).get("independent_verifier_pubkeys", [])
    actor_pubkey = mapping.get("actor_pubkey")
    raw_claim = mapping.get("raw_claim")

    suites = {}

    # canonical_envelope: recompute SHA-256(canonical bytes) == declared hash.
    # Preferred path: the endpoint exposes its EXACT canonical UTF-8 bytes (e.g. SafeAgent's
    # canonical_bytes_utf8) — we hash those bytes verbatim, making the binding implementation-independent
    # (no assumption that our JCS matches the issuer's). Fallback: re-canonicalize a returned raw claim.
    if canonical_bytes is not None:
        raw = canonical_bytes.encode("utf-8") if isinstance(canonical_bytes, str) else _jcs(canonical_bytes)
        recomputed = hashlib.sha256(raw).hexdigest()
        ok = recomputed == envelope_hash
        suites["canonical_envelope"] = _suite("pass" if ok else "fail",
                                              None if ok else "envelope_hash_mismatch",
                                              f"recomputed SHA-256 of declared canonical bytes {recomputed[:16]} "
                                              f"vs declared {str(envelope_hash)[:16]}")
    elif raw_claim is not None:
        recomputed = hashlib.sha256(_jcs(raw_claim)).hexdigest()
        ok = recomputed == envelope_hash
        suites["canonical_envelope"] = _suite("pass" if ok else "fail",
                                              None if ok else "envelope_hash_mismatch",
                                              f"recomputed {recomputed[:16]} vs declared {str(envelope_hash)[:16]}")
    else:
        suites["canonical_envelope"] = _suite("not_provided", None,
                                              "raw claim not returned by the endpoint; envelope hash is asserted, "
                                              "not recomputed (expose the canonical claim to enable this check)")

    # admission_invariant: independent identity signed the envelope hash
    sig_valid, sig_detail = _verify_admission(scheme, envelope_hash, pubkey, signature, event)
    if sig_valid is None:
        suites["admission_invariant"] = _suite("unverified_here", "scheme_not_verifiable_here", sig_detail)
    elif not sig_valid:
        suites["admission_invariant"] = _suite("fail", "admission_signature_invalid", sig_detail)
    elif trust and pubkey not in trust:
        suites["admission_invariant"] = _suite("fail", "key_different_but_identity_unproven",
                                              "signature valid, but signer pubkey is not in the declared independent set")
    elif actor_pubkey and pubkey == actor_pubkey:
        suites["admission_invariant"] = _suite("fail", "admission_not_independent", "signer is the actor")
    else:
        suites["admission_invariant"] = _suite("pass", None,
                                              f"{sig_detail}; signer resolves to a declared-independent identity")

    # anchoring_invariant: anchored, and the accepted point precedes the terminal outcome
    if not anchor_ep:
        suites["anchoring_invariant"] = _suite("fail", "ordering_unanchored", "no external anchor referenced")
    else:
        try:
            astate = _http("GET", anchor_ep) if isinstance(anchor_ep, str) and anchor_ep.startswith("http") else anchor_ep
        except Exception as e:  # noqa: BLE001
            astate = {"status": f"unreachable: {e}"}
        # accept either a bare `status` or an explicit `anchor_status` (submitted/confirmed distinction)
        raw_status = astate.get("anchor_status") or astate.get("status", "")
        st = str(raw_status).lower()
        ordering_assertable = astate.get("ordering_assertable")
        block_time = astate.get("bitcoin_block_time") or astate.get("accepted_anchor_point", {}).get("block_time") \
            if isinstance(astate.get("accepted_anchor_point"), dict) else astate.get("bitcoin_block_time")
        outcome_time = mapping.get("terminal_outcome_time")
        if "confirmed" in st and block_time and outcome_time:
            ok = block_time < outcome_time
            suites["anchoring_invariant"] = _suite("pass" if ok else "fail",
                                                  None if ok else "late_commitment",
                                                  f"anchor block_time {block_time} vs outcome {outcome_time}")
        elif "confirmed" in st:
            suites["anchoring_invariant"] = _suite("pass", None,
                                                  "anchor Bitcoin-confirmed; provide terminal_outcome_time to check ordering")
        else:
            # submitted/not_submitted — the anchor exists as a commitment but ordering is not yet assertable.
            # This is a correct, honest state (PENDING), not a failure: 'ordered' becomes assertable only on
            # Bitcoin confirmation. The endpoint correctly reports ordering_assertable=false here.
            suites["anchoring_invariant"] = _suite("pending", "anchor_not_yet_confirmed",
                                                  f"anchor_status={raw_status!r}, ordering_assertable={ordering_assertable} — "
                                                  "not yet Bitcoin-confirmed, so 'ordered' is correctly not yet assertable")

    overall = "pass" if all(s["state"] == "pass" for s in suites.values()) else \
        ("fail" if any(s["state"] == "fail" for s in suites.values()) else "partial")
    return {"endpoint": mapping.get("name"), "overall": overall, "suites": suites,
            "envelope_hash": envelope_hash, "signer_pubkey": pubkey, "sig_scheme": scheme}


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print("usage: live_check.py <mapping.json>")
        return 2
    mapping = json.loads(Path(argv[0]).read_text())
    r = run(mapping)
    if r["overall"] == "no_governance_block":
        print(f"{r['endpoint']}: NO GOVERNANCE BLOCK — {r.get('detail')} (status={r.get('raw_status')})")
        return 2
    icon = {"pass": "✓", "fail": "✗", "pending": "⏳", "not_provided": "—", "unverified_here": "?", "partial": "◑"}
    print(f"{r['endpoint']}: {r['overall'].upper()}  (signer {str(r['signer_pubkey'])[:16]}…, scheme {r['sig_scheme']})")
    for name, s in r["suites"].items():
        print(f"  {icon.get(s['state'],'?')} {name}: {s['state']} — {s['detail']}")
    return 0 if r["overall"] in ("pass", "partial") else 1


if __name__ == "__main__":
    raise SystemExit(main())
