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
    hdrs = dict(headers or {})
    # default User-Agent: some hosts UA-filter and 403 a bare urllib client (e.g. PMI/sixu-ai)
    hdrs.setdefault("User-Agent", "preaction-governance-conformance/referee")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        # Governance endpoints commonly embed the SIGNED governance block in a non-2xx body (e.g. PMI
        # serves it with HTTP 400 "agent_did is required"). Parse the error body so the invariants can
        # still be checked; re-raise only if there's no JSON body to read.
        raw = e.read().decode() if e.fp else ""
        try:
            return json.loads(raw)
        except Exception:
            raise e from None


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
            except ImportError:
                return None, "ed25519-jcs recognized; needs an ed25519 verifier (e.g. PyNaCl) to check here"
            vk = VerifyKey(bytes.fromhex(pubkey))
            sig_b = bytes.fromhex(signature)
            # Implementations differ on what message the hash-signature covers: the RAW 32 bytes of the
            # envelope hash, or the 64-char HEX STRING of it (e.g. PMI/moyan signs the hex string). Both
            # are a deterministic commitment to the same hash, so accept either and report which matched —
            # the adapter accommodates the convention so implementers need no local patch.
            for enc_label, msg in (("raw hash bytes", bytes.fromhex(envelope_hash)),
                                   ("hex-string of the hash", envelope_hash.encode("utf-8"))):
                try:
                    vk.verify(msg, sig_b)
                    return True, f"Ed25519 over the {enc_label} (via PyNaCl)"
                except Exception:  # noqa: BLE001 — try the next encoding
                    continue
            return False, "Ed25519 signature did not verify over the raw hash bytes or its hex string"
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
    scheme = (_dig(gov, fields["sig_scheme"]) if fields.get("sig_scheme") else None) or mapping.get("sig_scheme")
    event = _dig(gov, fields.get("event")) if fields.get("event") else None
    anchor_ep = _dig(gov, fields.get("anchor_endpoint"))
    canonical_bytes = _dig(gov, fields.get("canonical_bytes")) if fields.get("canonical_bytes") else None
    trust = mapping.get("trust_policy", {}).get("independent_verifier_pubkeys", [])
    actor_pubkey = mapping.get("actor_pubkey")
    raw_claim = mapping.get("raw_claim")
    # Some endpoints commit to the whole response MINUS the signature/governance block (e.g. PMI/moyan:
    # envelope_hash = sha256(JCS(response excluding `governance`)) — excluding it avoids self-reference).
    exclude = mapping.get("envelope_excludes")

    suites = {}

    # canonical_envelope: recompute SHA-256(canonical bytes) == declared hash.
    # Preferred path: the endpoint exposes its EXACT canonical UTF-8 bytes (e.g. SafeAgent's
    # canonical_bytes_utf8) — we hash those bytes verbatim, making the binding implementation-independent
    # (no assumption that our JCS matches the issuer's). Fallback: re-canonicalize a returned raw claim.
    if exclude is not None and isinstance(resp, dict):
        # commitment over the response with the named keys removed, JCS-canonicalized
        reduced = {k: v for k, v in resp.items() if k not in exclude}
        recomputed = hashlib.sha256(_jcs(reduced)).hexdigest()
        ok = recomputed == envelope_hash
        suites["canonical_envelope"] = _suite("pass" if ok else "fail",
                                              None if ok else "envelope_hash_mismatch",
                                              f"SHA-256(JCS(response excluding {exclude})) {recomputed[:16]} "
                                              f"vs declared {str(envelope_hash)[:16]}")
    elif canonical_bytes is not None:
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
    elif (scheme or "").lower() == "nostr-event" and event:
        # In the Nostr-event scheme the canonical envelope IS the signed event, and its commitment hash
        # is the event id = SHA-256 over the canonical NIP-01 serialization [0,pubkey,created_at,kind,
        # tags,content]. Recompute it from the published fields: if it matches the declared id (== the
        # envelope_hash for this scheme), the canonical bytes faithfully bind the hash — no separate
        # canonical_bytes field needed, the event content IS the canonical payload.
        recomputed = nostr_event_id(event)
        declared = event.get("id")
        ok = recomputed == declared
        suites["canonical_envelope"] = _suite("pass" if ok else "fail",
                                              None if ok else "envelope_hash_mismatch",
                                              f"Nostr event id recomputes from canonical [0,pubkey,created_at,kind,"
                                              f"tags,content]: {str(recomputed)[:16]} vs declared {str(declared)[:16]}")
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
        # resolve a relative anchor path (e.g. PMI returns "/api/arbiter/anchor") against the fetch origin
        if isinstance(anchor_ep, str) and anchor_ep.startswith("/") and "fetch" in mapping:
            from urllib.parse import urlsplit
            sp = urlsplit(mapping["fetch"]["url"])
            anchor_ep = f"{sp.scheme}://{sp.netloc}{anchor_ep}"
        try:
            astate = _http("GET", anchor_ep) if isinstance(anchor_ep, str) and anchor_ep.startswith("http") else anchor_ep
        except Exception as e:  # noqa: BLE001
            astate = {"status": f"unreachable: {e}"}
        if not isinstance(astate, dict):
            astate = {"status": str(astate)}
        # Some endpoints nest the Bitcoin anchor (e.g. invinoveritas /ledger commitment proofs carry it
        # under commitment_proof.ots_anchor). Descend to the OTS/anchor sub-block if present so the same
        # invariant logic applies to flat (SafeAgent) and nested (invinoveritas) shapes alike.
        if "commitment_proof" in astate and isinstance(astate["commitment_proof"], dict):
            astate = astate["commitment_proof"]
        # descend into the anchor sub-block, mechanism-agnostic: ots_anchor (Bitcoin), or the convergent
        # `anchor` / `timestamp_anchor` sibling (on-chain L2 / CT-log / OTS all use the same shape).
        for _sub in ("ots_anchor", "timestamp_anchor", "anchor"):
            if isinstance(astate.get(_sub), dict):
                astate = astate[_sub]
                break
        # accept either a bare `status` or an explicit `anchor_status` (submitted/confirmed distinction)
        raw_status = astate.get("anchor_status") or astate.get("status", "")
        st = str(raw_status).lower()
        ordering_assertable = astate.get("ordering_assertable")
        method = astate.get("method") or astate.get("mechanism") or ""
        tier = astate.get("tier")
        # precedence: an anchor can be CONFIRMED (the commitment provably existed by some block) yet NOT
        # prove it was made BEFORE the outcome — e.g. an integrity backfill stamped after the fact.
        # `precedence=True` means a forward commitment (made before the outcome was known) — the property
        # anchoring_invariant actually asserts. Mechanism-agnostic: Bitcoin OTS, on-chain L2 block time,
        # or a CT-style log all carry the same flag. (None = endpoint doesn't distinguish; confirm-only.)
        precedence = astate.get("precedence")
        # block time of the external anchor, under any standard field name (Bitcoin or on-chain L2)
        _ap = astate.get("accepted_anchor_point") if isinstance(astate.get("accepted_anchor_point"), dict) else {}
        block_time = (astate.get("bitcoin_block_time") or astate.get("block_time")
                      or astate.get("block_timestamp") or astate.get("timestamp") or _ap.get("block_time"))
        _tag = (f" [method={method}]" if method else "") + (f" [tier={tier}]" if tier else "")
        outcome_time = mapping.get("terminal_outcome_time")
        if "confirmed" in st and precedence is False:
            # Confirmed for INTEGRITY, but the stamp does not establish pre-outcome ordering (e.g. a
            # post-hoc backfill). Honest middle state: anchored + confirmed, ordering not asserted.
            suites["anchoring_invariant"] = _suite("pending", "anchored_integrity_only_no_precedence",
                                                  f"externally confirmed (block_time {block_time}){_tag} but precedence=false — "
                                                  "the commitment's existence is proven, but it is not established as "
                                                  "made BEFORE the outcome (no forward stamp yet), so 'ordered' is not asserted")
        elif "confirmed" in st and block_time and outcome_time:
            ok = block_time < outcome_time
            suites["anchoring_invariant"] = _suite("pass" if ok else "fail",
                                                  None if ok else "late_commitment",
                                                  f"anchor block_time {block_time} strictly-< outcome {outcome_time}{_tag}"
                                                  + ("; precedence=true" if precedence else ""))
        elif "confirmed" in st and precedence:
            suites["anchoring_invariant"] = _suite("pass", None,
                                                  f"confirmed forward stamp (precedence=true, block_time {block_time}){_tag} — "
                                                  "committed before the outcome")
        elif "confirmed" in st:
            suites["anchoring_invariant"] = _suite("pass", None,
                                                  f"anchor externally confirmed{_tag}; provide terminal_outcome_time to check ordering")
        else:
            # submitted/not_submitted — the anchor exists as a commitment but ordering is not yet assertable.
            # This is a correct, honest state (PENDING), not a failure: 'ordered' becomes assertable only on
            # Bitcoin confirmation. The endpoint correctly reports ordering_assertable=false here.
            suites["anchoring_invariant"] = _suite("pending", "anchor_not_yet_confirmed",
                                                  f"anchor_status={raw_status!r}, ordering_assertable={ordering_assertable} — "
                                                  "not yet confirmed by an external clock independent of the signer, so "
                                                  "'committed before the outcome' is correctly not yet assertable")

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
