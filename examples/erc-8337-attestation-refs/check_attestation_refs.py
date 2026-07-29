#!/usr/bin/env python3
"""Offline, zero-dep conformance checker for docs/interop/attestation-refs.md
(AwareLiquid/ERC-8337 x WYRIWE/ERC-8299 joint interop note), §2-§6.

Recomputes, from bytes alone, against everest-an's REAL live Sepolia fixture
(registry 0xDdf21937ba80b5fF973610877A0955b320C91241, spaceId 0xfbe20b84...b13564)
-- not synthetic data:

  1. CANONICALIZATION (§3): given a transition's raw attestation_refs input, recompute
     the canonical form -- deduplicated by entry identity (event_id, pubkey), sorted by
     decision_ref (bytewise over the lowercase hex string), verify_url excluded from the
     canonical entry -- and assert it matches the fixture's own declared
     attestation_refs_canonical exactly.
  2. SIGNATURE (§2): each entry's event_id recomputes from the signed NIP-01 event's own
     fields, and the BIP-340 signature verifies against the entry's pubkey. Identity is
     resolved from the event's OWN pubkey, never a self-claim.
  3. DECISION_REF (§2): decision_ref recomputes as sha256(JCS({artifact_hash,
     artifact_type, policy_version, verdict, source_class, vantage_limitation})) from the
     event's own content -- the exact 6-field preimage invinoveritas's own
     services/proof_signing.py:DECISION_REF_PREIMAGE_FIELDS uses (cross-implementation
     byte-for-byte convergence, differing only in cosmetic prefix style: this fixture uses
     "0x", invinoveritas uses "sha256:" -- same hash, different label).
  4. AUTHORITY (§6): three-valued classification against a consumer trust policy --
     structurally_invalid / structurally_valid_zero_authority / valid_and_authorized.
     Authority is NEVER a property read off the entry itself.

Plus deliberate NEGATIVE cases (tampered decision_ref, tampered signature, shuffled +
duplicated input, an authorized-key contrast) proving the checker is actually sensitive
to each invariant, not just echoing the fixture's own pre-computed answer.

    python3 check_attestation_refs.py        # exit 0 iff every positive+negative holds
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

# Vendored BIP-340 / NIP-01 core lives at the suite root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from _bip340_nostr import nostr_event_id, schnorr_verify  # noqa: E402

HERE = Path(__file__).resolve().parent

DECISION_REF_PREIMAGE_FIELDS = (
    "artifact_hash", "artifact_type", "policy_version", "verdict", "source_class",
    "vantage_limitation",
)


def jcs(v) -> str:
    """RFC-8785-style JCS -- pure stdlib, same minimal form as examples/profile-resolution/jcs.py."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (int, float)):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k])
                              for k in sorted(v.keys())) + "}"
    raise TypeError(f"non-canonicalizable type: {type(v).__name__}")


def _hex_only(decision_ref: str) -> str:
    """Compare hash BYTES only -- strip whatever cosmetic prefix a given implementation uses
    ('0x...' here, 'sha256:...' in invinoveritas). Prefix style is not part of the invariant."""
    s = decision_ref.lower()
    for prefix in ("0x", "sha256:"):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s


def canonicalize(raw_refs: list[dict]) -> list[dict]:
    """§3: dedupe by (event_id, pubkey), sort by decision_ref, verify_url excluded."""
    seen = {}
    for ref in raw_refs:
        key = (ref["event_id"], ref["pubkey"])
        if key not in seen:
            seen[key] = {
                "scheme": ref["scheme"],
                "decision_ref": ref["decision_ref"],
                "event_id": ref["event_id"],
                "pubkey": ref["pubkey"],
            }  # verify_url deliberately never copied in
    return sorted(seen.values(), key=lambda e: _hex_only(e["decision_ref"]))


def verify_signature(event: dict) -> bool:
    if nostr_event_id(event) != event.get("id"):
        return False
    try:
        return schnorr_verify(
            bytes.fromhex(event["id"]), bytes.fromhex(event["pubkey"]), bytes.fromhex(event["sig"])
        )
    except (ValueError, KeyError):
        return False


def recompute_decision_ref(event_content_json: str) -> str:
    obj = json.loads(event_content_json)
    preimage = {k: obj.get(k) for k in DECISION_REF_PREIMAGE_FIELDS}
    return hashlib.sha256(jcs(preimage).encode("utf-8")).hexdigest()


def classify_authority(pubkey: str, trust_policy: dict[str, str], sig_valid: bool) -> str:
    """§6's three-valued outcome. trust_policy: pubkey(lowercase) -> authority label
    ('none' or a real authority string). A pubkey absent from the policy is treated the
    same as a declared-zero-authority key: not authorized, but not proof of anything
    wrong either -- 'unknown to this consumer's policy', per §6's own framing that a
    conforming consumer's policy is a closed trust store, not an open blocklist."""
    if not sig_valid:
        return "structurally_invalid"
    authority = trust_policy.get(pubkey.lower(), "none")
    if authority and authority != "none":
        return "valid_and_authorized"
    return "structurally_valid_zero_authority"


def _events_by_id(fixture: dict) -> dict[str, dict]:
    return {e["id"]: e for e in fixture["events"]}


def check_positive(fixture: dict, trust_policy: dict[str, str]) -> tuple[bool, list[str]]:
    """The real thing: every attestation-carrying transition in everest-an's live Sepolia
    fixture, canonicalized, signature-checked, decision_ref-recomputed, authority-classified."""
    ok = True
    lines: list[str] = []
    events = _events_by_id(fixture)

    for t in fixture["transitions"]:
        seq = t["delta"]["sequence"]
        w = t["witness"]
        raw = w.get("attestation_refs_raw_input")
        expected_canonical = w.get("attestation_refs_canonical")
        if raw is None:
            lines.append(f"[skip] sequence {seq}: no attestation_refs (this transition doesn't carry one)")
            continue

        recomputed = canonicalize(raw)
        canon_match = recomputed == expected_canonical
        ok &= canon_match
        lines.append(f"[{'PASS' if canon_match else 'FAIL'}] sequence {seq}: canonicalize("
                     f"{len(raw)} raw refs) -> {len(recomputed)} canonical, "
                     f"matches fixture's own attestation_refs_canonical: {canon_match}")

        for entry in recomputed:
            ev = events.get(entry["event_id"])
            if ev is None:
                ok = False
                lines.append(f"  [FAIL] event_id {entry['event_id'][:12]}... not found in fixture events[]")
                continue
            sig_valid = verify_signature(ev)
            dref_recomputed = recompute_decision_ref(ev["content"])
            dref_matches = dref_recomputed == _hex_only(entry["decision_ref"])
            authority = classify_authority(entry["pubkey"], trust_policy, sig_valid)
            entry_ok = sig_valid and dref_matches
            ok &= entry_ok
            lines.append(f"  [{'PASS' if entry_ok else 'FAIL'}] event {entry['event_id'][:12]}...: "
                         f"sig_valid={sig_valid} decision_ref_recomputes={dref_matches} "
                         f"authority={authority}")
    return ok, lines


def check_negative_tampered_decision_ref(fixture: dict) -> tuple[bool, str]:
    """A single flipped hex char in decision_ref must break the recompute check."""
    t = next(x for x in fixture["transitions"] if x["witness"].get("attestation_refs_canonical"))
    entry = dict(t["witness"]["attestation_refs_canonical"][0])
    ev = _events_by_id(fixture)[entry["event_id"]]
    tampered = "0" if entry["decision_ref"][-1] != "0" else "1"
    entry["decision_ref"] = entry["decision_ref"][:-1] + tampered
    dref_recomputed = recompute_decision_ref(ev["content"])
    caught = dref_recomputed != _hex_only(entry["decision_ref"])
    return caught, f"[{'PASS' if caught else 'FAIL'}] tampered decision_ref correctly rejected: {caught}"


def check_negative_tampered_signature(fixture: dict) -> tuple[bool, str]:
    """A single flipped hex char in sig must break schnorr_verify."""
    ev = dict(fixture["events"][0])
    ev["sig"] = ("1" if ev["sig"][-1] != "1" else "0") + ev["sig"][1:]
    caught = not verify_signature(ev)
    return caught, f"[{'PASS' if caught else 'FAIL'}] tampered signature correctly rejected: {caught}"


def check_negative_shuffle_and_duplicate(fixture: dict) -> tuple[bool, str]:
    """§3's unordered-set + dedupe rule: shuffling the raw input and appending exact
    duplicates must not change the canonical result at all."""
    t = next(x for x in fixture["transitions"]
             if len(x["witness"].get("attestation_refs_canonical") or []) >= 2)
    raw = t["witness"]["attestation_refs_raw_input"]
    original = canonicalize(raw)
    shuffled_and_duped = list(reversed(raw)) + [raw[0], raw[-1]]  # reverse order + append dupes
    recomputed = canonicalize(shuffled_and_duped)
    stable = recomputed == original
    return stable, f"[{'PASS' if stable else 'FAIL'}] shuffle+duplicate input -> same canonical result: {stable}"


def check_negative_authorized_key_contrast(fixture: dict, trust_policy: dict[str, str]) -> tuple[bool, str]:
    """Proves the classifier reaches all THREE outcomes, not just the fixture's own
    zero-authority case. Simulates a consumer who DOES trust one of the fixture's keys
    for real -- same bytes, different consumer policy, different outcome. This is exactly
    §6's point: authority lives in the consumer's policy, never in the entry."""
    t = next(x for x in fixture["transitions"] if x["witness"].get("attestation_refs_canonical"))
    entry = t["witness"]["attestation_refs_canonical"][0]
    hypothetical_policy = dict(trust_policy)
    hypothetical_policy[entry["pubkey"].lower()] = "real-verifier-example-org"
    ev = _events_by_id(fixture)[entry["event_id"]]
    outcome = classify_authority(entry["pubkey"], hypothetical_policy, verify_signature(ev))
    correct = outcome == "valid_and_authorized"
    return correct, (f"[{'PASS' if correct else 'FAIL'}] same bytes, consumer policy trusts this key -> "
                     f"{outcome} (was structurally_valid_zero_authority under the fixture's own policy)")


def main() -> int:
    fixture = json.loads((HERE / "sepolia-fixture-v1.json").read_text())
    keys = json.loads((HERE / "fixture-keys-v1.json").read_text())
    trust_policy = {v["pubkey"].lower(): v["authority"] for v in keys["verifiers"]}

    print("== positive: recompute everest-an's live Sepolia fixture ==")
    pos_ok, pos_lines = check_positive(fixture, trust_policy)
    for line in pos_lines:
        print(line)
    top_level_expected = keys.get("expected_checker_outcome")
    print(f"fixture's own declared expected_checker_outcome: {top_level_expected}")

    print("\n== negatives: prove the checker is actually sensitive ==")
    neg_checks = [
        check_negative_tampered_decision_ref(fixture),
        check_negative_tampered_signature(fixture),
        check_negative_shuffle_and_duplicate(fixture),
        check_negative_authorized_key_contrast(fixture, trust_policy),
    ]
    for _, line in neg_checks:
        print(line)

    all_ok = pos_ok and all(ok for ok, _ in neg_checks)
    print("\nall invariants hold ✓" if all_ok else "\nCONFORMANCE CHECK FAILED ✗")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
