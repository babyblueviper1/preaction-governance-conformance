#!/usr/bin/env python3
"""Reference verifier for a THIRD-PARTY approval of a MUSUBI conditional action ("a2a-approval-v2"), proposed for settle v1.10
(ogasurfproject-jpg/horizon-shield#29, 2026-10-05). Stdlib + tools/_ed25519.py (verification only).

The contract pins its approvers in grant.approval_policy.approvers[] = {name, public_key_ed25519_b64, actions[]}; both parties sign that, so
neither can swap the approver later. An approval is an entry in an execution record's approvals[]:
    {"action", "by": "approver", "approver": <name>, "valid_until_height", "nonce" (32 hex), "single_use", "sig_b64"}
signed by the pinned approver key over
    b"a2a-approval-v2\\n" + canonical({"contract_sha256", "action", "approver_key", "valid_until_height", "nonce", "single_use"})
canonical() and contract_sha256() follow musubi-v0/contract_v0.py (sorted keys, "," ":" separators, non-ASCII unescaped; contract digest =
sha256(b"a2a-contract-v0\\n" + canonical(contract minus "signatures"))). Binding the whole contract digest (not contract_id) means the
approval cannot be replayed onto a contract with different terms, including a different approver policy.

verify_approval_v2(contract, entry) -> ("approved", None) | ("approval_unverified", reason)
policy_reading(contract) -> "pinned" | "approval_self_asserted" (no approvers pinned: the reading Oga proposed for contracts that pin none)
Time ordering (valid_until_height vs the action's anchor height, single_use) stays with settle's existing v1.1/v1.4 rules and is out of scope here.
"""
import base64, hashlib, json, os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import _ed25519  # noqa: E402

CONTRACT_CONTEXT = b"a2a-contract-v0\n"
APPROVAL_V2_CONTEXT = b"a2a-approval-v2\n"
HEX32 = re.compile(r"^[0-9a-f]{32}\Z")


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def contract_sha256(contract):
    body = {k: v for k, v in contract.items() if k != "signatures"}
    return hashlib.sha256(CONTRACT_CONTEXT + canonical(body).encode("utf-8")).hexdigest()


def b64_raw(s, n):
    if not isinstance(s, str) or not s:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    return raw if len(raw) == n and base64.b64encode(raw).decode("ascii") == s else None


def approval_v2_bytes(contract, e, approver_key_b64):
    return APPROVAL_V2_CONTEXT + canonical({
        "contract_sha256": contract_sha256(contract), "action": e.get("action"), "approver_key": approver_key_b64,
        "valid_until_height": e.get("valid_until_height"), "nonce": e.get("nonce"), "single_use": e.get("single_use")}).encode("utf-8")


def approvers(contract):
    ap = ((contract.get("grant") or {}).get("approval_policy") or {})
    a = ap.get("approvers") if isinstance(ap, dict) else None
    return a if isinstance(a, list) else []


def policy_reading(contract):
    return "pinned" if approvers(contract) else "approval_self_asserted"


def verify_approval_v2(contract, e):
    if not isinstance(e, dict) or e.get("by") != "approver":
        return "approval_unverified", "not_an_approver_approval"
    vu, nonce, su = e.get("valid_until_height"), e.get("nonce"), e.get("single_use")
    if not (isinstance(e.get("action"), str) and isinstance(vu, int) and not isinstance(vu, bool) and vu >= 0
            and isinstance(nonce, str) and HEX32.match(nonce) and isinstance(su, bool)):
        return "approval_unverified", "malformed"
    pin = next((a for a in approvers(contract) if isinstance(a, dict) and a.get("name") == e.get("approver")), None)
    if pin is None:
        return "approval_unverified", "approver_not_pinned"
    if e["action"] not in (pin.get("actions") or []):
        return "approval_unverified", "action_not_permitted_for_approver"
    pk = b64_raw(pin.get("public_key_ed25519_b64"), 32)
    sig = b64_raw(e.get("sig_b64"), 64)
    if pk is None or sig is None:
        return "approval_unverified", "malformed_key_or_signature"
    if not _ed25519.verify(pk, approval_v2_bytes(contract, e, pin["public_key_ed25519_b64"]), sig):
        return "approval_unverified", "bad_signature"
    return "approved", None


if __name__ == "__main__":
    V = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors.json")))
    contracts = V["contracts"]; bad = 0
    for v in V["vectors"]:
        c = contracts[v["contract"]]
        got = verify_approval_v2(c, v["approval"]) if v.get("approval") is not None else (policy_reading(c), None)
        ok = list(got) == [v["expect"]["result"], v["expect"].get("reason")]
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {v['id']:44s} {got[0]:22s} {got[1] or ''}")
    print(f"{len(V['vectors']) - bad}/{len(V['vectors'])} agree")
    sys.exit(1 if bad else 0)
