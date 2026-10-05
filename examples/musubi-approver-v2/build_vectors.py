#!/usr/bin/env python3
"""Builds vectors.json for verify_approval_v2.py. Base contract: musubi-v0/second_contract_AB.json from ogasurfproject-jpg/horizon-shield @8546c8a
(MIT, (c) The HORIZONs Co., Ltd.), copied here as base_second_contract_AB.json; its grant gets a conditional emit_witness and a pinned approver.
Keys from fixed seeds + deterministic Ed25519 -> byte-identical regeneration. Needs `cryptography` (signing only).
If HS_MUSUBI points at a horizon-shield musubi-v0 checkout, contract_sha256 is cross-checked against its contract_v0 module."""
import base64, copy, hashlib, json, os, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import verify_approval_v2 as V

def key(label):
    sk = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    return sk, base64.b64encode(sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

APP_SK, APP_PK = key("musubi-approver-v2/approver")     # the pinned approver (TEST key; the live approver key is published separately)
FORGE_SK, FORGE_PK = key("musubi-approver-v2/forger")    # not pinned
base = json.load(open(os.path.join(HERE, "base_second_contract_AB.json")))
C = copy.deepcopy(base); C.pop("signatures", None)
C["grant"]["conditional"] = [{"action": "emit_witness", "requires": "approver"}]
C["grant"]["approval_policy"] = {"allow_unscoped": False, "approvers": [{"name": "invinoveritas", "public_key_ed25519_b64": APP_PK, "actions": ["emit_witness"]}]}
C_OTHER = copy.deepcopy(C); C_OTHER["grant"]["expiry_height"] = C["grant"]["expiry_height"] + 1     # different terms, same parties
C_NOPIN = copy.deepcopy(C); C_NOPIN["grant"]["approval_policy"] = {"allow_unscoped": False}

def approval(contract, sk, pk, action="emit_witness", approver="invinoveritas", vu=980000, nonce="a" * 32, su=True):
    e = {"action": action, "by": "approver", "approver": approver, "valid_until_height": vu, "nonce": nonce, "single_use": su}
    e["sig_b64"] = base64.b64encode(sk.sign(V.approval_v2_bytes(contract, e, pk))).decode("ascii")
    return e

vec = []
def add(vid, contract, ap, result, reason=None, what=""):
    vec.append({"id": vid, "what": what, "contract": contract, "approval": ap, "expect": {"result": result, "reason": reason}})

good = approval(C, APP_SK, APP_PK)
add("v2-valid-approval", "C", good, "approved", None, "signed by the pinned approver over this contract's sha256 and this action")
add("v2-forged-unpinned-key", "C", approval(C, FORGE_SK, APP_PK), "approval_unverified", "bad_signature",
    "same fields and approver name, signed by a key the contract does not pin")
add("v2-replayed-to-other-contract", "C", approval(C_OTHER, APP_SK, APP_PK), "approval_unverified", "bad_signature",
    "a genuine approval for a contract with different terms (expiry_height+1), presented on this one")
t = copy.deepcopy(good); t["single_use"] = False
add("v2-tampered-after-signing", "C", t, "approval_unverified", "bad_signature", "single_use flipped after the approver signed")
add("v2-action-not-permitted", "C", approval(C, APP_SK, APP_PK, action="payment"), "approval_unverified", "action_not_permitted_for_approver",
    "the pinned approver may approve emit_witness only")
add("v2-approver-not-pinned", "C", approval(C, APP_SK, APP_PK, approver="someone-else"), "approval_unverified", "approver_not_pinned")
add("v2-bare-action-string", "C", {"action": "emit_witness"}, "approval_unverified", "not_an_approver_approval",
    "the v0 shape today's settle counts by action name alone (contract_v0.py L645)")
add("v2-malformed-nonce", "C", dict(good, nonce="xyz"), "approval_unverified", "malformed")
add("v2-no-approver-pinned", "C_NOPIN", None, "approval_self_asserted", None,
    "contract pins no approver: settle keeps today's reading but reports approval_self_asserted instead of passing silently")

out = {"description": "a2a-approval-v2 (third-party approver) vectors for MUSUBI settle v1.10, horizon-shield#29. Pair: v2-valid-approval / v2-forged-unpinned-key. CC0-1.0 (vectors); base contract MIT (c) The HORIZONs Co., Ltd.",
       "contracts": {"C": C, "C_OTHER": C_OTHER, "C_NOPIN": C_NOPIN},
       "contract_sha256": {k: V.contract_sha256(v) for k, v in (("C", C), ("C_OTHER", C_OTHER), ("C_NOPIN", C_NOPIN))},
       "test_keys": {"approver_public_key_ed25519_b64": APP_PK, "forger_public_key_ed25519_b64": FORGE_PK, "seed_rule": "sha256(label), labels in build_vectors.py"},
       "vectors": vec}
hs = os.environ.get("HS_MUSUBI")
if hs:
    sys.path.insert(0, hs); import contract_v0 as hv0
    assert hv0.contract_sha256(C) == out["contract_sha256"]["C"], "contract_sha256 differs from horizon-shield contract_v0"
    print("contract_sha256 cross-checked against horizon-shield contract_v0:", out["contract_sha256"]["C"][:16])
json.dump(out, open(os.path.join(HERE, "vectors.json"), "w"), indent=1, sort_keys=True, ensure_ascii=False); open(os.path.join(HERE, "vectors.json"), "a").write("\n")
print(len(vec), "vectors")
