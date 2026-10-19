"""Build vectors.json from the Base Sepolia snapshot (candidates_snapshot.json) and fixed, published test salts.

Test salts are sha256 of a label so anyone can regenerate them. They are NOT valid production salts: a real salt MUST
come from a CSPRNG, per payment.
"""
import hashlib
import json
from pathlib import Path

from commitment import commit

HERE = Path(__file__).parent
snap = json.loads((HERE / "candidates_snapshot.json").read_text())
ASSET, PAYER = snap["asset"], snap["authorizer"]
CANDS = [c["nonce"] for c in snap["candidates"]]
A = "0xc01225fc79db19be6ea2afdbbbc195968e121184e39df0b4f62d7f8f5df40c83"  # tx 0x1345479a..., block 48163177
B = "0xf24709b92dde0d79bcf949b42c4f7c9d9ec259a90ffa19366078fdb0ea01135c"  # tx 0x1a49341e..., block 48163178
assert A in CANDS and B in CANDS


def tsalt(label):
    return "0x" + hashlib.sha256(f"x402-rac-test-salt/{label}".encode()).hexdigest()


SA, SB = tsalt("A"), tsalt("B")
cA, cB = commit("eip3009", ASSET, PAYER, A, SA), commit("eip3009", ASSET, PAYER, B, SB)
base = {"method": "eip3009", "asset": ASSET, "authorizer": PAYER}

V = []
V.append({"id": "commit-A", "kind": "commit", **base, "nonce": A, "salt": SA, "expect": {"commitment": cA},
          "note": "real settlement A (tx 0x1345479a7c52..., Base Sepolia block 48163177)"})
V.append({"id": "commit-B", "kind": "commit", **base, "nonce": B, "salt": SB, "expect": {"commitment": cB},
          "note": "real settlement B, next block, same payer/payee/amount; receipts otherwise differ only in issuedAt"})
V.append({"id": "commit-A-uppercase-hex", "kind": "commit", **base, "nonce": "0x" + A[2:].upper(),
          "salt": SA, "authorizer": "0x87F344B6EC48A936373D774D3DE8649DEEB66EE1", "expect": {"commitment": cA},
          "note": "hex case is not part of the identity"})
V.append({"id": "link-A", "kind": "link", **base, "commitment": cA, "salt": SA, "candidates": "snapshot",
          "expect": {"result": "linked", "nonce": A}, "note": "holder of salt A finds exactly one of the payer's 12 nonces"})
V.append({"id": "link-B", "kind": "link", **base, "commitment": cB, "salt": SB, "candidates": "snapshot",
          "expect": {"result": "linked", "nonce": B}})
V.append({"id": "link-swapped-salt", "kind": "link", **base, "commitment": cA, "salt": SB, "candidates": "snapshot",
          "expect": {"result": "no_match"}, "note": "B's salt does not open A's commitment"})
# The x402 spec's own §5.4 version-2 example (PR text), so the published example is checkable.
V.append({"id": "commit-spec-example", "kind": "commit", "method": "eip3009",
          "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "authorizer": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
          "nonce": "0x" + hashlib.sha256(b"x402-rac-example/nonce").hexdigest(),
          "salt": tsalt("spec-example"),
          "expect": {"commitment": "0x5d905bbf08a97e04ab551d276d8e94b1abaff7d0737324d360e983c2796af23b"},
          "note": "the version-2 receipt example in extension-offer-and-receipt.md §5.4 (Base USDC, example payer, test nonce + salt)"})
# holistis (x402#2887): the seller chooses `authorizer` when committing, but the verifier recomputes with the receipt's
# signed `payer`. A commitment to someone else's authorization therefore opens to nothing -- never to a false link.
OTHER = "0x" + "22" * 20
V.append({"id": "link-commit-other-authorizer", "kind": "link", **base, "commitment": commit("eip3009", ASSET, OTHER, A, SA),
          "salt": SA, "candidates": "snapshot", "expect": {"result": "no_match"},
          "note": "committed with an authorizer other than the receipt payer: unlinkable (same as omitting the field), detectable, never a false link"})
V.append({"id": "link-other-asset", "kind": "link", **base, "asset": "0x" + "11" * 20, "commitment": cA, "salt": SA,
          "candidates": "snapshot", "expect": {"result": "no_match"}, "note": "the asset is bound: same nonce on another token is a different commitment"})

# Attacks: a receipt holder WITHOUT the salt, testing the payer's short candidate list (one indexed log query).
unsalted = "0x" + hashlib.sha256(bytes.fromhex(A[2:])).hexdigest()
V.append({"id": "attack-unsalted", "kind": "attack", "construction": "sha256(nonce)", "published": unsalted,
          "candidates": "snapshot", "expect": {"recovered": A},
          "note": "the 256-bit nonce buys nothing: the attacker tests the payer's 12 nonces, not 2^256"})
weak = "0x" + hashlib.sha256(bytes.fromhex(PAYER[2:])).hexdigest()
V.append({"id": "attack-payer-derived-salt", "kind": "attack", "construction": "commit(..., salt=sha256(payer))",
          "published": commit("eip3009", ASSET, PAYER, A, weak), "salt_rule": "sha256(payer)",
          "candidates": "snapshot", "expect": {"recovered": A},
          "note": "a salt computable from public receipt fields reduces to the unsalted case while looking protected"})
V.append({"id": "attack-csprng-salt", "kind": "attack", "construction": "commit(..., salt=CSPRNG)", "published": cA,
          "salt_rule": None, "candidates": "snapshot", "expect": {"recovered": None},
          "note": "with a 256-bit random salt the same 12-candidate search finds nothing"})

for vid, field, val, cond in [
    ("bad-salt-16-bytes", "salt", "0x" + "ab" * 16, "salt_not_bytes32"),
    ("bad-salt-no-0x", "salt", SA[2:], "salt_not_bytes32"),
    ("bad-nonce-trailing-newline", "nonce", A + "\n", "nonce_not_bytes32"),
    ("bad-nonce-31-bytes", "nonce", A[:-2], "nonce_not_bytes32"),
    ("bad-authorizer-39-hex", "authorizer", PAYER[:-1], "authorizer_not_address"),
    ("bad-asset-number", "asset", 12345, "asset_not_address"),
    ("bad-method-permit2", "method", "permit2", "unsupported_method"),
    ("bad-method-uppercase", "method", "EIP3009", "unsupported_method"),
]:
    v = {"id": vid, "kind": "commit", **base, "nonce": A, "salt": SA}
    v[field] = val
    # an authorizationMethod this checker does not implement is NOT malformed (spec §5.3 / §5.6.4): the link is not attempted
    v["expect"] = {"not_attempted": cond} if cond == "unsupported_method" else {"malformed": cond}
    V.append(v)

out = {"name": "x402-receipt-authorization-commitment/0", "license": "CC0-1.0",
       "candidates_snapshot": "candidates_snapshot.json", "vectors": V}
(HERE / "vectors.json").write_text(json.dumps(out, indent=1) + "\n")
print(f"wrote {len(V)} vectors")
