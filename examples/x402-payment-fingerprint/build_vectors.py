#!/usr/bin/env python3
"""Builds vectors.json for x402-payment-fingerprint/0 (deterministic; synthetic payments, no real keys). Each vector is a payment as ONE party
holds it, plus the expected outcome. Vectors sharing a `payment_id` are the same payment seen by two parties and MUST produce the same
fingerprint; different payment_ids MUST differ. `naive_full_payload_sha256` records what a naive recipe (sha256 of the party's JSON as held)
would give, to show why the recipe normalizes."""
import hashlib, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from fingerprint import fingerprint, RECIPE  # noqa: E402
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
BUYER = "0x857b06519E91e3A54538791bDbb0E22373e36b66"; SELLER = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
NONCE = "0x" + hashlib.sha256(b"x402-fp-fixture-nonce-1").hexdigest()
R = hashlib.sha256(b"r").hexdigest(); S = hashlib.sha256(b"s").hexdigest()
def sig(r, s, v): return "0x" + r + s + format(v, "02x")
S2 = format(N - int(S, 16), "064x")                      # the malleated twin: (r, n-s) also verifies
AUTH = {"from": BUYER, "to": SELLER, "value": "10000", "validAfter": "0", "validBefore": "1790000000", "nonce": NONCE}

def v1(auth, signature, network="base", asset=USDC):
    return {"x402Version": 1, "scheme": "exact", "network": network, "asset": asset,
            "payload": {"signature": signature, "authorization": auth}}
def v2(auth, signature, network="eip155:8453", asset=USDC):
    return {"x402Version": 2, "accepted": {"scheme": "exact", "network": network, "asset": asset},
            "payload": {"signature": signature, "authorization": auth}}
def view(p):
    """The fingerprint input both versions reduce to: network + asset + scheme + authorization."""
    acc = p.get("accepted", p)
    return {"network": acc["network"], "asset": acc["asset"], "scheme": acc["scheme"], "authorization": p["payload"]["authorization"]}

V = []
def add(name, payment_id, held, desc, expect_outcome="ok", condition=None):
    out, val = fingerprint(view(held))
    assert out == expect_outcome and (condition is None or val == condition), (name, out, val)
    V.append({"name": name, "description": desc, "payment_id": payment_id, "held": held,
              "expect": {"outcome": out, ("fingerprint" if out == "ok" else "condition"): val},
              "naive_full_payload_sha256": hashlib.sha256(json.dumps(held, sort_keys=False).encode()).hexdigest()})

buyer = v1(AUTH, sig(R, S, 27))
add("same-1-buyer-v1", "P1", buyer, "The buyer's copy: v1 envelope, network alias 'base', checksummed addresses.")
add("same-1-seller-v2", "P1", v2({k: (v.lower() if k in ("from", "to") else v) for k, v in AUTH.items()}, sig(R, S, 27), asset=USDC.lower()),
    "The seller's copy of the SAME payment: v2 envelope, CAIP-2 network, lowercase addresses. Same fingerprint.")
add("same-1-malleated-signature", "P1", v1(AUTH, sig(R, S2, 28)),
    "The same authorization carried with the malleated signature (r, n-s, v flipped) -- both verify. Same fingerprint; a recipe that hashes the signature splits here.")
add("same-1-reordered-keys", "P1", json.loads(json.dumps(v1(dict(reversed(list(AUTH.items()))), sig(R, S, 27)), sort_keys=True)),
    "The same payment with every object's keys in a different order. Same fingerprint.")
add("diff-2-other-nonce", "P2", v1(dict(AUTH, nonce="0x" + hashlib.sha256(b"x402-fp-fixture-nonce-2").hexdigest()), sig(R, S, 27)),
    "A second payment from the same buyer, same amount, new nonce. Different fingerprint (a repeat purchase is not a duplicate).")
add("diff-3-other-value", "P3", v1(dict(AUTH, value="10001"), sig(R, S, 27)),
    "Same nonce, different value: a record describing a different amount must not join.")
add("diff-4-other-network", "P4", v1(AUTH, sig(R, S, 27), network="base-sepolia"),
    "Same authorization on Base Sepolia: a testnet payment never joins a mainnet record.")
add("bad-value-number", None, v1(dict(AUTH, value=10000), sig(R, S, 27)),
    "value as a JSON number: parsers differ on large integers, so the recipe only accepts the decimal string.", "malformed", "value_not_canonical_decimal_string")
add("bad-value-leading-zero", None, v1(dict(AUTH, value="010000"), sig(R, S, 27)),
    "value '010000': two spellings of one amount would hash differently, so non-canonical decimals are refused.", "malformed", "value_not_canonical_decimal_string")
add("bad-network-unknown-alias", None, v1(AUTH, sig(R, S, 27), network="base-mainnet"),
    "An alias with no CAIP-2 mapping is refused rather than guessed.", "malformed", "network_not_caip2_mappable")
add("bad-nonce-short", None, v1(dict(AUTH, nonce="0x1234"), sig(R, S, 27)),
    "EIP-3009 nonces are bytes32.", "malformed", "nonce_not_bytes32_hex")
add("bad-value-trailing-newline", None, v1(dict(AUTH, value="10000\n"), sig(R, S, 27)),
    "A trailing newline on value must not be silently accepted (it would otherwise hash as a distinct, valid fingerprint).",
    "malformed", "value_not_canonical_decimal_string")
add("bad-nonce-trailing-newline", None, v1(dict(AUTH, nonce=AUTH["nonce"] + "\n"), sig(R, S, 27)),
    "Same class of bug on nonce: a trailing newline must be refused, not hashed as a different fingerprint.",
    "malformed", "nonce_not_bytes32_hex")
add("bad-scheme-not-exact", None, {**v1(AUTH, sig(R, S, 27)), "scheme": "upto"},
    "scheme='upto' is Permit2-only on EVM (EIP-3009 transferWithAuthorization is not supported for it); it must not fingerprint as if it were 'exact'.",
    "malformed", "scheme_not_exact")
add("bad-value-exceeds-uint256", None, v1(dict(AUTH, value=str(2**256)), sig(R, S, 27)),
    "value one past uint256 max: ERC-3009 value is a uint256, so a larger canonical-looking decimal string must be refused, not hashed.",
    "malformed", "value_exceeds_uint256")
add("alias-ts-only-abstract", "P5", v1(dict(AUTH, nonce="0x" + hashlib.sha256(b"x402-fp-fixture-nonce-5").hexdigest()), sig(R, S, 27), network="abstract"),
    "A payment on Abstract, a v1 TS-only alias not in the old 8-entry table. Pins the normative table resolution of the group's open network-alias question (x402-foundation/tsc#4).")
add("alias-go-only-celo", "P6", v1(dict(AUTH, nonce="0x" + hashlib.sha256(b"x402-fp-fixture-nonce-6").hexdigest()), sig(R, S, 27), network="celo"),
    "A payment on Celo, a v1 Go-only alias (absent from the TS NetworkSchema) not in the old 8-entry table. Same normative-table resolution.")

fps = {}
for v in V:
    if v["expect"]["outcome"] == "ok":
        fps.setdefault(v["payment_id"], set()).add(v["expect"]["fingerprint"])
assert all(len(s) == 1 for s in fps.values()) and len({next(iter(s)) for s in fps.values()}) == len(fps), "same payment -> same fp; different -> different"
naive_p1 = {v["naive_full_payload_sha256"] for v in V if v["payment_id"] == "P1"}
doc = {"recipe": RECIPE, "license": "CC0-1.0", "vectors": V,
       "naive_recipe_note": f"sha256 over the JSON each party holds gives {len(naive_p1)} different digests for the 4 copies of payment P1; the recipe gives 1."}
open(os.path.join(HERE, "vectors.json"), "w").write(json.dumps(doc, indent=1) + "\n")
print(f"{len(V)} vectors; P1 naive digests {len(naive_p1)} vs recipe 1; sha256(vectors.json) {hashlib.sha256(open(os.path.join(HERE,'vectors.json'),'rb').read()).hexdigest()[:16]}")
