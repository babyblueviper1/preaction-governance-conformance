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
    # a missing network/asset/scheme reaches fingerprint() as None, so it gets the recipe's own specific condition (2026-10-06, Noûs)
    return {"network": acc.get("network"), "asset": acc.get("asset"), "scheme": acc.get("scheme"), "authorization": p["payload"]["authorization"]}

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
add("diff-7-max-value", "P7", v1(dict(AUTH, value=str(2**256 - 1)), sig(R, S, 27)),
    "value 2^256-1, the largest uint256: accepted and fingerprinted (the uint256 bound is inclusive).")
add("diff-8-uppercase-nonce", "P8", v1(dict(AUTH, nonce="0x" + hashlib.sha256(b"x402-fp-fixture-nonce-8").hexdigest().upper()), sig(R, S, 27)),
    "A nonce written in uppercase hex: accepted, and the preimage holds it lowercased, so it fingerprints like the lowercase spelling.")
add("diff-9-reference-32-chars", "P9", v1(AUTH, sig(R, S, 27), network="eip155:" + "1" * 32),
    "A CAIP-2 reference of exactly 32 characters: accepted (CAIP-2 allows 1-32, the bound is inclusive).")
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
_noscheme = v1(AUTH, sig(R, S, 27)); _noscheme.pop("scheme")
add("bad-scheme-missing", None, _noscheme,
    "Envelope with no scheme at all: refused as scheme_not_exact (only an explicit 'exact' fingerprints), not as an unreadable envelope. "
    "Pins the condition name raised by Noûs (x402-foundation/tsc#4, 2026-10-06).",
    "malformed", "scheme_not_exact")
add("bad-address-trailing-newline", None, v1(dict(AUTH, **{"from": BUYER + "\n"}), sig(R, S, 27)),
    "authorization.from plus a final newline: refused, not lowercased and hashed as a different payment.", "malformed", "from_not_evm_address")
add("bad-network-chain-zero", None, v1(AUTH, sig(R, S, 27), network="eip155:0"),
    "eip155:0: the chain-id reference must start with 1-9, so chain id 0 is refused.", "malformed", "network_not_caip2_mappable")
add("bad-network-reference-too-long", None, v1(AUTH, sig(R, S, 27), network="eip155:" + "1" * 33),
    "A CAIP-2 reference of 33 characters: CAIP-2 allows 1-32.", "malformed", "network_not_caip2_mappable")
add("bad-network-trailing-newline", None, v1(AUTH, sig(R, S, 27), network="eip155:8453\n"),
    "network 'eip155:8453' plus a final newline: refused, neither stripped to Base nor hashed as another chain.", "malformed", "network_not_caip2_mappable")
add("bad-network-number", None, v1(AUTH, sig(R, S, 27), network=8453),
    "network as a JSON number: refused with the network condition, not looked up and not an unreadable envelope.", "malformed", "network_not_caip2_mappable")
add("bad-network-not-eip155", None, v1(AUTH, sig(R, S, 27), network="xrpl:1"),
    "A CAIP-2 id outside the eip155 namespace with a numeric reference: the recipe is EVM only.", "malformed", "network_not_caip2_mappable")
add("bad-network-hex-reference", None, v1(AUTH, sig(R, S, 27), network="eip155:0x2105"),
    "eip155:0x2105 (Base's chain id in hex, as EIP-1193 wallets report it): the CAIP-2 reference is decimal.", "malformed", "network_not_caip2_mappable")
add("bad-network-alias-uppercase", None, v1(AUTH, sig(R, S, 27), network="Base"),
    "'Base': the alias table is matched exactly, so a differently-cased alias is refused rather than guessed.", "malformed", "network_not_caip2_mappable")
add("bad-asset-41-hex", None, v1(AUTH, sig(R, S, 27), asset=USDC + "0"),
    "asset with 41 hex digits: addresses are 20 bytes.", "malformed", "asset_not_evm_address")
add("bad-address-39-hex", None, v1(dict(AUTH, **{"from": BUYER[:-1]}), sig(R, S, 27)),
    "authorization.from with 39 hex digits.", "malformed", "from_not_evm_address")
add("bad-address-uppercase-prefix", None, v1(dict(AUTH, to="0X" + SELLER[2:]), sig(R, S, 27)),
    "authorization.to with the prefix '0X': the prefix is '0x'.", "malformed", "to_not_evm_address")
add("bad-address-no-prefix", None, v1(dict(AUTH, to=SELLER[2:]), sig(R, S, 27)),
    "authorization.to as 40 hex digits without '0x'.", "malformed", "to_not_evm_address")
add("bad-address-leading-space", None, v1(dict(AUTH, **{"from": " " + BUYER}), sig(R, S, 27)),
    "authorization.from with a leading space: refused, like the trailing newline (an end-anchored-only check would accept it).",
    "malformed", "from_not_evm_address")
add("bad-nonce-63-hex", None, v1(dict(AUTH, nonce=NONCE[:-1]), sig(R, S, 27)),
    "nonce with 63 hex digits.", "malformed", "nonce_not_bytes32_hex")
add("bad-nonce-65-hex", None, v1(dict(AUTH, nonce=NONCE + "0"), sig(R, S, 27)),
    "nonce with 65 hex digits.", "malformed", "nonce_not_bytes32_hex")
add("bad-nonce-uppercase-prefix", None, v1(dict(AUTH, nonce="0X" + NONCE[2:]), sig(R, S, 27)),
    "nonce with the prefix '0X': the prefix is '0x' (only the hex digits may be uppercase).", "malformed", "nonce_not_bytes32_hex")
add("bad-value-negative", None, v1(dict(AUTH, value="-1"), sig(R, S, 27)),
    "value '-1': uint256 has no sign.", "malformed", "value_not_canonical_decimal_string")
add("bad-value-79-digits", None, v1(dict(AUTH, value="1" + "0" * 78), sig(R, S, 27)),
    "value 10^78, 79 digits: past uint256 max by length alone.", "malformed", "value_exceeds_uint256")
add("bad-value-5000-digits", None, v1(dict(AUTH, value="9" * 5000), sig(R, S, 27)),
    "value of 5000 digits: refused by length before int(), which by default refuses to parse more than 4300 digits.",
    "malformed", "value_exceeds_uint256")
add("bad-scheme-uppercase", None, {**v1(AUTH, sig(R, S, 27)), "scheme": "EXACT"},
    "scheme 'EXACT': the scheme name is matched exactly.", "malformed", "scheme_not_exact")
add("bad-scheme-trailing-newline", None, {**v1(AUTH, sig(R, S, 27)), "scheme": "exact\n"},
    "scheme 'exact' plus a final newline: matched exactly, not stripped.", "malformed", "scheme_not_exact")
add("bad-authorization-not-object", None, {**v1(AUTH, sig(R, S, 27)), "payload": {"signature": sig(R, S, 27), "authorization": sig(R, S, 27)}},
    "authorization is a string, not an object: refused with the recipe's own condition.", "malformed", "authorization_missing")
add("bad-authorization-missing-from", None, v1({k: v for k, v in AUTH.items() if k != "from"}, sig(R, S, 27)),
    "authorization without from: refused with the from condition, not as an unreadable envelope (the bad-scheme-missing rule, applied to the authorization fields).",
    "malformed", "from_not_evm_address")
add("bad-authorization-missing-to", None, v1({k: v for k, v in AUTH.items() if k != "to"}, sig(R, S, 27)),
    "authorization without to: refused with the to condition.", "malformed", "to_not_evm_address")
add("bad-authorization-missing-value", None, v1({k: v for k, v in AUTH.items() if k != "value"}, sig(R, S, 27)),
    "authorization without value: refused with the value condition (a missing value is not 0).", "malformed", "value_not_canonical_decimal_string")
add("bad-authorization-missing-nonce", None, v1({k: v for k, v in AUTH.items() if k != "nonce"}, sig(R, S, 27)),
    "authorization without nonce: refused with the nonce condition.", "malformed", "nonce_not_bytes32_hex")
add("bad-address-non-hex", None, v1(dict(AUTH, **{"from": BUYER[:-1] + "g"}), sig(R, S, 27)),
    "authorization.from with a non-hex character ('g') in place of a hex digit: the alphabet is 0-9a-fA-F.", "malformed", "from_not_evm_address")
add("bad-nonce-non-hex", None, v1(dict(AUTH, nonce=NONCE[:-1] + "g"), sig(R, S, 27)),
    "nonce with a non-hex character ('g') in place of a hex digit.", "malformed", "nonce_not_bytes32_hex")
add("bad-nonce-no-prefix", None, v1(dict(AUTH, nonce=NONCE[2:]), sig(R, S, 27)),
    "nonce as 64 hex digits without '0x'.", "malformed", "nonce_not_bytes32_hex")
add("bad-nonce-number", None, v1(dict(AUTH, nonce=1234), sig(R, S, 27)),
    "nonce as a JSON number: refused with the nonce condition, not an unreadable envelope.", "malformed", "nonce_not_bytes32_hex")
add("bad-value-unicode-digits", None, v1(dict(AUTH, value="1\u0660\u0660\u0660\u0660"), sig(R, S, 27)),
    "value '1' followed by four Arabic-Indic zeros (U+0660): refused; a Unicode-aware digit class (Python's \\d) or int() alone would read it as 10000.",
    "malformed", "value_not_canonical_decimal_string")
add("bad-value-underscore", None, v1(dict(AUTH, value="10_000"), sig(R, S, 27)),
    "value '10_000': refused; int() alone would accept the underscore.", "malformed", "value_not_canonical_decimal_string")
add("bad-network-unicode-digits", None, v1(AUTH, sig(R, S, 27), network="eip155:8\u0664\u0665\u0663"),
    "eip155:8 followed by Arabic-Indic digits (U+0664 U+0665 U+0663, '8453' in mixed scripts): the CAIP-2 reference is ASCII; a Unicode-aware digit class would accept it.",
    "malformed", "network_not_caip2_mappable")
add("bad-network-namespace-uppercase", None, v1(AUTH, sig(R, S, 27), network="EIP155:8453"),
    "'EIP155:8453': the CAIP-2 namespace is lowercase and matched exactly.", "malformed", "network_not_caip2_mappable")
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
