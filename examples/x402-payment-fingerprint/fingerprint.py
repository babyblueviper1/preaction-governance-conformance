#!/usr/bin/env python3
"""x402 payment fingerprint, recipe x402-payment-fingerprint/0 (draft, CC0) -- for the x402 TSC evidence-record group (x402-foundation/tsc#4,
the "Evidence lane" proposal of 2026-10-06): one digest that the buyer and the seller each derive, independently, from the payment they both saw,
so their records join without either side minting a reference number.

    fp = sha256( JCS({ "v": "x402-payment-fingerprint/0",
                       "network": CAIP-2 chain id ("eip155:<chainId>"; v1 aliases mapped, see NETWORK_ALIASES),
                       "asset":   token contract, lowercase 0x + 40 hex,
                       "from":    authorization.from, lowercase,
                       "to":      authorization.to, lowercase,
                       "value":   authorization.value as a canonical decimal integer string,
                       "nonce":   authorization.nonce, lowercase 0x + 64 hex }) )   -> "sha256:<hex>"

Inputs are the EIP-3009 `exact`-scheme authorization both parties hold (v1 PaymentPayload.payload.authorization or the v2 equivalent),
plus the requirement's network + asset. Deliberately EXCLUDED: the signature (ECDSA is malleable: (r, s) and (r, n-s) both verify, so two honest
copies of one payment can carry different signature bytes), validAfter/validBefore, the envelope (x402Version, resource, description, extra), and
any JSON formatting. On EVM the token records (from, nonce) as used (AuthorizationUsed), so (network, asset, from, nonce) already identifies at
most one settlement; to/value bind the record to its content.

fingerprint(payment) -> ("ok", "sha256:<hex>") | ("malformed", "<condition>")

Independent clean-room re-implementation + differential fuzz (x402-foundation/tsc#4, robertolocatelli81-dev/Noûs,
2026-10-06) found two real acceptance bugs, fixed here: (1) the four field regexes anchored with a trailing `$`,
which in Python also matches just before a final "\n" -- a value/nonce/network/asset string with a trailing
newline was silently accepted and hashed as its own distinct fingerprint instead of being refused; fixed by
anchoring with a hard end-of-string anchor instead of `$`. (2) `scheme` was accepted as part of the payment but never checked, so a Permit2
`upto` authorization (not supported for EIP-3009 `transferWithAuthorization`, see x402 specs/schemes/upto) was
fingerprinted identically to an `exact` one; now a non-"exact" scheme is refused as malformed ("scheme_not_exact").
`scheme` is validated, never hashed -- adding it to the gate does not change any existing vector's fingerprint.
"""
import hashlib, json, os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
from _rfc8785 import jcs  # noqa: E402  (vendored RFC 8785 canonicalizer this recipe depends on; see ../../tools/)
canonicalize = lambda o: jcs(o).encode("utf-8")

RECIPE = "x402-payment-fingerprint/0"
UINT256_MAX = 2**256 - 1
NETWORK_ALIASES = {"base": "eip155:8453", "base-sepolia": "eip155:84532", "ethereum": "eip155:1", "polygon": "eip155:137",
                   "avalanche": "eip155:43114", "avalanche-fuji": "eip155:43113", "sei": "eip155:1329", "iotex": "eip155:4689"}
# NOTE (open question for the group, not settled here): this table has 8 entries; the x402 v1 TS NetworkSchema has
# 15 EVM entries and the Go v1 table disagrees with it on 9 aliases (e.g. "ethereum" is Go-only). Either this table
# becomes normative for /0, or /0 accepts CAIP-2 only and leaves alias mapping to the caller.
ADDR = re.compile(r"\A0x[0-9a-fA-F]{40}\Z"); NONCE = re.compile(r"\A0x[0-9a-fA-F]{64}\Z"); CAIP2 = re.compile(r"\Aeip155:[1-9][0-9]{0,31}\Z")
DEC = re.compile(r"\A(0|[1-9][0-9]*)\Z")


def _network(n):
    if not isinstance(n, str):
        return None
    n = NETWORK_ALIASES.get(n, n)
    return n if CAIP2.match(n) else None


def preimage(payment):
    """payment = {"network", "asset", "scheme", "authorization": {"from", "to", "value", "nonce", ...}} (any other
    extra keys ignored). "scheme" is required and checked (EVM `exact` only) but is not part of the hashed preimage."""
    a = payment.get("authorization") if isinstance(payment, dict) else None
    if not isinstance(a, dict):
        return None, "authorization_missing"
    if payment.get("scheme") != "exact":
        return None, "scheme_not_exact"
    net = _network(payment.get("network"))
    if net is None:
        return None, "network_not_caip2_mappable"
    for k, v in (("asset", payment.get("asset")), ("from", a.get("from")), ("to", a.get("to"))):
        if not isinstance(v, str) or not ADDR.match(v):
            return None, f"{k}_not_evm_address"
    if not isinstance(a.get("nonce"), str) or not NONCE.match(a["nonce"]):
        return None, "nonce_not_bytes32_hex"
    val = a.get("value")
    if isinstance(val, bool) or not isinstance(val, str) or not DEC.match(val):
        return None, "value_not_canonical_decimal_string"
    if len(val) > 78 or (len(val) == 78 and int(val) > UINT256_MAX):
        return None, "value_exceeds_uint256"
    return {"v": RECIPE, "network": net, "asset": payment["asset"].lower(), "from": a["from"].lower(), "to": a["to"].lower(),
            "value": val, "nonce": a["nonce"].lower()}, None


def fingerprint(payment):
    pre, err = preimage(payment)
    if err:
        return "malformed", err
    return "ok", "sha256:" + hashlib.sha256(canonicalize(pre)).hexdigest()


if __name__ == "__main__":
    print(json.dumps(fingerprint(json.load(open(sys.argv[1]))) if len(sys.argv) > 1 else "usage: fingerprint.py payment.json"))
