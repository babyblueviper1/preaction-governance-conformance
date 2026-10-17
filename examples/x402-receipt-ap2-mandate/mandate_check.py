"""x402-receipt-ap2-mandate/0 -- does a receipt's settlement trace back to the user's AP2 consent? (draft, CC0)

AP2's embedded x402 flow (google-agentic-commerce/a2a-x402 spec v0.2 sec 4) already chains three signatures through one value:
  * the merchant signs the cart (CartMandate.merchant_authorization, a JWT whose cart_hash covers CartContents);
  * the user signs consent (PaymentMandate.user_authorization, an SD-JWT VC whose key-binding JWT carries transaction_data =
    the hashes of the CartMandate and the PaymentMandateContents);
  * the PaymentMandateContents embed the x402 PaymentPayload, i.e. the signed ERC-3009 authorization with its nonce.
An x402 receipt v2 (x402#3827) commits to that same nonce with a salt. So a holder of the receipt, its salt and the two
mandates can check, without trusting the seller, the buyer's agent or us:
    the user consented to THIS cart and THIS payment  ->  the authorization pays the cart's payee no more than its price
    ->  the receipt names THIS authorization  ->  THIS authorization settled on chain, to that payee, for that amount.
check() returns one result; the first failing link names it:
    consented_and_settled | consent_invalid | consent_not_bound | cart_not_merchant_signed | terms_mismatch
    | receipt_not_this_authorization | no_settlement | settlement_terms_mismatch | incomplete_check | malformed
Not covered here: the ERC-3009 signature itself (the USDC contract checked it when it consumed the nonce, which is what
the chain leg reads); expiry windows; selective disclosures (the user credential here discloses nothing); key resolution
(trusted issuer and merchant keys are inputs). AP2 does not yet pin the hash encoding for cart_hash / transaction_data;
this kit uses base64url(sha256(canonical JSON)) and says so (an open question for AP2, not a claim about it).
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_HERE, "..", rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_rac = _load("x402_rac_commitment", "x402-receipt-authorization-commitment/commitment.py")
ed = _load("x402_ed25519_ref", "x402-receipt-private-opening/ed25519_ref.py")

TYPE = "x402-receipt-ap2-mandate/0"
X402_METHOD = "https://www.x402.org/"
RESULTS = ("consented_and_settled", "consent_invalid", "consent_not_bound", "cart_not_merchant_signed", "terms_mismatch",
           "receipt_not_this_authorization", "no_settlement", "settlement_terms_mismatch", "incomplete_check", "malformed")


def canon(obj) -> bytes:
    """Canonical JSON for the ASCII strings/ints/bools/objects used here (sorted keys, no whitespace: RFC 8785 for this subset)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    if not isinstance(s, str) or "=" in s:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def h(obj) -> str:
    """The hash this kit uses for cart_hash and transaction_data: base64url(sha256(canonical JSON))."""
    return b64u(hashlib.sha256(canon(obj)).digest())


def jwt_sign(header: dict, payload: dict, secret: bytes) -> str:
    si = b64u(canon(header)) + "." + b64u(canon(payload))
    return si + "." + b64u(ed.sign(secret, si.encode("ascii")))


def jwt_verify(token: str, pub: bytes) -> dict | None:
    """EdDSA (Ed25519) JWS compact. Returns the payload if the signature verifies under `pub`, else None."""
    try:
        hd, pl, sg = token.split(".")
        if json.loads(unb64u(hd)).get("alg") != "EdDSA":
            return None
        if not ed.verify(pub, (hd + "." + pl).encode("ascii"), unb64u(sg)):
            return None
        return json.loads(unb64u(pl))
    except (ValueError, KeyError, AttributeError, TypeError):
        return None


def _x402_requirement(cart_contents: dict) -> dict:
    for m in cart_contents["payment_request"]["method_data"]:
        if m.get("supported_methods") == X402_METHOD:
            return m["data"]["accepts"][0]
    raise KeyError("no x402 method in the cart")


def check(bundle: dict, chain: dict | None, trusted: dict) -> str:
    """bundle = {cart_mandate, payment_mandate, receipt, salt}; trusted = {"issuer": b64u pubkey, "merchant": b64u pubkey};
    chain = {"nonces": {nonce: {"status", "tx", "transfers": [{"to", "amount"}] | None}}} for the payer, or None /
    {"available": False} when the log query failed."""
    try:
        cm, pm, receipt, salt = bundle["cart_mandate"], bundle["payment_mandate"], bundle["receipt"], bundle["salt"]
        pmc = pm["payment_mandate_contents"]
        issuer_jwt, kb_jwt = pm["user_authorization"].split("~")[0], pm["user_authorization"].split("~")[-1]
        cart = cm["contents"]
        req = _x402_requirement(cart)
        pay = pmc["payment_response"]["details"]
        auth = pay["payload"]["authorization"]
    except (KeyError, TypeError, AttributeError, IndexError, ValueError):
        return "malformed"
    # 1. the user's consent: the issuer vouches for the user's key (cnf), the user's key signs the key-binding JWT
    cred = jwt_verify(issuer_jwt, unb64u(trusted["issuer"]))
    try:
        user_pub = unb64u(cred["cnf"]["jwk"]["x"]) if cred else None
    except (KeyError, TypeError, ValueError):
        user_pub = None
    kb = jwt_verify(kb_jwt, user_pub) if user_pub else None
    if not kb or kb.get("sd_hash") != b64u(hashlib.sha256((issuer_jwt + "~").encode("ascii")).digest()):
        return "consent_invalid"
    # 2. ...over THIS cart and THIS payment
    td = kb.get("transaction_data")
    if not isinstance(td, list) or h(cm) not in td or h(pmc) not in td or pmc.get("payment_details_id") != \
            cart["payment_request"]["details"]["id"]:
        return "consent_not_bound"
    # 3. the cart is the merchant's: its JWT signs the hash of these contents
    mj = jwt_verify(cm.get("merchant_authorization") or "", unb64u(trusted["merchant"]))
    if not mj or mj.get("cart_hash") != h(cart):
        return "cart_not_merchant_signed"
    # 4. the consented authorization pays what the cart asks: same network and asset, the cart's payee, no more than its price
    try:
        terms_ok = (pay.get("network") == req["network"] and pay.get("scheme") == req["scheme"]
                    and auth["to"].lower() == req["payTo"].lower() and int(auth["value"]) <= int(req["maxAmountRequired"]))
    except (KeyError, ValueError, TypeError, AttributeError):
        return "malformed"
    if not terms_ok:
        return "terms_mismatch"
    # 5. the receipt names THIS authorization (x402#3827 sec 5.5: the authorizer is the receipt's signed payer)
    try:
        same = (receipt["payer"].lower() == auth["from"].lower() and receipt.get("authorizationMethod") == "eip3009"
                and _rac.commit("eip3009", req["asset"], receipt["payer"], auth["nonce"], salt)
                == receipt["authorizationCommitment"].lower())
    except (_rac.Malformed, KeyError, AttributeError):
        same = False
    if not same:
        return "receipt_not_this_authorization"
    # 6. THIS authorization settled, to that payee, for that amount (sec 5.6.4: an unreadable chain is incomplete, not "no")
    if not isinstance(chain, dict) or chain.get("available") is False or not isinstance(chain.get("nonces"), dict):
        return "incomplete_check"
    s = chain["nonces"].get(auth["nonce"].lower())
    if not s or s.get("status") != 1:
        return "no_settlement"
    if s.get("transfers") is None:
        return "incomplete_check"
    if not any(t["to"].lower() == auth["to"].lower() and int(t["amount"]) == int(auth["value"]) for t in s["transfers"]):
        return "settlement_terms_mismatch"
    return "consented_and_settled"
