"""Build vectors.json: an AP2 cart + payment mandate around the REAL Base Sepolia settlement A, and one-link-broken cases.

Settlement A (also used by the two sibling kits): USDC 0x036c...cf7e on eip155:84532, tx 0x1345479a...de88, block 48163177,
transferWithAuthorization(from 0x87f3...6ee1, to 0x2888...ec26, value 1000, validAfter 0, validBefore 0x6ad13286,
nonce 0xc012...0c83, v 27, r 0xdfcc...0352, s 0x42e1...91e1), all read from the transaction's calldata. The receipt and its
salt are the sibling kits' (test salt "A"). The issuer, merchant and user keys are PUBLIC TEST KEYS from fixed seeds.
"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mandate_check as M  # noqa: E402

ed, rac = M.ed, M._rac


def key(label):
    sk = hashlib.sha256(f"x402-ap2-mandate-test-key/{label}".encode()).digest()
    return sk, ed.public_key(sk)


ISS, MER, USER, OTHER = key("issuer"), key("merchant"), key("user"), key("not-the-user")
ASSET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
PAYER = "0x87f344b6ec48a936373d774d3de8649deeb66ee1"
PAYTO = "0x2888f36548a900b9b08d584524e1f73bc563ec26"
NONCE_A = "0xc01225fc79db19be6ea2afdbbbc195968e121184e39df0b4f62d7f8f5df40c83"
NONCE_UNSPENT = "0x" + hashlib.sha256(b"x402-ap2-mandate-test/never-consumed").hexdigest()
SALT_A = "0x" + hashlib.sha256(b"x402-rac-test-salt/A").hexdigest()
AUTH_A = {"from": PAYER, "to": PAYTO, "value": "1000", "validAfter": "0", "validBefore": str(0x6ad13286), "nonce": NONCE_A}
SIG_A = ("0xdfcc417d5f96cdbc9e06335b7b9cd7865d338b5068f40f4dd18003fa86900352"
         "42e199afab6c7853ff3dc00ed291e2a47a9a5636be2dbb6bd72893634e6391e1" "1b")
CHAIN = json.load(open(os.path.join(HERE, "..", "x402-receipt-private-opening", "vectors.json")))["chain"]
RESOURCE = "https://seller.example/api/resource"


def cart(pay_to=PAYTO, max_amount="1000", cart_id="cart_report_123"):
    return {"id": cart_id, "user_cart_confirmation_required": True, "cart_expiry": "2026-10-15T21:30:00Z",
            "merchant_name": "Example Seller",
            "payment_request": {
                "details": {"id": "order_" + cart_id, "total": {"label": "Total", "amount": {"currency": "USDC", "value": "0.001"}}},
                "method_data": [{"supported_methods": M.X402_METHOD, "data": {"x402Version": 1, "accepts": [{
                    "scheme": "exact", "network": "base-sepolia", "asset": ASSET, "payTo": pay_to,
                    "maxAmountRequired": max_amount, "resource": RESOURCE}]}}]}}


def cart_mandate(contents, signed_contents=None):
    jwt = M.jwt_sign({"alg": "EdDSA", "kid": "merchant-test", "typ": "JWT"},
                     {"iss": "merchant.example", "sub": "merchant.example", "aud": "payment-processor.example",
                      "iat": 1776000000, "exp": 1776000900, "jti": "cart-jwt-1",
                      "cart_hash": M.h(signed_contents if signed_contents is not None else contents)}, MER[0])
    return {"contents": contents, "merchant_authorization": jwt}


def pm_contents(c, auth=AUTH_A):
    return {"payment_mandate_id": "pm_1", "payment_details_id": c["payment_request"]["details"]["id"],
            "payment_details_total": c["payment_request"]["details"]["total"],
            "payment_response": {"request_id": c["payment_request"]["details"]["id"], "method_name": M.X402_METHOD,
                                 "details": {"x402Version": 1, "scheme": "exact", "network": "base-sepolia",
                                             "payload": {"signature": SIG_A, "authorization": dict(auth)}}},
            "merchant_agent": "merchant-agent.example", "timestamp": "2026-10-15T21:10:00Z"}


def consent(cm, pmc, user=USER, issuer=ISS, hashes=None, signer=None):
    cred = M.jwt_sign({"alg": "EdDSA", "kid": "issuer-test", "typ": "vc+sd-jwt"},
                      {"iss": "issuer.example", "sub": "user-1", "vct": "ap2-user-credential",
                       "cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": M.b64u(user[1])}}}, issuer[0])
    kb = M.jwt_sign({"alg": "EdDSA", "typ": "kb+jwt"},
                    {"aud": "merchant.example", "nonce": "kb-nonce-1", "iat": 1776000600,
                     "sd_hash": M.b64u(hashlib.sha256((cred + "~").encode()).digest()),
                     "transaction_data": hashes if hashes is not None else [M.h(cm), M.h(pmc)]}, (signer or user)[0])
    return {"payment_mandate_contents": pmc, "user_authorization": cred + "~" + kb}


def receipt(nonce=NONCE_A, salt=SALT_A):
    return {"authorizationCommitment": rac.commit("eip3009", ASSET, PAYER, nonce, salt), "authorizationMethod": "eip3009",
            "issuedAt": 1776000000, "network": "eip155:84532", "payer": PAYER, "resourceUrl": RESOURCE}


def bundle(c=None, auth=AUTH_A, rec=None, **kw):
    c = c or cart()
    cm = cart_mandate(c)
    pmc = pm_contents(c, auth)
    return {"cart_mandate": cm, "payment_mandate": consent(cm, pmc, **kw), "receipt": rec or receipt(auth["nonce"]),
            "salt": SALT_A}


def vectors():
    good = bundle()
    V = [("consented-and-settled", good, CHAIN, "consented_and_settled",
          "the user consented to this cart and payment; the authorization pays the cart's payee its price; the receipt "
          "commits to its nonce; that nonce settled on chain to that payee for 1000")]
    V.append(("consent-signed-by-another-key", bundle(signer=OTHER), CHAIN, "consent_invalid",
              "the issuer vouches for the user's key, but the key-binding JWT is signed by another key"))
    V.append(("consent-issuer-untrusted", bundle(issuer=OTHER), CHAIN, "consent_invalid",
              "the user credential is not from the trusted issuer"))
    other = cart(cart_id="cart_other_999")
    b = bundle()
    b["payment_mandate"] = consent(b["cart_mandate"], b["payment_mandate"]["payment_mandate_contents"],
                                   hashes=[M.h(cart_mandate(other)), M.h(b["payment_mandate"]["payment_mandate_contents"])])
    V.append(("consent-for-another-cart", b, CHAIN, "consent_not_bound",
              "the user signed a different cart's hash; this cart was never consented to"))
    c = cart()
    cm = cart_mandate(c, signed_contents=cart(max_amount="500"))
    pmc = pm_contents(c)
    b = {"cart_mandate": cm, "payment_mandate": consent(cm, pmc), "receipt": receipt(), "salt": SALT_A}
    V.append(("cart-not-what-merchant-signed", b, CHAIN, "cart_not_merchant_signed",
              "the merchant's JWT signs a cart priced 500; the cart presented (and consented to) is a different one"))
    V.append(("authorization-pays-another-wallet", bundle(c=cart(pay_to="0x" + "11" * 20)), CHAIN, "terms_mismatch",
              "the consented authorization pays 0x2888..., not the cart's payee"))
    V.append(("authorization-above-cart-price", bundle(c=cart(max_amount="999")), CHAIN, "terms_mismatch",
              "the consented authorization pays 1000; the cart asks at most 999"))
    other_nonce = next(n for n, v in CHAIN["nonces"].items() if n != NONCE_A)
    V.append(("receipt-names-another-authorization", bundle(rec=receipt(other_nonce)), CHAIN,
              "receipt_not_this_authorization", "the receipt commits to one of the payer's other settled nonces"))
    unspent = dict(AUTH_A, nonce=NONCE_UNSPENT)
    V.append(("consented-but-never-settled", bundle(auth=unspent), CHAIN, "no_settlement",
              "consent and receipt agree on a nonce the payer never consumed"))
    V.append(("chain-unavailable", good, {"available": False}, "incomplete_check",
              "the log query failed: an incomplete check, never no_settlement (x402#3827 sec 5.6.4)"))
    unread = copy.deepcopy(CHAIN)
    unread["nonces"][NONCE_A]["transfers"] = None
    V.append(("settlement-transfers-unread", good, unread, "incomplete_check",
              "the settlement was found but its transfers were not read, so payee and amount are unconfirmed"))
    short = copy.deepcopy(CHAIN)
    short["nonces"][NONCE_A]["transfers"] = [{"to": PAYTO, "amount": "999", "log_index": 181}]
    V.append(("settled-amount-differs", good, short, "settlement_terms_mismatch",
              "the nonce settled, but the transfer on chain is not the consented amount"))
    return {"name": M.TYPE, "license": "CC0-1.0",
            "trusted": {"issuer": M.b64u(ISS[1]), "merchant": M.b64u(MER[1])},
            "test_keys": "issuer, merchant and user keys are PUBLIC TEST KEYS: sha256('x402-ap2-mandate-test-key/<label>')",
            "vectors": [{"id": i, "bundle": bd, "chain": ch, "expect": e, "why": w} for i, bd, ch, e, w in V]}


if __name__ == "__main__":
    with open(os.path.join(HERE, "vectors.json"), "w") as f:
        json.dump(vectors(), f, indent=1, sort_keys=True)
        f.write("\n")
    print("wrote vectors.json")
