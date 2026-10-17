"""x402-receipt-private-opening/0 -- a verifier's signed statement about a PRIVATELY opened receipt commitment (draft, CC0).

The tier proposed on ethereum-magicians t/25098 (#422 predge-ai, #423): a rater opens the receipt v2
`authorizationCommitment` to one verifier that is neither seller nor buyer, instead of publishing the salt. The verifier
signs what it found, and the payment stays off the public record.

What the statement attests, and nothing else:
  * the commitment opens to a consumed ERC-3009 authorization of the receipt's signed `payer` (x402#3827 sec 5.5),
  * that `payer` is the rater,
  * the settlement paid a wallet bound to the rated agent.
Counting is per distinct (rater, agent) pair, so a payment cannot ground a second agent (payTo binds it) and a verifier
needs no cross-verifier "not seen before" store (which would have to be keyed on the public (asset, payer, nonce)
tuple and would re-link the rating to its settlement).

Privacy rule: the statement never carries the nonce, the settlement transaction or the salt.
Challengeability: the statement binds sha256 of the exact receipt it opened and sits in an append-only, hash-chained
log; if the rater later opens in public, anyone can recompute the result for that receipt (challenge()).
Not covered: the seller's receipt signature (sec 5 of the receipt spec) is taken as already verified, and this kit
does not anchor the log to an external clock (a deployment would, e.g. OpenTimestamps on the daily log head).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import importlib.util
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# Load the sibling kit's commitment.py by PATH under its own name. Putting that directory on sys.path would shadow
# this kit's modules (both kits have a build_vectors.py).
_spec = importlib.util.spec_from_file_location(
    "x402_rac_commitment", os.path.join(_HERE, "..", "x402-receipt-authorization-commitment", "commitment.py"))
_rac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rac)
Malformed, link = _rac.Malformed, _rac.link
sys.path.insert(0, _HERE)
import ed25519_ref as ed  # noqa: E402

TYPE = "x402-receipt-private-opening/0"
RESULTS = ("opens_to_settlement", "no_settlement", "payer_is_not_rater", "payto_not_bound_to_agent", "incomplete_check")
ZERO = "0" * 64


def canon(obj) -> bytes:
    """Canonical JSON for the ASCII strings/ints/objects used here (sorted keys, no whitespace: RFC 8785 for this subset)."""
    s = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return s.encode("ascii")


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def receipt_sha256(receipt: dict) -> str:
    return hashlib.sha256(canon(receipt)).hexdigest()


def assess(receipt: dict, opening: dict, rater: str, agent_wallets: list[str], chain: dict) -> str:
    """The verifier's finding. `opening` = {salt, asset} received privately from the rater; `chain` = the settlement facts
    the verifier read for the payer: {"nonces": {nonce: {"tx", "status", "transfers": [{"to", "amount"}]}}}."""
    payer = receipt["payer"].lower()
    if payer != rater.lower():
        return "payer_is_not_rater"
    # x402#3827 sec 5.6.4 (as amended): a verifier that could not obtain the candidate set reports an INCOMPLETE CHECK,
    # never "no settlement". chain = None / {"available": False} means the log query failed or was rate limited.
    if not isinstance(chain, dict) or chain.get("available") is False or not isinstance(chain.get("nonces"), dict):
        return "incomplete_check"
    try:
        r = link(receipt["authorizationCommitment"], opening["salt"], receipt["authorizationMethod"], opening["asset"],
                 payer, list(chain["nonces"]))
    except Malformed:
        return "no_settlement"
    if r["result"] != "linked":
        return "no_settlement"
    s = chain["nonces"][r["nonce"]]
    if s.get("status") != 1:
        return "no_settlement"
    if s.get("transfers") is None:          # settlement found, but its transfers were not read: payTo cannot be confirmed
        return "incomplete_check"
    bound = {w.lower() for w in agent_wallets}
    if not any(t["to"].lower() in bound for t in s["transfers"]):
        return "payto_not_bound_to_agent"
    return "opens_to_settlement"


def make_statement(receipt: dict, result: str, rater: str, agent: str, asset: str, checked_at: str, seq: int,
                   prev: str, secret: bytes) -> dict:
    if result not in RESULTS:
        raise ValueError(result)
    st = {"type": TYPE, "receipt_sha256": receipt_sha256(receipt), "commitment": receipt["authorizationCommitment"].lower(),
          "method": receipt["authorizationMethod"], "network": receipt["network"], "asset": asset.lower(),
          "rater": rater.lower(), "agent": agent, "result": result, "checked_at": checked_at, "seq": seq, "prev": prev,
          "verifier": _b64u(ed.public_key(secret))}
    st["signature"] = _b64u(ed.sign(secret, canon(st)))
    return st


def signature_ok(st: dict) -> bool:
    body = {k: v for k, v in st.items() if k != "signature"}
    try:
        return ed.verify(_unb64u(st["verifier"]), canon(body), _unb64u(st["signature"]))
    except Exception:
        return False


def leaks(st: dict, secrets: list[str]) -> list[str]:
    """Which of nonce / settlement tx / salt appear anywhere in the statement (with or without 0x, any case)."""
    blob = canon(st).decode().lower()
    return [s for s in secrets if s.lower().removeprefix("0x") in blob]


def log_ok(statements: list[dict]) -> bool:
    """Append-only: seq runs 0..n-1 and each prev is sha256 of the previous statement's canonical bytes."""
    prev = ZERO
    for i, st in enumerate(statements):
        if st.get("seq") != i or st.get("prev") != prev or not signature_ok(st):
            return False
        prev = hashlib.sha256(canon(st)).hexdigest()
    return True


def challenge(st: dict, receipt: dict, public_opening: dict, agent_wallets: list[str], chain: dict) -> str:
    """After the rater opens in public: upheld | refuted | not_bound (statement is about another receipt) | bad_signature |
    incomplete (the challenger could not read the chain; never read as upheld or refuted)."""
    if not signature_ok(st):
        return "bad_signature"
    if st.get("receipt_sha256") != receipt_sha256(receipt):
        return "not_bound"
    again = assess(receipt, public_opening, st["rater"], agent_wallets, chain)
    if again == "incomplete_check":                # the challenger could not read the chain: no verdict either way
        return "incomplete"
    return "upheld" if again == st["result"] else "refuted"


def grounded_pairs(statements: list[dict], trusted_verifiers: set[str]) -> set[tuple[str, str]]:
    """Distinct (rater, agent) pairs a named verifier found opens_to_settlement for. Ratings are not the unit."""
    return {(s["rater"], s["agent"]) for s in statements
            if s.get("result") == "opens_to_settlement" and s.get("verifier") in trusted_verifiers and signature_ok(s)}
