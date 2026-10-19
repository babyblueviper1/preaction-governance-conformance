"""x402-receipt-authorization-commitment/0 -- reference construction and holder-side link check (draft, CC0).

A receipt carries `authorizationCommitment`, a salted commitment to the payment authorization's on-chain identifier.
The seller returns the salt to the buyer outside the signed payload. Without the salt the field links to nothing on
chain; with it, the holder recomputes the link to exactly one settlement.

    commitment = sha256( TAG || 0x00 || method || 0x00 || asset(20) || authorizer(20) || nonce(32) || salt(32) )

TAG = b"x402-receipt-authorization/0". Every field after `method` has a fixed length, so the preimage is unambiguous.
Only method "eip3009" is defined here (identifier = the ERC-3009 `nonce`, consumed per (asset, authorizer) and logged
as `AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)`).
"""
from __future__ import annotations

import hashlib
import re

TAG = b"x402-receipt-authorization/0"
METHODS = ("eip3009",)
_ADDR = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_B32 = re.compile(r"0x[0-9a-fA-F]{64}\Z")


class Malformed(ValueError):
    def __init__(self, condition: str):
        super().__init__(condition)
        self.condition = condition


class NotAttempted(ValueError):
    """The input is well formed but this checker does not implement the method: the spec (§5.3, §5.6.4) says such a receipt is
    NOT malformed and the link is not attempted. Kept apart from Malformed so the two results are never conflated."""
    def __init__(self, condition: str):
        super().__init__(condition)
        self.condition = condition


def _addr(v, name):
    if not isinstance(v, str) or not _ADDR.match(v):
        raise Malformed(f"{name}_not_address")
    return bytes.fromhex(v[2:].lower())


def _b32(v, name):
    if not isinstance(v, str) or not _B32.match(v):
        raise Malformed(f"{name}_not_bytes32")
    return bytes.fromhex(v[2:].lower())


def commit(method: str, asset: str, authorizer: str, nonce: str, salt: str) -> str:
    """The commitment as 0x-prefixed lowercase hex. Raises Malformed with a named condition."""
    if method not in METHODS:
        raise NotAttempted("unsupported_method")
    pre = (TAG + b"\x00" + method.encode() + b"\x00" + _addr(asset, "asset") + _addr(authorizer, "authorizer")
           + _b32(nonce, "nonce") + _b32(salt, "salt"))
    return "0x" + hashlib.sha256(pre).hexdigest()


def link(commitment: str, salt: str, method: str, asset: str, authorizer: str, candidates: list[str]) -> dict:
    """Holder-side check: which of the authorizer's consumed nonces does the commitment name?

    `candidates` is every nonce in AuthorizationUsed(authorizer, *) on `asset` (one log query). The result is
    `linked` with the single matching nonce, or `no_match`. Two matches would mean a sha256 collision.
    """
    _b32(commitment, "commitment")
    hits = [n for n in candidates if commit(method, asset, authorizer, n, salt) == commitment.lower()]
    if len(hits) == 1:
        return {"result": "linked", "nonce": hits[0].lower()}
    return {"result": "no_match"} if not hits else {"result": "ambiguous", "nonces": hits}
