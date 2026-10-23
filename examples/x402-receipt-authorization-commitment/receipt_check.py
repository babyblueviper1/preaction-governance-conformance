#!/usr/bin/env python3
"""Receipt-level checker for x402 offer-receipt payload version 2 (x402#3827 at fe777a4).

Written from the specification text alone (specs/extensions/extension-offer-and-receipt.md,
sections 3, 5.2 to 5.6), without reading commitment.py, check_live.py, run_vectors.py or any
other implementation, so it is a third checker independent of the two that exist.

Standard library only. keccak-256 and secp256k1 are implemented here because hashlib has
neither (hashlib.sha3_256 is FIPS 202 SHA-3, which pads differently from keccak-256).

  python3 receipt_check.py            run receipt_vectors.json, print one line per vector
  python3 receipt_check.py --live FILE [CANDIDATES]
                                      check one held receipt ({receipt, authorizationSalt, asset}),
                                      default candidates candidates_snapshot_2026-10-23.json

Order of checks, as the text gives it:
  1. the receipt itself (section 5.5): format, payload version selects the EIP-712 types,
     signature, signer authorisation. A receipt that fails here gets no link result.
  2. the link (section 5.6.4), one of: linked, no_match, incomplete, not_attempted,
     malformed, inconsistent.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- keccak-256 (original Keccak padding)

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M64 = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def _keccak_f(a: list) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data) + b"\x01"
    msg += b"\x00" * ((-len(msg)) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        _keccak_f(a)
    out = b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# ---------------------------------------------------------------- secp256k1

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], -1, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def _mul(k: int, pt):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _address(pub) -> str:
    raw = pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
    return "0x" + keccak256(raw)[-20:].hex()


def address_of_key(priv: int) -> str:
    return _address(_mul(priv, G))


def _rfc6979_k(priv: int, z: int) -> int:
    x = priv.to_bytes(32, "big")
    h = (z % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, "big")
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(priv: int, digest: bytes) -> tuple:
    """Deterministic (RFC 6979) secp256k1 signature, low s. Returns (r, s, recovery_id)."""
    z = int.from_bytes(digest, "big")
    k = _rfc6979_k(priv, z)
    R = _mul(k, G)
    r = R[0] % N
    s = pow(k, -1, N) * (z + r * priv) % N
    rec = R[1] & 1
    if s > N // 2:
        s, rec = N - s, rec ^ 1
    return r, s, rec


def recover_address(digest: bytes, r: int, s: int, rec: int) -> str | None:
    if not (1 <= r < N and 1 <= s < N) or rec not in (0, 1):
        return None
    x = r
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != rec:
        y = P - y
    z = int.from_bytes(digest, "big")
    rinv = pow(r, -1, N)
    q = _add(_mul(s * rinv % N, (x, y)), _mul((-z * rinv) % N, G))
    return None if q is None else _address(q)


# ---------------------------------------------------------------- EIP-712 (section 3.2, 5.3)

RECEIPT_FIELDS = {
    1: [("version", "uint256"), ("network", "string"), ("resourceUrl", "string"),
        ("payer", "string"), ("issuedAt", "uint256"), ("transaction", "string")],
}
RECEIPT_FIELDS[2] = RECEIPT_FIELDS[1] + [("authorizationMethod", "string"),
                                         ("authorizationCommitment", "string")]
DOMAIN = {"name": "x402 receipt", "version": "1", "chainId": 1}


def _type_string(name: str, fields: list) -> bytes:
    return (name + "(" + ",".join("%s %s" % (t, n) for n, t in fields) + ")").encode()


def _encode(fields: list, values: dict) -> bytes:
    out = b""
    for name, typ in fields:
        v = values.get(name, "")  # section 5.3: unused optional fields are the empty string
        if typ == "string":
            out += keccak256(v.encode("utf-8"))
        else:
            out += int(v).to_bytes(32, "big")
    return out


def eip712_digest(payload: dict, types_version: int) -> bytes:
    dom_fields = [("name", "string"), ("version", "string"), ("chainId", "uint256")]
    dom = keccak256(keccak256(_type_string("EIP712Domain", dom_fields)) + _encode(dom_fields, DOMAIN))
    fields = RECEIPT_FIELDS[types_version]
    struct = keccak256(keccak256(_type_string("Receipt", fields)) + _encode(fields, payload))
    return keccak256(b"\x19\x01" + dom + struct)


def sign_eip712(priv: int, payload: dict, types_version: int) -> str:
    r, s, rec = sign_digest(priv, eip712_digest(payload, types_version))
    return "0x" + r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex() + "%02x" % (27 + rec)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_jws_es256k(priv: int, payload: dict, kid: str) -> str:
    head = _b64u(json.dumps({"alg": "ES256K", "kid": kid}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    r, s, _ = sign_digest(priv, hashlib.sha256((head + "." + body).encode()).digest())
    return head + "." + body + "." + _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


# ---------------------------------------------------------------- section 5.5: the receipt

def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def check_receipt(receipt: dict, authorized: dict) -> dict:
    """Return {"receipt": "valid", "signer": addr, "payload": {...}} or {"receipt": "rejected", "reason": ...}.

    `authorized` stands in for section 4.5.1, which leaves the mechanism open: a list of signer
    addresses for EIP-712, and a map of kid to signer address for JWS.
    """
    fmt = receipt.get("format")
    if fmt == "eip712":
        payload, sig = receipt.get("payload"), receipt.get("signature", "")
        if not isinstance(payload, dict):
            return {"receipt": "rejected", "reason": "payload_missing"}
        version = payload.get("version")
        if not _is_int(version) or version not in RECEIPT_FIELDS:
            return {"receipt": "rejected", "reason": "unsupported_version"}
        if not _is_int(payload.get("issuedAt")):
            return {"receipt": "rejected", "reason": "payload_field_type"}
        if not (isinstance(sig, str) and sig.startswith("0x") and len(sig) == 132):
            return {"receipt": "rejected", "reason": "signature_encoding"}
        raw = bytes.fromhex(sig[2:])
        r, s, v = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
        rec = v - 27 if v >= 27 else v
        signer = recover_address(eip712_digest(payload, version), r, s, rec)
        if signer is None:
            return {"receipt": "rejected", "reason": "signature_invalid"}
        if signer not in [a.lower() for a in authorized.get("eip712", [])]:
            return {"receipt": "rejected", "reason": "signer_not_authorized", "signer": signer}
        return {"receipt": "valid", "signer": signer, "payload": payload}
    if fmt == "jws":
        if "payload" in receipt:
            return {"receipt": "rejected", "reason": "jws_payload_duplicated"}  # section 3.1.1: MUST be omitted
        parts = receipt.get("signature", "").split(".")
        if len(parts) != 3:
            return {"receipt": "rejected", "reason": "signature_encoding"}
        try:
            head = json.loads(_unb64u(parts[0]))
            payload = json.loads(_unb64u(parts[1]))
            raw = _unb64u(parts[2])
        except (ValueError, json.JSONDecodeError):
            return {"receipt": "rejected", "reason": "signature_encoding"}
        if head.get("alg") != "ES256K" or not head.get("kid") or len(raw) != 64:
            return {"receipt": "rejected", "reason": "unsupported_alg"}
        version = payload.get("version")
        if not _is_int(version) or version not in RECEIPT_FIELDS:
            return {"receipt": "rejected", "reason": "unsupported_version"}
        expected = authorized.get("jws", {}).get(head["kid"])
        if expected is None:
            return {"receipt": "rejected", "reason": "kid_unresolved"}
        digest = hashlib.sha256((parts[0] + "." + parts[1]).encode()).digest()
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        if expected.lower() not in (recover_address(digest, r, s, 0), recover_address(digest, r, s, 1)):
            return {"receipt": "rejected", "reason": "signature_invalid"}
        return {"receipt": "valid", "signer": expected.lower(), "payload": payload}
    return {"receipt": "rejected", "reason": "unsupported_format"}


# ---------------------------------------------------------------- section 5.6: the link

IMPLEMENTED_METHODS = {"eip3009"}
DOMAIN_TAG = b"x402-receipt-authorization/0"


def _hex_bytes(v, n: int) -> bytes | None:
    if not (isinstance(v, str) and v[:2] in ("0x", "0X") and len(v) == 2 + 2 * n):
        return None
    try:
        return bytes.fromhex(v[2:])
    except ValueError:
        return None


def commitment(method: str, asset: bytes, authorizer: bytes, identifier: bytes, salt: bytes) -> str:
    pre = DOMAIN_TAG + b"\x00" + method.encode("ascii") + b"\x00" + asset + authorizer + identifier + salt
    return "0x" + hashlib.sha256(pre).hexdigest()


def link(payload: dict, salt, asset, candidates) -> dict:
    """Section 5.6.4. `candidates` is a list of {"nonce", "tx"} or None when it could not be obtained."""
    if payload.get("version") != 2:
        return {"result": "not_attempted", "detail": "no_commitment"}
    method = payload.get("authorizationMethod", "") or ""
    commit = payload.get("authorizationCommitment", "") or ""
    if (method == "") != (commit == ""):
        return {"result": "malformed", "detail": "one_of_method_and_commitment"}
    if method == "":
        return {"result": "not_attempted", "detail": "no_commitment"}
    if method not in IMPLEMENTED_METHODS:
        return {"result": "not_attempted", "detail": "unsupported_method"}
    if _hex_bytes(commit, 32) is None:
        return {"result": "malformed", "detail": "commitment_encoding"}
    salt_b, asset_b = _hex_bytes(salt, 32), _hex_bytes(asset, 20)
    if salt_b is None:
        return {"result": "not_attempted", "detail": "salt_not_held"}
    if asset_b is None:
        return {"result": "not_attempted", "detail": "asset_not_held"}
    authorizer = _hex_bytes(payload.get("payer"), 20)  # step 1: from the signed payer, never from outside
    if authorizer is None:
        return {"result": "not_attempted", "detail": "payer_not_an_eip3009_authorizer"}
    if candidates is None:
        return {"result": "incomplete", "detail": "candidate_set_unobtainable"}
    matches = []
    for c in candidates:
        nonce = _hex_bytes(c.get("nonce"), 32)
        if nonce is not None and commitment(method, asset_b, authorizer, nonce, salt_b) == commit.lower():
            matches.append(c)
    if len(matches) != 1:
        return {"result": "no_match", "detail": "matches=%d" % len(matches)}
    m = matches[0]
    tx = payload.get("transaction", "") or ""
    if tx and tx.lower() != m["tx"].lower():
        return {"result": "inconsistent", "nonce": m["nonce"], "transaction": m["tx"]}
    return {"result": "linked", "nonce": m["nonce"], "transaction": m["tx"]}


# ---------------------------------------------------------------- runner

def evaluate(vec: dict, snapshot: dict) -> dict:
    rec = check_receipt(vec["receipt"], vec.get("authorized_signers", {}))
    out = {"receipt": rec["receipt"]}
    if rec["receipt"] != "valid":
        out["reason"] = rec["reason"]
        return out
    out["signer"] = rec["signer"]
    held = vec.get("held", {})
    cands = vec.get("candidates")
    if cands == "snapshot":
        cands = snapshot["candidates"]
    elif isinstance(cands, dict) and cands.get("status") == "unobtainable":
        cands = None
    out["link"] = link(rec["payload"], held.get("salt"), held.get("asset"), cands)
    return out


def _matches(expect: dict, got: dict) -> bool:
    for k, v in expect.items():
        if isinstance(v, dict):
            if not isinstance(got.get(k), dict) or not _matches(v, got[k]):
                return False
        elif isinstance(v, str) and isinstance(got.get(k), str):
            if v.lower() != got[k].lower():
                return False
        elif got.get(k) != v:
            return False
    return True


def live(path: str, cand_path: str) -> int:
    """A receipt as a later verifier holds it. Signer authorisation (4.5.1) is out of scope here,
    so the recovered signer is printed for the reader to judge, not accepted on its own."""
    held = json.load(open(path, encoding="utf-8"))
    r = held["receipt"]
    if r.get("format") != "eip712":
        print("only eip712 receipts are supported in --live")
        return 2
    p, raw = r["payload"], bytes.fromhex(r["signature"][2:])
    sig = (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64] - 27 if raw[64] >= 27 else raw[64])
    signer = recover_address(eip712_digest(p, p["version"]), *sig) if p.get("version") in RECEIPT_FIELDS else None
    rec = check_receipt(r, {"eip712": [signer] if signer else []})
    print("receipt %s, signer %s (authorisation not checked)" % (rec["receipt"], signer))
    if rec["receipt"] != "valid":
        return 1
    cands = json.load(open(cand_path, encoding="utf-8"))["candidates"]
    out = link(p, held.get("authorizationSalt"), held.get("asset"), cands)
    print("link %s against %d candidates%s" % (out["result"], len(cands),
          ": nonce %s, settlement tx %s" % (out["nonce"], out["transaction"]) if "nonce" in out else ""))
    return 0 if out["result"] == "linked" else 1


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--live":
        cand = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "candidates_snapshot_2026-10-23.json")
        return live(sys.argv[2], cand)
    vectors = json.load(open(os.path.join(HERE, "receipt_vectors.json"), encoding="utf-8"))
    snapshot = json.load(open(os.path.join(HERE, vectors["candidates_snapshot"]), encoding="utf-8"))
    failed = 0
    for vec in vectors["vectors"]:
        got = evaluate(vec, snapshot)
        ok = _matches(vec["expect"], got)
        failed += not ok
        shown = got.get("link", {}).get("result") or got.get("reason")
        print("%-4s %-44s %s" % ("ok" if ok else "FAIL", vec["id"], shown))
        if not ok:
            print("     expected %s\n     got      %s" % (json.dumps(vec["expect"]), json.dumps(got)))
    n = len(vectors["vectors"])
    print("%d/%d receipt vectors pass" % (n - failed, n))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
