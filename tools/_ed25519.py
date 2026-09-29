"""Ed25519 signature VERIFICATION, stdlib only (RFC 8032 section 5.1.7). Verification only: it holds no secret and
never signs. Used by tools/issuer_profile.py for JWS (alg EdDSA) envelopes, so the marker checkers stay pip-free.
Cross-checked against the `cryptography` package in examples/trace-marker-second-issuer-demo/build.py."""
import hashlib

_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _xrecover(y):
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p:
        x = x * _I % _p
    if (x * x - xx) % _p:
        raise ValueError("not on curve")
    return x


_By = 4 * pow(5, _p - 2, _p) % _p
_B = (_xrecover(_By), _By, 1, _xrecover(_By) * _By % _p)
if _B[0] & 1:
    _B = (_p - _B[0], _By, 1, (_p - _B[0]) * _By % _p)


def _add(P, Q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = P, Q
    a = (y1 - x1) * (y2 - x2) % _p
    b = (y1 + x1) * (y2 + x2) % _p
    c = 2 * t1 * t2 * _d % _p
    dd = 2 * z1 * z2 % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _p, g * h % _p, f * g % _p, e * h % _p)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % _p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % _p == 0


def _decode(b):
    if len(b) != 32:
        raise ValueError("point must be 32 bytes")
    y = int.from_bytes(b, "little") & ((1 << 255) - 1)
    if y >= _p:
        raise ValueError("y out of range")
    x = _xrecover(y)
    if (x & 1) != (b[31] >> 7):
        x = _p - x
    if x == 0 and (b[31] >> 7):
        raise ValueError("invalid point")
    return (x, y, 1, x * y % _p)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(signature) != 64:
            return False
        A = _decode(public_key)
        R = _decode(signature[:32])
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
        return _eq(_mul(s, _B), _add(R, _mul(h, A)))
    except Exception:
        return False
