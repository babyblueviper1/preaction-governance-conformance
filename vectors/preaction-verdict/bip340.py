"""BIP-340 Schnorr over secp256k1, the reference algorithm in pure Python (stdlib only).
verify() is what a reader needs; sign() exists only so gen.py can build the TEST-ONLY wrong-key case."""
import hashlib

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _th(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None
    if p1 == p2:
        lam = 3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return x, (lam * (p1[0] - x) - p1[1]) % P


def _mul(p, k):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = _add(r, p)
        p = _add(p, p)
    return r


def _lift_x(x):
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return x, y if y % 2 == 0 else P - y


def pubkey(seckey32):
    return _mul(G, int.from_bytes(seckey32, "big"))[0].to_bytes(32, "big")


def verify(msg32, pub32, sig64):
    if len(pub32) != 32 or len(sig64) != 64:
        return False
    pt = _lift_x(int.from_bytes(pub32, "big"))
    r, s = int.from_bytes(sig64[:32], "big"), int.from_bytes(sig64[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(_th("BIP0340/challenge", sig64[:32] + pub32 + msg32), "big") % N
    R = _add(_mul(G, s), _mul(pt, N - e))
    return R is not None and R[1] % 2 == 0 and R[0] == r


def sign(msg32, seckey32, aux32=b"\x00" * 32):
    d0 = int.from_bytes(seckey32, "big")
    Pt = _mul(G, d0)
    d = d0 if Pt[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(_th("BIP0340/aux", aux32), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_th("BIP0340/nonce", t + Pt[0].to_bytes(32, "big") + msg32), "big") % N
    R = _mul(G, k0)
    k = k0 if R[1] % 2 == 0 else N - k0
    e = int.from_bytes(_th("BIP0340/challenge", R[0].to_bytes(32, "big") + Pt[0].to_bytes(32, "big") + msg32), "big") % N
    return R[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")
