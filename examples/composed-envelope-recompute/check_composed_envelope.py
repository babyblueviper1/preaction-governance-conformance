#!/usr/bin/env python3
"""
check_composed_envelope.py -- N independent signers, ONE artifact.

Recomputes a verification.v0.3+composed envelope entirely from published
bytes: canonicalizes the payload as received (RFC 8785 / JCS), recomputes
the canonical hash, and verifies EVERY signature in the envelope against
a key resolved from that signer's OWN published key set -- three issuers,
three separate JWKS origins, no key carried in the artifact, no call to
any issuer's /verify endpoint.

This is the single-artifact variant of the composed-trust discipline:
the three-party example checks N artifacts with one checker; this checks
N *signers* on one artifact. Same invariant one level down: no signer is
the party being judged, and an examiner can accept one signature while
rejecting another on the same record.

Zero dependencies. The Ed25519 core is vendored below (pure stdlib,
RFC 8032 construction); a second verifier using any correct Ed25519
implementation reaches the same result.

Usage:
    python3 check_composed_envelope.py                 # verify + tamper demo
    python3 check_composed_envelope.py envelope.json   # verify a given envelope
"""

import base64, hashlib, json, sys, os

# ----------------------------------------------------------------------------
# Vendored Ed25519 verify (RFC 8032, pure stdlib). Verification only.
# ----------------------------------------------------------------------------
_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p


def _sha512(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, _p - 2, _p)


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * _inv(_d * y * y + 1) % _p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * pow(2, (_p - 1) // 4, _p) % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_Bx = _recover_x(_By, 0)
_B = (_Bx, _By, 1, _Bx * _By % _p)  # extended coords


def _edwards_add(P, Q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = P, Q
    a = (y1 - x1) * (y2 - x2) % _p
    b = (y1 + x1) * (y2 + x2) % _p
    c = 2 * t1 * t2 * _d % _p
    dd = 2 * z1 * z2 % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _p, g * h % _p, f * g % _p, e * h % _p)


def _scalarmult(P, e):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


def _point_equal(P, Q):
    (x1, y1, z1, _), (x2, y2, z2, _) = P, Q
    return (x1 * z2 - x2 * z1) % _p == 0 and (y1 * z2 - y2 * z1) % _p == 0


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def ed25519_verify(public_key: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    A = _decompress(public_key)
    if A is None:
        return False
    Rs, ss = signature[:32], signature[32:]
    R = _decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(ss, "little")
    if s >= _L:
        return False
    h = int.from_bytes(_sha512(Rs + public_key + msg), "little") % _L
    sB = _scalarmult(_B, s)
    hA = _scalarmult(A, h)
    return _point_equal(sB, _edwards_add(R, hA))


# ----------------------------------------------------------------------------
# Vendored RFC 8785 (JCS) canonicalizer -- strict, with round-trip asserts.
# ----------------------------------------------------------------------------
_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
        "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_string(s):
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_number(x):
    if isinstance(x, bool):  # bool is int subclass; handled by caller
        raise TypeError
    if isinstance(x, int):
        return str(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("non-finite number not allowed in JCS")
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    assert float(r) == x, "round-trip failed for %r" % x
    # Python repr matches ECMAScript shortest-form for these magnitudes;
    # assert no exponent forms sneak in for the value ranges we handle.
    assert "e" not in r and "E" not in r, (
        "exponent-form float %r needs full ES6 serializer; "
        "not present in these fixtures" % x)
    return r


def jcs(obj):
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, (int, float)):
        return _jcs_number(obj)
    if isinstance(obj, list):
        return "[" + ",".join(jcs(v) for v in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(),
                       key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v)
                              for k, v in items) + "}"
    raise TypeError("unsupported type: %r" % type(obj))


# ----------------------------------------------------------------------------
# Envelope verification
# ----------------------------------------------------------------------------
def _b64u_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def load_jwks(directory):
    """kid -> raw 32-byte Ed25519 public key, from all jwks-*.json files."""
    keys = {}
    for fn in sorted(os.listdir(directory)):
        if fn.startswith("jwks-") and fn.endswith(".json"):
            for k in json.load(open(os.path.join(directory, fn)))["keys"]:
                assert k["kty"] == "OKP" and k["crv"] == "Ed25519", fn
                keys[k["kid"]] = (_b64u_decode(k["x"]), fn)
    return keys


def check(envelope_path, jwks_dir, expect_fail=False):
    env = json.load(open(envelope_path))
    payload_b64 = env["payload"]
    payload_bytes = _b64u_decode(payload_b64)

    # 1. canonicalize-as-received: the payload bytes must BE their own JCS.
    #    An unparseable payload fails closed -- it cannot crash the verifier.
    try:
        payload_obj = json.loads(payload_bytes.decode("utf-8"))
        recomputed = jcs(payload_obj).encode("utf-8")
        canon_ok = recomputed == payload_bytes
    except (ValueError, UnicodeDecodeError):
        canon_ok = False
    canonical_sha256 = hashlib.sha256(payload_bytes).hexdigest()

    print("canonical_recomputes : %s" % canon_ok)
    print("canonical_sha256     : sha256-%s" % canonical_sha256)

    # 2. every signature verifies against its signer's OWN published key.
    keys = load_jwks(jwks_dir)
    all_ok = canon_ok
    for sig in env["signatures"]:
        prot_b64 = sig["protected"]
        prot = json.loads(_b64u_decode(prot_b64))
        kid, alg = prot.get("kid"), prot.get("alg")
        signing_input = (prot_b64 + "." + payload_b64).encode("ascii")
        ok = False
        origin = "kid-not-found"
        if alg == "EdDSA" and kid in keys:
            pk, origin = keys[kid]
            ok = ed25519_verify(pk, signing_input, _b64u_decode(sig["signature"]))
        all_ok = all_ok and ok
        print("%-4s -- %-38s key_origin=%s" % ("PASS" if ok else "FAIL", kid, origin))

    verdict = all_ok
    print("envelope             : %s" % ("PASS" if verdict else "FAIL"))
    if expect_fail:
        assert not verdict, "tamper demo unexpectedly PASSED"
    else:
        assert verdict, "envelope failed verification"
    return canonical_sha256


def tamper_demo(envelope_path, jwks_dir):
    """Flip one byte of the payload; every signature must fail."""
    env = json.load(open(envelope_path))
    raw = bytearray(_b64u_decode(env["payload"]))
    raw[-2] ^= 0x01  # flip one bit near the end
    env["payload"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    tampered = envelope_path + ".tampered.tmp"
    json.dump(env, open(tampered, "w"))
    print("\n-- tamper demo: one bit flipped in payload --")
    try:
        check(tampered, jwks_dir, expect_fail=True)
        print("tamper detected      : True (all signatures fail, as they must)")
    finally:
        os.remove(tampered)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    envelope = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        here, "envelope-three-signer.json")
    print("== composed envelope: N signers, one artifact ==")
    check(envelope, here)
    tamper_demo(envelope, here)
    print("\nOK -- every claim above was recomputed, not trusted.")
