#!/usr/bin/env python3
"""
check_sequence_integrity.py -- N artifacts over TIME: sequence integrity.

The composed-envelope example (this suite) proves N signers on one artifact.
This example proves the next layer: N artifacts in an append-only SEQUENCE --
that nothing was reordered and nothing was dropped between two signed tree
heads, and that every entry is provably included under the newer head.

Everything recomputes from committed bytes:

  1. each entry is a real composed envelope (2 or 3 independent signers) --
     canonical bytes recompute, every signature verifies against its issuer's
     own published JWKS (same discipline as the composed-envelope example)
  2. leaf hashes recompute from the log's leaf payloads (JCS -> sha256 with
     0x00 domain separation), and each leaf payload's envelope_hash matches
     the entry it claims to commit
  3. both Signed Tree Heads recompute: Merkle construction per
     verification.v0.4 rev-1 §3.3 -- H(0x00||leaf), H(0x01||l||r),
     odd-node promotion -- and each STH's Ed25519 signature verifies
     against the log's published key
  4. every inclusion proof (§3.3 format: ordered leaf-to-root
     {sibling, position}) recomputes from its leaf to STH_2's root
  5. consistency: STH_1 (size 4) and STH_2 (size 7) are roots over the SAME
     ordered prefix -- recomputed from the leaves directly. At this scale the
     full-leaf replay IS the consistency argument, stated plainly; succinct
     RFC 6962-style consistency proofs are the production form for logs too
     large to replay, and change nothing about what is being proven.

Then two tamper demos:
  reorder -- swap entries 2 and 3 -> STH_1 and STH_2 roots both fail
  drop    -- remove entry 5       -> tree size mismatch AND every surviving
             inclusion proof after the gap fails

No network, no dependencies beyond the Python standard library. The Ed25519
and JCS cores are vendored below (same code as the composed-envelope example).

Fixture provenance: entries are the seven published accept vectors of the
verification.v0.3 composed conformance suite (fixture-suite keys, stated
plainly, not production keys). The log key is a fixture key published in
log/jwks-log.json. Independently reimplemented byte-identical:
giskard09/argentum-core PR #33.

Usage: python3 check_sequence_integrity.py
"""

import base64, hashlib, json, os, sys

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
# Sequence verification
# ----------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))

def b64u_d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def leaf_hash(b): return hashlib.sha256(b"\x00" + b).digest()
def node_hash(l, r): return hashlib.sha256(b"\x01" + l + r).digest()

def build_root(leaves):
    cur = list(leaves)
    while len(cur) > 1:
        nxt = [node_hash(cur[i], cur[i+1]) for i in range(0, len(cur)-1, 2)]
        if len(cur) % 2 == 1:
            nxt.append(cur[-1])            # §3.3 odd-node promotion
        cur = nxt
    return cur[0]

def load_jwks(path):
    keys = {}
    for k in json.load(open(path))["keys"]:
        assert k["kty"] == "OKP" and k["crv"] == "Ed25519"
        keys[k["kid"]] = b64u_d(k["x"])
    return keys

def verify_envelope(path, issuer_keys):
    env = json.load(open(path))
    pb = b64u_d(env["payload"])
    obj = json.loads(pb.decode("utf-8"))
    canon_ok = jcs(obj).encode() == pb
    sig_ok = True
    kids = []
    for s in env["signatures"]:
        prot = json.loads(b64u_d(s["protected"]))
        kid = prot.get("kid"); kids.append(kid)
        si = (s["protected"] + "." + env["payload"]).encode("ascii")
        ok = (prot.get("alg") == "EdDSA" and kid in issuer_keys and
              ed25519_verify(issuer_keys[kid], si, b64u_d(s["signature"])))
        sig_ok = sig_ok and ok
    return canon_ok and sig_ok, hashlib.sha256(pb).hexdigest(), len(env["signatures"])

def verify_sth(sth, log_keys):
    pb = jcs(sth["payload"]).encode()
    return (sth["kid"] in log_keys and
            ed25519_verify(log_keys[sth["kid"]], pb, b64u_d(sth["signature"])))

def apply_inclusion(leaf, proof):
    h = leaf
    for step in proof:
        sib = bytes.fromhex(step["sibling"])
        h = node_hash(h, sib) if step["position"] == "right" else node_hash(sib, h)
    return h

def run(leaf_payloads, entries_dir, label="", expect_fail=False):
    issuer_keys = {}
    for fn in ("jwks-agentoracle.json", "jwks-agenttrust.json", "jwks-presidio.json"):
        issuer_keys.update(load_jwks(os.path.join(HERE, fn)))
    log_keys = load_jwks(os.path.join(HERE, "log", "jwks-log.json"))
    sth1 = json.load(open(os.path.join(HERE, "log", "sth-1.json")))
    sth2 = json.load(open(os.path.join(HERE, "log", "sth-2.json")))
    proofs = json.load(open(os.path.join(HERE, "log", "inclusion-proofs.json")))

    ok = True
    # 1+2: entries verify; leaf payloads commit to the right envelopes
    leaves = []
    for n, lp in enumerate(leaf_payloads, 1):
        ep = os.path.join(entries_dir, "entry-%03d.json" % n)
        if os.path.exists(ep):
            env_ok, env_hash, nsig = verify_envelope(ep, issuer_keys)
            match = lp["envelope_hash"] == "sha256-" + env_hash
            print("entry %d: envelope %-4s (%d signers)  leaf-commit %s" %
                  (n, "PASS" if env_ok else "FAIL", nsig, match))
            ok = ok and env_ok and match
        leaves.append(leaf_hash(jcs(lp).encode()))

    # 3: STH signatures + recomputed roots
    s1_sig = verify_sth(sth1, log_keys); s2_sig = verify_sth(sth2, log_keys)
    size1 = sth1["payload"]["tree_size"]; size2 = sth2["payload"]["tree_size"]
    r1_ok = (len(leaves) >= size1 and
             build_root(leaves[:size1]).hex() == sth1["payload"]["root_hash"])
    r2_ok = (len(leaves) == size2 and
             build_root(leaves).hex() == sth2["payload"]["root_hash"])
    print("STH_1 (size %d): signature %s  root-recompute %s" %
          (size1, s1_sig, r1_ok))
    print("STH_2 (size %d): signature %s  root-recompute %s" %
          (size2, s2_sig, r2_ok))
    ok = ok and s1_sig and s2_sig and r1_ok and r2_ok

    # 4: inclusion proofs under STH_2
    inc_all = True
    for idx in sorted(proofs, key=int):
        i = int(idx) - 1
        got = (i < len(leaves) and
               apply_inclusion(leaves[i], proofs[idx]).hex()
               == sth2["payload"]["root_hash"])
        inc_all = inc_all and got
    print("inclusion proofs 1..%d under STH_2: %s" %
          (len(proofs), "ALL PASS" if inc_all else "FAIL"))
    ok = ok and inc_all

    # 5: consistency -- same ordered prefix under both heads
    cons = r1_ok and r2_ok
    print("consistency STH_1 -> STH_2 (append-only prefix): %s" % cons)

    verdict = ok and cons
    print("%ssequence: %s" % (label, "PASS" if verdict else "FAIL"))
    if expect_fail:
        assert not verdict, "tamper demo unexpectedly passed"
    else:
        assert verdict, "sequence verification failed"
    return verdict

if __name__ == "__main__":
    lp = json.load(open(os.path.join(HERE, "log", "leaves.json")))
    ed = os.path.join(HERE, "entries")
    print("== sequence integrity: N artifacts over time ==")
    run(lp, ed)

    print()
    print("-- tamper demo 1: entries 2 and 3 REORDERED --")
    swapped = list(lp); swapped[1], swapped[2] = swapped[2], swapped[1]
    run(swapped, ed, expect_fail=True)
    print("reorder detected: True (both tree heads fail to recompute)")

    print()
    print("-- tamper demo 2: entry 5 DROPPED --")
    dropped = lp[:4] + lp[5:]
    run(dropped, ed, expect_fail=True)
    print("drop detected: True (size mismatch + downstream inclusion fails)")

    print()
    print("OK -- ordering and completeness recomputed, not asserted.")
