"""Step 9 of the work-acceptance record profile (1.4.1): the time-stamp authority's CMS signature and certificate chain.

Written from the profile README's rule text and RFC 3161 / RFC 5652 / RFC 2634 / RFC 5035 / RFC 5280, without reading the reference
verifier. The CMS structure is walked by the small DER reader below; X.509 parsing and the RSA / RSASSA-PSS / ECDSA arithmetic are
done by the `cryptography` package.

    evaluate(token_der, anchors_der) -> "verified" | "failed" | "untrusted" | "unsupported" | "no_signer" | "not_evaluated"

`anchors_der` empty -> "not_evaluated" (profile 1.4.1: an empty anchor list is no anchors). With several defects the value is
"failed" if any check that can run fails; otherwise "no_signer", then "unsupported", then "untrusted". Revocation is not checked.
"""
import hashlib
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID
    HAVE_CRYPTO = True
except ImportError:            # without the package nothing past the digest checks can run
    HAVE_CRYPTO = False

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"     # ESS SigningCertificate (RFC 2634), SHA-1 cert hash
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"  # ESS SigningCertificateV2 (RFC 5035), hashAlgorithm DEFAULT sha256
OID_RSA = "1.2.840.113549.1.1.1"
OID_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
DIGESTS = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
           "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512"}
RSA_SIGS = {"1.2.840.113549.1.1.5": "sha1", "1.2.840.113549.1.1.14": "sha224", "1.2.840.113549.1.1.11": "sha256",
            "1.2.840.113549.1.1.12": "sha384", "1.2.840.113549.1.1.13": "sha512"}
ECDSA_SIGS = {"1.2.840.10045.4.1": "sha1", "1.2.840.10045.4.3.1": "sha224", "1.2.840.10045.4.3.2": "sha256",
              "1.2.840.10045.4.3.3": "sha384", "1.2.840.10045.4.3.4": "sha512"}
REQUIRED_CURVES = ("secp256r1", "secp384r1")     # P-256 and P-384; any other curve is `unsupported`
_SKIP = set()                                    # used only by tsa_sig_mutations.py to remove one rule at a time


# ---- DER ------------------------------------------------------------------------------------------------------------------------
def tlv(b, i):
    """(tag, content_start, content_end, element_end) of the element starting at b[i]. Definite lengths only (DER)."""
    tag = b[i]
    if tag & 0x1F == 0x1F:
        raise ValueError("multi-byte tags are not used in these structures")
    n = b[i + 1]
    j = i + 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4:
            raise ValueError("indefinite or oversized length")
        n = int.from_bytes(b[j:j + k], "big")
        j += k
    if j + n > len(b):
        raise ValueError("element runs past its container")
    return tag, j, j + n, j + n


def children(b, start, end):
    out, i = [], start
    while i < end:
        t, s, e, nxt = tlv(b, i)
        out.append((t, s, e, i, nxt))
        i = nxt
    return out


def oid(b, s, e):
    v = b[s:e]
    first = v[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    acc = 0
    for x in v[1:]:
        acc = (acc << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(acc))
            acc = 0
    return ".".join(parts)


def alg_id(b, s, e):
    """(oid, parameters-element or None) of an AlgorithmIdentifier."""
    ch = children(b, s, e)
    return oid(b, ch[0][1], ch[0][2]), (ch[1] if len(ch) > 1 else None)


# ---- the token ------------------------------------------------------------------------------------------------------------------
class Token:
    def __init__(self, der):
        b = self.b = der
        _, s, e, _ = tlv(b, 0)
        ci = children(b, s, e)
        if ci and ci[0][0] == 0x30 and len(ci) > 1 and ci[1][0] == 0x30:
            # a TimeStampResp (RFC 3161 2.4.2): PKIStatusInfo, then the timeStampToken ContentInfo
            ci = children(b, ci[1][1], ci[1][2])
        if ci[0][0] != 0x06 or oid(b, ci[0][1], ci[0][2]) != OID_SIGNED_DATA:
            raise ValueError("not CMS SignedData")
        _, s2, e2, _ = tlv(b, ci[1][1])                       # [0] EXPLICIT SignedData
        sd = children(b, s2, e2)
        idx = 2                                                # version, digestAlgorithms
        enc = children(b, sd[idx][1], sd[idx][2]); idx += 1
        self.econtent_type = oid(b, enc[0][1], enc[0][2])
        _, ps, pe, _ = tlv(b, enc[1][1])                       # [0] EXPLICIT OCTET STRING
        self.econtent = b[ps:pe]
        self.certs_der = []
        while idx < len(sd) and sd[idx][0] in (0xA0, 0xA1):  # [0] certificates, [1] crls
            if sd[idx][0] == 0xA0:
                self.certs_der = [b[c[3]:c[4]] for c in children(b, sd[idx][1], sd[idx][2]) if c[0] == 0x30]
            idx += 1
        sis = children(b, sd[idx][1], sd[idx][2])
        self.signer = None
        if sis:
            self.signer = self._signer_info(sis[0])
        self.gen_time = self._gen_time()

    def _signer_info(self, el):
        b = self.b
        f = children(b, el[1], el[2])
        k = 1
        sid = f[k]; k += 1
        if sid[0] == 0x30:                                    # IssuerAndSerialNumber
            sc = children(b, sid[1], sid[2])
            sid_v = ("issuer_serial", b[sc[0][3]:sc[0][4]], int.from_bytes(b[sc[1][1]:sc[1][2]], "big", signed=True))
        else:                                                  # [0] SubjectKeyIdentifier
            sid_v = ("ski", b[sid[1]:sid[2]])
        digest_alg = alg_id(b, f[k][1], f[k][2])[0]; k += 1
        attrs, attrs_der = {}, None
        if f[k][0] == 0xA0:
            attrs_der = b"\x31" + b[f[k][3] + 1:f[k][4]]       # signature covers the SET OF tag, not [0]
            for a in children(b, f[k][1], f[k][2]):
                ac = children(b, a[1], a[2])
                vals = children(b, ac[1][1], ac[1][2])
                attrs.setdefault(oid(b, ac[0][1], ac[0][2]), []).extend(vals)
            k += 1
        sig_alg, sig_params = alg_id(b, f[k][1], f[k][2]); k += 1
        signature = b[f[k][1]:f[k][2]]
        return {"sid": sid_v, "digest_alg": digest_alg, "attrs": attrs, "attrs_der": attrs_der, "sig_alg": sig_alg,
                "sig_params": sig_params, "signature": signature}

    def _gen_time(self):
        b = self.econtent
        _, s, e, _ = tlv(b, 0)
        for t, cs, ce, _, _ in children(b, s, e):
            if t == 0x18:                                     # GeneralizedTime
                txt = b[cs:ce].decode("ascii").rstrip("Z")
                whole = txt.split(".")[0]
                return datetime.strptime(whole, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        raise ValueError("TSTInfo has no genTime")

    def attr_value(self, attr_oid):
        v = (self.signer or {}).get("attrs", {}).get(attr_oid)
        return v[0] if v else None


# ---- checks ---------------------------------------------------------------------------------------------------------------------
def _utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _valid_at(cert, t):
    nb = getattr(cert, "not_valid_before_utc", None) or _utc(cert.not_valid_before)
    na = getattr(cert, "not_valid_after_utc", None) or _utc(cert.not_valid_after)
    return nb <= t <= na


def _hash(name):
    return {"sha1": hashes.SHA1, "sha224": hashes.SHA224, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[name]()


def _find_signer_cert(tok, certs):
    sid = tok.signer["sid"]
    for c in certs:
        if sid[0] == "issuer_serial":
            if c.issuer.public_bytes() == sid[1] and c.serial_number == sid[2]:
                return c
        else:
            try:
                ski = c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid[1]:
                return c
    return None


def _ess_binding(tok, cert_der):
    """True / False if an ESS signing-certificate attribute is present and checked; None if absent (absence is a failure: RFC 3161
    requires the attribute)."""
    b = tok.b
    for attr_oid, v2 in ((OID_SIGNING_CERT_V2, True), (OID_SIGNING_CERT, False)):
        el = tok.attr_value(attr_oid)
        if el is None:
            continue
        certs_seq = children(b, el[1], el[2])[0]
        first = children(b, certs_seq[1], certs_seq[2])[0]
        f = children(b, first[1], first[2])
        alg = "sha1"
        if v2:
            if f[0][0] == 0x30:                              # hashAlgorithm present
                alg = DIGESTS.get(alg_id(b, f[0][1], f[0][2])[0])
                f = f[1:]
            else:
                alg = "sha256"
        if alg is None:
            return False
        want = b[f[0][1]:f[0][2]]
        return hashlib.new(alg, cert_der).digest() == want
    return None


def _signature_ok(tok, cert):
    """True / False, or "unsupported"."""
    s = tok.signer
    pub = cert.public_key()
    data, sig, alg = s["attrs_der"], s["signature"], s["sig_alg"]
    if data is None:
        return False                                          # a TST signature must cover signed attributes (RFC 3161 2.4.2)
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            if alg == OID_PSS:
                h, mgf_h, salt = _pss_params(tok.b, s["sig_params"])
                if h is None:
                    return "unsupported"
                pub.verify(sig, data, padding.PSS(mgf=padding.MGF1(_hash(mgf_h)), salt_length=salt), _hash(h))
                return True
            h = RSA_SIGS.get(alg) or (DIGESTS.get(s["digest_alg"]) if alg == OID_RSA else None)
            if h is None:
                return "unsupported"
            pub.verify(sig, data, padding.PKCS1v15(), _hash(h))
            return True
        if isinstance(pub, ec.EllipticCurvePublicKey):
            if pub.curve.name not in REQUIRED_CURVES:
                return "unsupported"
            h = ECDSA_SIGS.get(alg)
            if h is None:
                return "unsupported"
            pub.verify(sig, data, ec.ECDSA(_hash(h)))
            return True
    except InvalidSignature:
        return False
    return "unsupported"


def _pss_params(b, params):
    h, mgf_h, salt = "sha1", "sha1", 20                       # RFC 4055 defaults
    if params is None or params[0] != 0x30:
        return h, mgf_h, salt
    for t, s, e, _, _ in children(b, params[1], params[2]):
        inner = children(b, s, e)[0]
        if t == 0xA0:
            h = DIGESTS.get(alg_id(b, inner[1], inner[2])[0])
        elif t == 0xA1:
            mo, mp = alg_id(b, inner[1], inner[2])
            if mo != OID_MGF1 or mp is None:
                return None, None, None
            mgf_h = DIGESTS.get(alg_id(b, mp[1], mp[2])[0])
        elif t == 0xA2:
            salt = int.from_bytes(b[inner[1]:inner[2]], "big")
    if h is None or mgf_h is None:
        return None, None, None
    return h, mgf_h, salt


def _same_cert(a, b):
    return a.public_bytes(serialization_der()) == b.public_bytes(serialization_der())


def _spki(c):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return c.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _is_anchor(c, anchors):
    """A trust anchor is a name and a key (RFC 5280 6.1.1), not one certificate: a cross-signed copy of the anchor's certificate
    inside the token (DigiCert's Trusted Root G4, issued by Assured ID Root CA) is the anchor. A self-signed root inside the token
    with a different key or name is not."""
    return any(c.subject == a.subject and _spki(c) == _spki(a) for a in anchors)


def serialization_der():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.DER


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _chain(signer, pool, anchors, t, failures):
    """True if a chain of CA issuers reaches an anchor; False if none does (untrusted). Appends to `failures` when a link that leads
    to an anchor fails a check (an issuer not valid at genTime, a non-CA issuer, a bad link signature)."""
    cur, seen = signer, set()
    while True:
        if _is_anchor(cur, anchors):
            return True
        key = cur.fingerprint(hashes.SHA256())
        if key in seen:
            return False
        seen.add(key)
        issuers = [c for c in pool + anchors if c.subject == cur.issuer and not _same_cert(c, cur)]
        nxt = None
        for c in issuers:
            try:
                cur.verify_directly_issued_by(c)
            except (InvalidSignature, ValueError, TypeError):
                continue
            nxt = c
            break
        if nxt is None:
            if issuers and _reaches_anchor(issuers, pool, anchors):
                failures.append("chain link signature")        # the anchor is reachable by name, but the link does not verify
            return False
        is_anchor = _is_anchor(nxt, anchors)
        if not is_anchor:
            if not _valid_at(nxt, t):
                if _reaches_anchor([nxt], pool, anchors):
                    failures.append("issuer not valid at genTime")
            if not _is_ca(nxt):
                if _reaches_anchor([nxt], pool, anchors):
                    failures.append("issuer is not a CA")
        cur = nxt


def _reaches_anchor(start, pool, anchors, depth=8):
    """Name-level reachability of an anchor (no signature checks): decides whether a defect lies on a chain to an anchor
    (`failed`) or on a chain to nowhere the relying party trusts (`untrusted`)."""
    frontier, seen = list(start), set()
    for _ in range(depth):
        nxt = []
        for c in frontier:
            if _is_anchor(c, anchors) or any(c.issuer == a.subject for a in anchors):
                return True
            fp = c.fingerprint(hashes.SHA256())
            if fp in seen:
                continue
            seen.add(fp)
            nxt += [p for p in pool if p.subject == c.issuer and not _same_cert(p, c)]
        frontier = nxt
        if not frontier:
            return False
    return False


def evaluate(token_der, anchors_der):
    if not anchors_der:
        return "not_evaluated"
    try:
        tok = Token(token_der)
    except (ValueError, IndexError):
        return "failed"
    if tok.signer is None:
        return "no_signer"
    failures, no_signer, unsupported, untrusted = [], False, False, False
    s = tok.signer
    # contentType signed attribute equals eContentType, which is id-ct-TSTInfo (RFC 5652 5.3; RFC 3161 2.4.2)
    ct = tok.attr_value(OID_CONTENT_TYPE)
    if "contentType" not in _SKIP and (tok.econtent_type != OID_TSTINFO or ct is None or oid(tok.b, ct[1], ct[2]) != tok.econtent_type):
        failures.append("contentType")
    # messageDigest over eContent with the SignerInfo digest algorithm
    md, dname = tok.attr_value(OID_MESSAGE_DIGEST), DIGESTS.get(s["digest_alg"])
    if "messageDigest" not in _SKIP and (md is None or dname is None or hashlib.new(dname, tok.econtent).digest() != tok.b[md[1]:md[2]]):
        failures.append("messageDigest")
    if not HAVE_CRYPTO:
        return "failed" if failures else "unsupported"
    certs = [x509.load_der_x509_certificate(c) for c in tok.certs_der]
    anchors = [x509.load_der_x509_certificate(a) for a in anchors_der]
    signer = _find_signer_cert(tok, certs)
    if signer is None:
        no_signer = True
    else:
        der = signer.public_bytes(serialization_der())
        ess = _ess_binding(tok, der)
        if ess is not True:
            failures.append("ESS signing-certificate")
        ok = _signature_ok(tok, signer)
        if ok == "unsupported":
            unsupported = True
        elif not ok:
            failures.append("signature")
        try:
            eku = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
                failures.append("id-kp-timeStamping")
        except x509.ExtensionNotFound:
            failures.append("id-kp-timeStamping")
        reached = _chain(signer, certs, anchors, tok.gen_time, failures)
        if not _valid_at(signer, tok.gen_time) and (reached or _reaches_anchor([signer], certs, anchors)):
            failures.append("signer not valid at genTime")
        if not reached:
            untrusted = True
    if failures:
        return "failed"
    if no_signer:
        return "no_signer"
    if unsupported:
        return "unsupported"
    if untrusted:
        return "untrusted"
    return "verified"
