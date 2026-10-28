"""Clean-room verifier for the work-acceptance record (trilatic.acceptance-receipt/1.2, profile 1.4.2 since 2026-10-28), first written from the README of
maximusrufus/work-acceptance-record @ d78865c alone, updated to the 1.2.1 README @ f7d8984 and to profile 1.3 @ 270e9fe (draft, CC0). Standard library only; Ed25519 from ../x402-receipt-private-opening.

    python3 war_check.py <vector.json>...      # prints our result next to the vector's `expected`, field by field

Where the README is silent this checker says what it assumed (ASSUMED below) instead of copying a vector.
"""
import base64
import hashlib
import importlib.util
import json, math, re, calendar, datetime
from fractions import Fraction
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tsa_sig as _TSA

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("x402_ed25519_ref", os.path.join(_HERE, "..", "x402-receipt-private-opening",
                                                                              "ed25519_ref.py"))
ed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ed)

SCHEMAS = {"trilatic.acceptance-receipt/1.2"}
RESULTS = {"pass", "fail", "not-evaluated", "error"}
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
REF_RULE = os.environ.get("WAR_REF_RULE", "earlier")   # "1.2.1" = profile as written; see step 5


# ---- profile 1.4.2 (README step 10 @ cb7e8f1): canonical base64, strict time forms, millisecond rounding ----
_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_GEN = re.compile(r"(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d*[1-9]))?Z")
_RFC = re.compile(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z")   # ASSUMED: "[.fff]" = 1 to 3 digits


def b64c(v):
    """1.4.2 canonical base64: standard alphabet, '=' padding to a multiple of four, no whitespace, and re-encoding the decoded bytes
    gives the input string. Anything else -> None (the caller turns it into SIGNATURE_INVALID / KEY_REJECTED / a mismatch)."""
    if not isinstance(v, str) or len(v) % 4 or not _B64.fullmatch(v):
        return None
    try:
        b = base64.b64decode(v, validate=True)
    except (ValueError, TypeError):
        return None
    return b if base64.b64encode(b).decode() == v else None


def _cal(m):
    """real calendar fields -> exact seconds since the epoch as a Fraction, or None (month 13, 30 February, ...)."""
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    try:
        datetime.datetime(y, mo, d, h, mi, se)
    except ValueError:
        return None
    f = m.groups()[6]
    return Fraction(calendar.timegm((y, mo, d, h, mi, se))) + (Fraction(int(f), 10 ** len(f)) if f else 0)


def gen_time(g):
    """1.4.2: DER GeneralizedTime in UTC, YYYYMMDDHHMMSS[.digits not ending in 0]Z with real calendar fields, else None (no usable time)."""
    m = _GEN.fullmatch(g) if isinstance(g, str) else None
    return _cal(m) if m else None


def rfc_time(t):
    """1.4.2: stated times are RFC 3339 UTC YYYY-MM-DDTHH:MM:SS[.fff]Z, else None (RECEIPT_TIME_UNREADABLE where step 5 uses it)."""
    m = _RFC.fullmatch(t) if isinstance(t, str) else None
    return _cal(m) if m else None


def _ms_up(x):
    return math.ceil(x * 1000)


def _ms_down(x):
    return math.floor(x * 1000)


def _types_ok(inputs):
    """1.4.2 'Types': objects, arrays and strings of the types the specification gives, else the record is refused (77)."""
    try:
        rec = inputs["receipt"]; r = rec["receipt"]
        ok = isinstance(rec, dict) and isinstance(r, dict) and isinstance(rec.get("signature"), dict)
        ok &= all(isinstance(rec["signature"].get(k), str) for k in ("value", "key_id"))
        ok &= isinstance(r.get("key_id"), str) and isinstance(r.get("issued_utc"), str)
        ok &= isinstance(r.get("parties"), dict) and isinstance(r["parties"].get("checker"), dict)
        ok &= r["parties"].get("producer") is None or isinstance(r["parties"]["producer"], dict)
        for party in (r["parties"].get("checker") or {}, r["parties"].get("producer") or {}):
            ok &= all(party.get(k) is None or isinstance(party.get(k), str) for k in ("name", "key_id"))
        ok &= isinstance(r.get("criteria"), dict) and isinstance(r["criteria"].get("sha256"), str)
        ok &= r["criteria"].get("committed_at") is None or isinstance(r["criteria"]["committed_at"], str)
        ok &= isinstance(r.get("results"), list) and all(isinstance(x, dict) and isinstance(x.get("id"), str) and
                                                          isinstance(x.get("result"), str) for x in r["results"])
        ok &= isinstance(inputs.get("keys"), dict) and isinstance(inputs["keys"].get("keys"), list)
        ok &= all(isinstance(k, dict) and isinstance(k.get("key_id"), str) and isinstance(k.get("public_key_base64"), str)
                  for k in inputs["keys"]["keys"])
        return bool(ok)
    except (KeyError, TypeError, AttributeError):
        return False


def key_ok(pub):
    """Profile 1.3 step 2 key rule: a canonical encoding (y < p) of a point of prime order L. The neutral point, small-order and
    mixed-order points and non-canonical encodings are refused (KEY_REJECTED) before any signature check. RFC 8032 does not require
    this and the bare verification equation accepts R = neutral, S = 0 under a neutral-point key for any message (vector 26)."""
    if len(pub) != 32 or (int.from_bytes(pub, "little") & ((1 << 255) - 1)) >= ed.p:
        return False
    P = ed._decompress(pub)
    O = (0, 1, 1, 0)
    return P is not None and not ed._equal(P, O) and ed._equal(ed._mul(ed.L, P), O)


# 2026-10-22: full RFC 8785 -- ECMAScript Number::toString for non-integer numbers (upstream vector 52: Python repr gives 1e-05 /
# 1e-07 / 1.2345678901234568e+20, RFC 8785 wants 0.00001 / 1e-7 / 123456789012345680000) and keys sorted by UTF-16 code units.
# Checked against node JSON.stringify on 89,980 doubles (0 mismatches); the 14 records issued so far are byte-identical.

def es_number(x):
    """RFC 8785 sec 3.2.2.3: an IEEE 754 double serialized as ECMAScript Number::toString does (shortest round-trip digits)."""
    if isinstance(x, bool):
        raise TypeError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > 2 ** 53:
            x = float(x)
        else:
            return str(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN/Infinity are not JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))                      # shortest round-trip digits
    if "e" in r:
        mant, ex = r.split("e"); ex = int(ex)
    else:
        mant, ex = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    if fp == "0":
        fp = ""
    digits = (ip + fp).lstrip("0")
    lead = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) - lead + ex                  # value = 0.digits x 10^n
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s

def jcs(v):
    """RFC 8785 JSON Canonicalization Scheme: keys sorted by UTF-16 code units, ECMAScript number form, JSON.stringify string escaping."""
    def enc(o):
        if o is None: return "null"
        if o is True: return "true"
        if o is False: return "false"
        if isinstance(o, (int, float)): return es_number(o)
        if isinstance(o, str): return json.dumps(o, ensure_ascii=False)
        if isinstance(o, (list, tuple)): return "[" + ",".join(enc(x) for x in o) + "]"
        if isinstance(o, dict):
            ks = sorted(o, key=lambda s: s.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(o[k]) for k in ks) + "}"
        raise TypeError(type(o))
    return enc(v).encode("utf-8")



# --- minimal DER reader: enough to read TSTInfo.messageImprint and genTime from an RFC 3161 response or token ---
def _tlv(b, i):
    tag, i = b[i], i + 1
    ln = b[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln, i = int.from_bytes(b[i:i + n], "big"), i + n
    return tag, b[i:i + ln], i + ln


def _children(b):
    out, i = [], 0
    while i < len(b):
        t, v, i = _tlv(b, i)
        out.append((t, v))
    return out


def _oid(v):
    parts, n = [], 0
    for x in v:
        n = (n << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(n)
            n = 0
    first = parts[0]
    return ".".join(map(str, [min(first // 40, 2), first - 40 * min(first // 40, 2)] + parts[1:]))


def _find_tstinfo(b):
    """Depth-first: the OCTET STRING that follows the id-ct-TSTInfo OID in an encapContentInfo."""
    stack = [b]
    while stack:
        cur = stack.pop()
        try:
            kids = _children(cur)
        except IndexError:
            continue
        for k, (t, v) in enumerate(kids):
            if t == 0x06 and _oid(v) == OID_TSTINFO and k + 1 < len(kids):
                t2, v2 = kids[k + 1]
                if t2 == 0xA0:                       # [0] EXPLICIT eContent
                    return _children(v2)[0][1]
            if t in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3) or (t == 0x04 and v[:1] == b"\x30"):
                stack.append(v)
    return None


def tst(token_b64):
    """(hash_oid, imprint_hex, gen_time 'YYYYMMDDHHMMSS[.fff]Z', accuracy_seconds) from an RFC 3161 TimeStampResp/token, or None.
    accuracy_seconds is 0.0 when the token states no accuracy (1.3: taken at its genTime)."""
    if not token_b64:
        return None
    raw = b64c(token_b64)
    if raw is None:
        return "noncanonical"          # 1.4.2: a token that is not canonical base64 matches nothing
    info = _find_tstinfo(raw)
    if info is None:
        return None
    f = _children(info)
    if len(f) == 1 and f[0][0] == 0x30:              # eContent holds the DER TSTInfo SEQUENCE: step inside it
        f = _children(f[0][1])
    mi = _children(f[2][1])
    alg = _oid(_children(mi[0][1])[0][1])
    gi = next(k for k, (t, v) in enumerate(f) if t == 0x18)
    gen = f[gi][1].decode("latin-1")
    acc = Fraction(0)
    # RFC 3161: Accuracy ::= SEQUENCE { seconds INTEGER OPTIONAL, millis [0] INTEGER OPTIONAL, micros [1] INTEGER OPTIONAL },
    # the optional field right after genTime (ordering, nonce, tsa and extensions are not SEQUENCEs).
    if gi + 1 < len(f) and f[gi + 1][0] == 0x30:
        for t, v in _children(f[gi + 1][1]):
            n = int.from_bytes(v, "big")
            acc += {0x02: Fraction(1), 0x80: Fraction(1, 1000), 0x81: Fraction(1, 10 ** 6)}.get(t, Fraction(0)) * n
    return alg, mi[1][1].hex(), gen, acc


def _secs(t):
    """'2026-03-01T00:00:00.5Z' or '20260301000000.5Z' -> seconds since the epoch (UTC), fractions kept."""
    import calendar
    d = "".join(c for c in t if c.isdigit() or c == ".")
    whole, _, frac = d.partition(".")
    whole = whole.replace(".", "")[:14]
    base = calendar.timegm((int(whole[0:4]), int(whole[4:6]), int(whole[6:8]), int(whole[8:10]), int(whole[10:12]), int(whole[12:14])))
    return base + (float("0." + frac) if frac else 0.0)


def _iso(t):
    """'2026-03-01T00:00:00Z' or '20260301000000Z' -> comparable 'YYYYMMDDHHMMSS'."""
    return "".join(c for c in t if c.isdigit())[:14]


def check(inputs):
    """Profile 1.4.2 (README @ cb7e8f1); written for 1.2.1 (f7d8984) and kept through 1.3 / 1.4 / 1.4.1. Step numbers are the README's."""
    if not _types_ok(inputs):                               # 1.4.2 'Types' (77): refused, never a verifier failure
        return {"refused": True, "reason": "unknown schema, canonicalization or suite"}
    rec = inputs["receipt"]
    r = rec["receipt"]
    out = {"problem_codes": [], "warning_codes": []}
    P = lambda c: c in out["problem_codes"] or out["problem_codes"].append(c)
    W = lambda c: c in out["warning_codes"] or out["warning_codes"].append(c)
    # step 1
    if r.get("schema") not in SCHEMAS or r.get("canonicalization") != "JCS-RFC8785" or \
            r.get("suite") != {"digest": "sha-256", "signature": "Ed25519"}:
        return {"refused": True, "reason": "unknown schema, canonicalization or suite"}
    # step 2. 1.4.2: keys are read as canonical base64 only and compared as decoded bytes; a key_id listed more than once is
    # KEY_REJECTED whichever entry comes first; if it is the signing key's, no signature check is run (75, 79).
    klist = inputs["keys"]["keys"]
    ids = [k["key_id"] for k in klist]
    dup = {i for i in ids if ids.count(i) > 1}
    dec = {}
    for k in klist:
        dec.setdefault(k["key_id"], b64c(k["public_key_base64"]))
    if dup:
        P("KEY_REJECTED")
    skid = r.get("key_id")
    if skid in dup or (skid in dec and dec[skid] is None):
        out["signature_valid"] = False                      # 1.4.2: repeated or non-canonical signing key -> no signature check
        P("KEY_REJECTED")
    elif dec.get(skid) is not None and not key_ok(dec[skid]):
        out["signature_valid"] = False                      # 1.3 key rule (26, 27)
        P("KEY_REJECTED")
    else:
        pub, sig = dec.get(skid), b64c(rec["signature"]["value"])   # 1.4.2: a non-canonical signature value is SIGNATURE_INVALID (60-63)
        out["signature_valid"] = bool(pub) and sig is not None and len(sig) == 64 and \
            rec["signature"].get("key_id") == skid and ed.verify(pub, jcs(r), sig)
        if not out["signature_valid"]:
            P("SIGNATURE_INVALID")
    checker, producer = r["parties"]["checker"], r["parties"].get("producer") or {}
    # 1.4.2 'Checker is the signer': the checker's key_id against the SIGNED key_id, never the unsigned envelope's (64, 86)
    if out["signature_valid"] and checker.get("key_id") != skid:
        P("CHECKER_NOT_SIGNER")
    # step 4: criteria document hash (1.4.2: a criteria file that is not canonical base64 matches nothing, 89), then results
    if inputs.get("criteria_file_base64"):
        cb = b64c(inputs["criteria_file_base64"])
        out["criteria_hash"] = "match" if cb is not None and hashlib.sha256(cb).hexdigest() == r["criteria"]["sha256"] else "mismatch"
    else:
        cb, out["criteria_hash"] = None, "absent"
    if out["criteria_hash"] == "mismatch":
        P("CRITERIA_HASH_MISMATCH")
    elif out["criteria_hash"] == "match":
        try:
            doc = json.loads(cb)
            crit = {c["id"]: bool(c.get("required")) for c in doc["criteria"]}
        except (ValueError, KeyError, TypeError):
            crit = None                                     # ASSUMED: an unreadable criteria document cannot correspond
        got = {x["id"]: bool(x.get("required")) for x in r["results"]}
        if got != crit:                                     # ASSUMED: same ids, same required flags, one result each
            P("CRITERIA_RESULTS_MISMATCH")
    # step 6 (needed by step 5's reference time): the record's own token. 1.4.2: not canonical base64 -> imprint_mismatch.
    rt = tst(inputs.get("receipt_tsr_base64"))
    if rt is None:
        out["receipt_timestamp"] = "none"
    elif rt == "noncanonical":
        out["receipt_timestamp"] = "imprint_mismatch"
    else:
        out["receipt_timestamp"] = "imprint_match" if rt[0] == OID_SHA256 and rt[1] == hashlib.sha256(jcs(r)).hexdigest() else "imprint_mismatch"
    ct = tst(inputs.get("criteria_tsr_base64"))
    # step 9 (profile 1.4 / 1.4.1): the authority's CMS signature and chain, one key per token present, against the relying party's
    # anchors (inputs.tsa_roots_base64). No anchors, or an empty list, is `not_evaluated`. Written from the README (tsa_sig.py).
    _anchors = [base64.b64decode(a) for a in (inputs.get("tsa_roots_base64") or [])]
    _tsa = {}
    for _k, _tok in (("criteria", inputs.get("criteria_tsr_base64")), ("receipt", inputs.get("receipt_tsr_base64"))):
        if _tok:
            _raw = b64c(_tok)
            # ASSUMED (1.4.2 is silent): a token that is not canonical base64 has no signature to check -> not_evaluated without
            # anchors (as every other token), `failed` with anchors
            _tsa[_k] = _TSA.evaluate(_raw, _anchors) if _raw is not None else ("failed" if _anchors else "not_evaluated")
    out["tsa_signature"] = _tsa
    # step 5: criteria commitment. A USABLE token: canonical, SHA-256 imprint equal to criteria.sha256, and (1.4.2) a genTime of the
    # DER GeneralizedTime form with real calendar fields. Imprint over other bytes (or non-canonical base64) is
    # CRITERIA_TIMESTAMP_MISMATCH; a matching imprint whose genTime is not usable is treated as no token (70-74, 78): both fall back
    # to committed_at with CRITERIA_COMMITMENT_UNVERIFIED.
    unreadable = False
    usable = ct is not None and ct != "noncanonical" and ct[0] == OID_SHA256 and ct[1] == r["criteria"]["sha256"] and gen_time(ct[2]) is not None
    if usable:
        tc = gen_time(ct[2])
        crit_ms = _ms_up(tc + ct[3])                        # 1.4.2: criteria time to the millisecond, rounded UP (66, 68)
        stated = rfc_time(r["criteria"].get("committed_at"))
        # 1.4.2: with a usable token, a committed_at in another form is CRITERIA_TIME_MISMATCH (88); a readable one is compared
        # to the second, as in 1.2-1.4.1 (ASSUMED: unchanged)
        if stated is None or math.floor(stated) != math.floor(tc):
            P("CRITERIA_TIME_MISMATCH")
    else:
        if ct is not None and (ct == "noncanonical" or not (ct[0] == OID_SHA256 and ct[1] == r["criteria"]["sha256"])):
            P("CRITERIA_TIMESTAMP_MISMATCH")
        W("CRITERIA_COMMITMENT_UNVERIFIED")
        stated = rfc_time(r["criteria"].get("committed_at"))
        if stated is None:
            unreadable = True                               # 1.4.2: step 5 uses committed_at here and cannot read it (76)
            crit_ms = None
        else:
            crit_ms = _ms_up(stated)
    # Reference time: the EARLIER of issued_utc and a covering token's genTime (1.4.1); reference rounded DOWN to the millisecond.
    issued = rfc_time(r["issued_utc"])
    if issued is None:
        unreadable = True                                   # 1.4.2: step 5 always uses issued_utc
        ref_ms = None
    else:
        ref_ms = _ms_down(issued)
        if out["receipt_timestamp"] == "imprint_match" and gen_time(rt[2]) is not None:
            tr = _ms_down(gen_time(rt[2]) - rt[3])
            ref_ms = tr if REF_RULE == "1.2.1" else min(ref_ms, tr)
        # ASSUMED (1.4.2 is silent): a covering record token whose genTime is not usable gives no time, so issued_utc stands
    out["_times"] = {"commitment_ms": crit_ms, "reference_ms": ref_ms}
    if unreadable:
        P("RECEIPT_TIME_UNREADABLE")
        out["criteria_committed_before_check"] = "no"       # 1.4.2: 'no', and not CRITERIA_COMMITTED_AFTER_CHECK (76)
    else:
        before = crit_ms < ref_ms                           # strict "<" (68)
        out["criteria_committed_before_check"] = "yes" if before else "no"
        if not before:
            P("CRITERIA_COMMITTED_AFTER_CHECK")
    # independence (property 3). 1.4.2 'Independence by key': keys compared as decoded bytes (65, 87); a stated producer or checker
    # key entry that is not canonical base64 is KEY_REJECTED and self-checked (69); a repeated producer/checker key_id is
    # self-checked (75); with `independent` claimed, a stated party key_id must be non-empty and listed once (80, 81; 82 = none stated).
    pk, ck = producer.get("key_id"), checker.get("key_id")
    by_key = False
    for kid in (pk, ck):
        if kid is not None and kid in dec and dec[kid] is None:
            P("KEY_REJECTED"); by_key = True
        if kid is not None and kid in dup:
            by_key = True
    collision = pk is not None and (pk == ck or (pk in dec and ck in dec and dec[pk] is not None and dec[pk] == dec[ck]))
    if collision:
        P("KEY_COLLISION")
    self_checked = r.get("independence") == "self-checked" or collision or by_key
    out["independence"] = "self-checked" if self_checked else "independent"
    if self_checked:
        W("SELF_CHECKED")
    else:
        if producer.get("name") is not None and producer.get("name") == checker.get("name"):
            P("INDEPENDENCE_INCONSISTENT")                  # labelled independent, same party named on both sides
        if r.get("independence") == "independent" and any(kid is not None and (kid == "" or ids.count(kid) != 1) for kid in (pk, ck)):
            P("INDEPENDENCE_INCONSISTENT")
    if not producer.get("name") and not producer.get("key_id"):
        W("PRODUCER_UNDECLARED")
        # ASSUMED reading of 1.3 step 8 (vector 20): with no producer named, independence cannot be derived, so a record that
        # states "independent" anyway is INDEPENDENCE_INCONSISTENT.
        if r.get("independence") == "independent":
            P("INDEPENDENCE_INCONSISTENT")
    # step 7: verdict (property 4). A result outside the vocabulary is RESULT_VOCABULARY and counts as not-pass.
    if any(x["result"] not in RESULTS for x in r["results"]):
        P("RESULT_VOCABULARY")
    req = [x["result"] for x in r["results"] if x.get("required")]
    out["verdict_recomputed"] = "fail" if "fail" in req else ("pass" if all(x == "pass" for x in req) else "incomplete")
    out["verdict_stated"] = r.get("verdict")
    if out["verdict_recomputed"] != out["verdict_stated"]:
        P("VERDICT_MISMATCH")
    return out


def main(paths):
    agree_all = True
    for p in paths:
        v = json.load(open(p))
        got, exp = check(v["inputs"]), v["expected"]
        norm = lambda x: sorted(x) if isinstance(x, list) else x
        diffs = {k: (got.get(k), exp[k]) for k in exp if norm(got.get(k)) != norm(exp[k])}
        # profile 1.4.1: a vector may list alternative conforming step-9 values (40: RSASSA-PSS is optional, `unsupported` conforms)
        acc = v.get("tsa_signature_accepted") or {}
        if "tsa_signature" in diffs and acc:
            g, e = got.get("tsa_signature") or {}, exp["tsa_signature"]
            if all(g.get(t) == e.get(t) or g.get(t) in acc.get(t, []) for t in e) and set(g) == set(e):
                del diffs["tsa_signature"]
        agree_all &= not diffs
        print(f"{'agree' if not diffs else 'DISAGREE'} {os.path.basename(p)}" + "".join(f"\n    {k}: ours {a!r} vector {b!r}" for k, (a, b) in diffs.items()))
        if diffs and got.get("_times"):
            print(f"    times: {got['_times']}")
    return 0 if agree_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
