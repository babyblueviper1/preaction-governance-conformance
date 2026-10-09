#!/usr/bin/env python3
"""A NENRIN provenance-v0 verifier written from the normative procedure alone.

Source: ogasurfproject-jpg/horizon-shield workers/hs-ledger/nenrin/provenance-v0/VERIFIER.md (Oga, T. (2026), DOI
10.5281/zenodo.23136978). Clean room: written from that text only, without reading the reference verifier, its ports, or any
other implementation. Python standard library only (Ed25519 is implemented here, verification only). MIT.

    python3 nenrin_cleanroom.py IN OUT      TSUNAGI batch contract: IN = [{"name", "bundle"}], OUT = {name: signature}
    verify(bundle) -> Report                Report.signature() = {"verdict", "refusals", "findings"} (section 4)

Section references (s1..s5) are to VERIFIER.md.
"""
import base64, datetime, hashlib, json, re, sys

__version__ = "0.1.0"

# ---------------------------------------------------------------- s2 canonical form (musubi-canonical-v0)
SAFE = 2 ** 53 - 1


class CanonicalError(Exception):
    pass


def _cstr(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == "\\": out.append("\\\\")
        elif o == 0x08: out.append("\\b")
        elif o == 0x0C: out.append("\\f")
        elif o == 0x0A: out.append("\\n")
        elif o == 0x0D: out.append("\\r")
        elif o == 0x09: out.append("\\t")
        elif o < 0x20: out.append("\\u%04x" % o)
        elif 0xD800 <= o <= 0xDFFF: out.append("\\u%04x" % o)   # lone surrogate (a valid pair is one code point in Python)
        else: out.append(ch)
    out.append('"')
    return "".join(out)


def _c(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, float):
        # s5 Input: the bundle is a parsed JSON value, so the token 1.0 is the integer 1 and -0 is 0
        if v != v or v in (float("inf"), float("-inf")) or v != int(v): raise CanonicalError("non_integer_number")
        v = int(v)
    if isinstance(v, int):
        if not -SAFE <= v <= SAFE: raise CanonicalError("unsafe_number")
        return str(v)
    if isinstance(v, str): return _cstr(v)
    if isinstance(v, list): return "[" + ",".join(_c(x) for x in v) + "]"
    if isinstance(v, dict):
        for k in v:
            if not (isinstance(k, str) and all(0x20 <= ord(ch) <= 0x7E for ch in k)): raise CanonicalError("key_not_printable_ascii")
        return "{" + ",".join(_cstr(k) + ":" + _c(v[k]) for k in sorted(v)) + "}"
    raise CanonicalError("unsupported_type")


def canonical(v):
    """UTF-8 bytes of canonical(v); raises CanonicalError. Lone surrogates are already escaped, so encoding cannot fail."""
    return _c(v).encode("utf-8")


def try_canonical(v):
    try:
        return canonical(v)
    except (CanonicalError, RecursionError):
        return None


def sha256c(v):
    b = try_canonical(v)
    return None if b is None else hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- s2 / s5 Ed25519 (verification only)
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRTM1 = pow(2, (P - 1) // 4, P)
IDENT = (0, 1, 1, 0)


def _add(p1, p2):
    X1, Y1, Z1, T1 = p1; X2, Y2, Z2, T2 = p2
    A = (Y1 - X1) * (Y2 - X2) % P; B = (Y1 + X1) * (Y2 + X2) % P
    C = 2 * T1 * T2 * D % P; Dd = 2 * Z1 * Z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s, p):
    q = IDENT
    while s:
        if s & 1: q = _add(q, p)
        p = _add(p, p); s >>= 1
    return q


def _encode(p):
    X, Y, Z, _ = p
    zi = pow(Z, P - 2, P); x, y = X * zi % P, Y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _is_ident(p):
    X, Y, Z, _ = p
    return X % P == 0 and (Y - Z) % P == 0


def _decode(b):
    """Canonical point decoding (y < p; x = 0 with the sign bit set refused); None if not a point."""
    if len(b) != 32: return None
    n = int.from_bytes(b, "little"); sign = n >> 255; y = n & ((1 << 255) - 1)
    if y >= P: return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign: return None
        return (0, y, 1, 0)
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P: x = x * SQRTM1 % P
    if (x * x - x2) % P: return None
    if (x & 1) != sign: x = P - x
    return (x, y, 1, x * y % P)


BY = 4 * pow(5, P - 2, P) % P
B = _decode(BY.to_bytes(32, "little"))


def resolve_key(raw):
    """s5 Ed25519: a key resolves only if canonical and a point of the prime-order subgroup, not the identity."""
    A = _decode(raw)
    if A is None or _is_ident(A) or not _is_ident(_mul(L, A)): return None
    return A


def ed25519_verify(A, raw_key, sig, msg):
    """RFC 8032 cofactorless check as OpenSSL does it: S < L, and encode([S]B - [k]A) equals the R bytes."""
    if len(sig) != 64: return False
    Rb, S = sig[:32], int.from_bytes(sig[32:], "little")
    if S >= L: return False
    k = int.from_bytes(hashlib.sha512(Rb + raw_key + msg).digest(), "little") % L
    X, Y, Z, T = _mul(k, A)
    return _encode(_add(_mul(S, B), ((-X) % P, Y, Z, (-T) % P))) == Rb


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_KEYS = {}


def did_key(ident):
    """s2 did:key -> (point, raw 32 bytes) or None. Only did:key resolves offline (s5 Key resolution)."""
    if not isinstance(ident, str): return None
    if ident in _KEYS: return _KEYS[ident]
    out = None
    if ident.startswith("did:key:z") and len(ident) > 9:
        s = ident[9:]
        if all(ch in B58 for ch in s):
            n = 0
            for ch in s: n = n * 58 + B58.index(ch)
            body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
            raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + body
            if len(raw) == 34 and raw[:2] == b"\xed\x01":
                A = resolve_key(raw[2:])
                if A is not None: out = (A, raw[2:])
    _KEYS[ident] = out
    return out


def b64_canonical(s):
    """s5 Base64: canonical standard base64 only (alphabet, padding, no whitespace, zero trailing bits)."""
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", s) or len(s) % 4: return None
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    return raw if base64.b64encode(raw).decode("ascii") == s else None


def sig_verifies(signer, sig_b64, preimage):
    k = did_key(signer)
    if k is None: return False
    sig = b64_canonical(sig_b64)
    if sig is None or len(sig) != 64: return False
    msg = try_canonical(preimage)
    if msg is None: return False
    return ed25519_verify(k[0], k[1], sig, msg)


# ---------------------------------------------------------------- s2 preimages, timestamps, action_binding
MISSING = object()
DERIVED = {"obs": ("evidence_id", "witness_sig", "edge_sig", "consent"),
           "grant": ("grant_ref", "caller_sig", "action_binding"),
           "receipt": ("receipt_id", "provider_sig", "action_binding"),
           "intent": ("intent_id", "intent_sig", "action_binding")}


def preimage(rec, kind):
    return {k: v for k, v in rec.items() if k not in DERIVED[kind]}


def rid(rec, kind):
    return sha256c(preimage(rec, kind))


def recomputes(rec, kind, field):
    h = rid(rec, kind)
    return h is not None and rec.get(field, MISSING) == h


TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")


def instant(t):
    """s2/s5 Timestamps -> comparable (date ordinal, second of day, millisecond) or None."""
    if not isinstance(t, str) or not TS.fullmatch(t): return None
    try:
        d = datetime.date(int(t[0:4]), int(t[5:7]), int(t[8:10]))
    except ValueError:
        return None
    h, mi, se = int(t[11:13]), int(t[14:16]), int(t[17:19])
    if h > 23 or mi > 59 or se > 59: return None
    ms = int((t[20:-1] + "000")[:3]) if t[19] == "." else 0
    return (d.toordinal(), h * 3600 + mi * 60 + se, ms)


def bound_ok(rec, key):
    v = rec.get(key)
    return v is None or instant(v) is not None


def in_window(rec, t):
    nb, na = rec.get("not_before"), rec.get("not_after")
    return (nb is None or instant(nb) <= t) and (na is None or t <= instant(na))


def action_binding(rec, action_field):
    """None if fine (absent, or present and matching), else the reason (s2 action_binding)."""
    if "action_binding" not in rec: return None
    ab = rec["action_binding"]
    if not isinstance(ab, dict) or ab.get("type") != "canonical_request_digest": return "action_binding_malformed"
    dg = ab.get("digest")
    if not isinstance(dg, dict) or dg.get("alg") != "sha-256" or not isinstance(dg.get("value"), str): return "action_binding_malformed"
    if ab.get("canonicalization") != "musubi-canonical-v0" or ab.get("preimage_profile") != "task-execution-bind-v0/action":
        return "action_binding_unknown_profile"
    act = rec.get(action_field)
    if act is None or dg["value"] != sha256c(act): return "action_binding_mismatch"
    return None


def falsy_action(v):
    """s5 Missing fields: missing, null, false, 0 or "" fails the action check."""
    return v is MISSING or v is None or v is False or v == "" or (type(v) in (int, float) and v == 0)


def actions_equal(a, b):
    if falsy_action(a) or falsy_action(b): return False
    ca, cb = try_canonical(a), try_canonical(b)
    return ca is not None and ca == cb


# ---------------------------------------------------------------- s3 the procedure
class Report:
    def __init__(self):
        self.refusals, self.findings, self.reasons = [], [], []

    def refuse(self, code, reason=None):
        self.refusals.append(code)
        if reason: self.reasons.append((code, reason))

    def find(self, code):
        self.findings.append(code)

    @property
    def verdict(self):
        return "refused" if self.refusals else "accepted"

    def signature(self):
        return {"verdict": self.verdict, "refusals": sorted(set(self.refusals)), "findings": sorted(set(self.findings))}


def _slot(bundle, key, r, code):
    """s5 Null and absent / Malformed records: returns the record or None."""
    v = bundle.get(key)
    if v is None or v is False: return None
    if isinstance(v, dict): return v
    r.refuse(code, "record_not_object")
    return None


def _list(bundle, key):
    v = bundle.get(key)
    return v if isinstance(v, list) else []


def pair_check(grant, rec, r, add_findings):
    """s3 step 2a on (grant, receipt). Returns the first failing reason or None."""
    gref = rid(grant, "grant")
    if gref is None or grant.get("grant_ref", MISSING) != gref: return "grant_recompute_mismatch"
    if not recomputes(rec, "receipt", "receipt_id"): return "receipt_recompute_mismatch"
    why = action_binding(grant, "action") or action_binding(rec, "executed_action")
    if why: return why
    if rec.get("grant_ref", MISSING) != gref: return "receipt_unbound"
    t = instant(rec.get("executed_at"))
    if t is None or not bound_ok(grant, "not_before") or not bound_ok(grant, "not_after"): return "invalid_timestamp"
    gp = grant.get("provider_id")
    if gp is not None and gp != rec.get("provider_id", MISSING): return "provider_not_authorized"
    if not in_window(grant, t): return "outside_authorization_window"
    if add_findings:
        if gp is None: r.find("open_grant")
        elif gp == grant.get("caller_id", MISSING): r.find("self_authorized")
    if not actions_equal(grant.get("action", MISSING), rec.get("executed_action", MISSING)): return "action_diverged"
    return None


def verify(bundle):
    r = Report()
    if not isinstance(bundle, dict): bundle = {}
    sigs = bundle.get("require_signatures") is not False

    # record slots, read once (s5 malformed records add their refusal in their own step, collected here in step order below)
    raw_obs = _list(bundle, "observations")
    obs = [o for o in raw_obs if isinstance(o, dict)]
    obs_malformed = len(obs) != len(raw_obs)
    r_exec, r_pre = Report(), Report()            # holders so malformed refusals land in the right step's list
    grant = _slot(bundle, "grant", r_exec, "execution_invalid")
    intent = _slot(bundle, "intent", r_pre, "preflight_invalid")
    rset, seen = [], []
    first = _slot(bundle, "receipt", r_exec, "execution_invalid")
    cands = ([first] if first is not None else [])
    for x in _list(bundle, "receipts"):
        if isinstance(x, dict): cands.append(x)
        else: r_exec.refuse("execution_invalid", "record_not_object")
    for x in cands:
        cb = try_canonical(x)
        if cb is not None and cb in seen: continue
        if cb is not None: seen.append(cb)
        rset.append(x)
    primary = rset[0] if rset else None

    # Step 0, identity
    tid = bundle.get("task_id")
    records = obs + ([grant] if grant else []) + ([intent] if intent else []) + rset
    if not (isinstance(tid, str) and tid):
        r.refuse("task_id_missing")
        if records: r.refuse("task_id_mismatch")
    elif any(x.get("task_id", MISSING) != tid for x in records):
        r.refuse("task_id_mismatch")

    # Step 1, delegation
    if not raw_obs:
        r.find("no_delegation_observations")
    else:
        if obs_malformed: r.refuse("delegation_observation_invalid", "record_not_object")
        for o in obs:
            hop = o.get("hop") if isinstance(o.get("hop"), dict) else {}
            w = o.get("witness_id", MISSING)
            if w == hop.get("from", MISSING) or w == hop.get("to", MISSING):
                r.refuse("delegation_observation_invalid", "witness_not_independent"); continue
            if not recomputes(o, "obs", "evidence_id"):
                r.refuse("delegation_observation_invalid", "recompute_mismatch"); continue
            if sigs:
                if not sig_verifies(o.get("witness_id"), o.get("witness_sig"), preimage(o, "obs")):
                    r.refuse("delegation_observation_invalid", "witness_sig_invalid"); continue
                if "task_id" not in o or "hop" not in o or not sig_verifies(hop.get("from"), o.get("edge_sig"),
                                                                            {"task_id": o["task_id"], "hop": o["hop"]}):
                    r.refuse("delegation_observation_invalid", "edge_sig_invalid"); continue
        # R3
        def seq_of(o):
            h = o.get("hop")
            s = h.get("seq", MISSING) if isinstance(h, dict) else MISSING
            return s if (isinstance(s, int) and not isinstance(s, bool)) else MISSING
        seqs = [seq_of(o) for o in obs]
        broken = None
        if any(s is MISSING for s in seqs) or sorted(set(seqs)) != list(range(len(set(seqs)))):
            broken = "seq_gap"
        else:
            ids = {}
            for o, s in zip(obs, seqs): ids.setdefault(s, set()).add(rid(o, "obs"))
            for o, s in zip(obs, seqs):
                pv = o.get("prev_evidence_id", MISSING)
                if s == 0:
                    if pv is not None: broken = "root_prev_not_null"; break
                elif pv is MISSING or pv is None or pv not in ids.get(s - 1, set()):
                    broken = "broken_link"; break
        if broken: r.refuse("delegation_chain_broken", broken)
        # R4
        by_seq = {}
        for o in obs:
            h = o.get("hop"); key = repr(h.get("seq", MISSING)) if isinstance(h, dict) else "missing"
            c = o.get("conduct")
            v = c.get("verdict", MISSING) if isinstance(c, dict) else MISSING
            by_seq.setdefault(key, set()).add(("s", v) if isinstance(v, str) else ("m", id(MISSING) if v is MISSING else repr(v)))
        if any(len(v) > 1 for v in by_seq.values()): r.find("witness_disagreement")

    # Step 2, execution
    for c, why in zip(r_exec.refusals, [w for _, w in r_exec.reasons]): r.refuse(c, why)
    reconciled = None
    if grant is None and not rset:
        r.find("no_execution_records")
    elif grant is None or not rset:
        r.refuse("execution_incomplete_pair")
    else:
        why = pair_check(grant, primary, r, True)
        if why: r.refuse("execution_invalid", why)
        if sigs:
            if not sig_verifies(grant.get("caller_id"), grant.get("caller_sig"), preimage(grant, "grant")):
                r.refuse("execution_signature_invalid", "caller_sig")
            elif not sig_verifies(primary.get("provider_id"), primary.get("provider_sig"), preimage(primary, "receipt")):
                r.refuse("execution_signature_invalid", "provider_sig")
        caller_ok = (not sigs) or sig_verifies(grant.get("caller_id"), grant.get("caller_sig"), preimage(grant, "grant"))
        for x in rset[1:]:
            if sigs and not (caller_ok and sig_verifies(x.get("provider_id"), x.get("provider_sig"), preimage(x, "receipt"))):
                continue
            why = pair_check(grant, x, r, False)
            if why: r.refuse("execution_invalid", why)
        gp = grant.get("provider_id")
        if gp is None:
            r.refuse("execution_unreconciled", "open_grant")
        else:
            auth, ids = [], []
            for x in rset:
                if (x.get("grant_ref", MISSING) == grant.get("grant_ref", MISSING) and x.get("provider_id", MISSING) == gp
                        and recomputes(x, "receipt", "receipt_id")
                        and ((not sigs) or sig_verifies(gp, x.get("provider_sig"), preimage(x, "receipt")))):
                    if x["receipt_id"] not in ids: ids.append(x["receipt_id"]); auth.append(x)
            if not ids: r.refuse("execution_unreconciled")
            elif len(ids) > 1: r.refuse("execution_equivocation")
            else: reconciled = auth[0]

    # Step 3, preflight
    for c, why in zip(r_pre.refusals, [w for _, w in r_pre.reasons]): r.refuse(c, why)
    if intent is not None:
        if grant is None:
            r.refuse("preflight_without_grant")
        else:
            why = None
            gref = rid(grant, "grant")
            if gref is None or grant.get("grant_ref", MISSING) != gref: why = "grant_recompute_mismatch"
            elif not recomputes(intent, "intent", "intent_id"): why = "intent_recompute_mismatch"
            else: why = action_binding(intent, "proposed_action")
            if not why:
                t = instant(intent.get("declared_at"))
                gp = grant.get("provider_id")
                if intent.get("grant_ref", MISSING) != gref: why = "intent_unbound"
                elif t is None or not bound_ok(grant, "not_before") or not bound_ok(grant, "not_after"): why = "invalid_timestamp"
                elif gp is not None and gp != intent.get("provider_id", MISSING): why = "provider_not_authorized"
                elif not in_window(grant, t): why = "outside_authorization_window"
                else:
                    if gp is None: r.find("open_grant")
                    elif gp == grant.get("caller_id", MISSING): r.find("self_authorized")
                    if not actions_equal(grant.get("action", MISSING), intent.get("proposed_action", MISSING)): why = "action_diverged"
            if why: r.refuse("preflight_invalid", why)
            if sigs and not sig_verifies(intent.get("provider_id"), intent.get("intent_sig"), preimage(intent, "intent")):
                r.refuse("preflight_signature_invalid")
            if reconciled is not None:
                a, b = try_canonical(intent.get("proposed_action")), try_canonical(reconciled.get("executed_action"))
                if a is None or b is None or a != b: r.find("declared_executed_divergence")

    # Step 4, evidence
    target = reconciled if reconciled is not None else primary
    if target is not None:
        out = target.get("outcome")
        E = out.get("evidence", MISSING) if isinstance(out, dict) else MISSING
        if E is MISSING or E is None or E is False or E == "" or (type(E) in (int, float) and E == 0):
            r.find("no_evidence_bound")
        elif (isinstance(E, dict) and E.get("kind") in ("bitcoin_tx", "ledger_record", "document_sha256", "url_sha256")
              and isinstance(E.get("ref"), str) and re.fullmatch(r"[0-9a-f]{64}", E["ref"])
              and isinstance(E.get("system"), str) and E["system"]):
            r.find("evidence_bound_unchecked")
        else:
            r.refuse("evidence_invalid")

    # Step 5, linkage
    if raw_obs and reconciled is not None:
        want = rid(reconciled, "receipt")
        links = [c["detail_ref"] for c in (o.get("conduct") for o in obs)
                 if isinstance(c, dict) and isinstance(c.get("detail_ref"), str) and c["detail_ref"].startswith("nenrin-exec://")]
        if not links: r.find("no_digest_link")
        elif any(l[len("nenrin-exec://"):] != want for l in links): r.refuse("linkage_receipt_mismatch")
    return r


# ---------------------------------------------------------------- TSUNAGI batch contract
def main(src, dst):
    cases = json.load(open(src, encoding="utf-8"))
    out = {}
    for c in cases:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str): continue
        try:
            out[c["name"]] = verify(c.get("bundle")).signature()
        except Exception as e:
            out[c["name"]] = {"error": "%s: %s" % (type(e).__name__, e)}
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, sort_keys=True, indent=1); f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
