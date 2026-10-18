"""Clean-room verifier for the work-acceptance record (trilatic.acceptance-receipt/1.2, profile 1.2.1), first written from the README of
maximusrufus/work-acceptance-record @ d78865c alone, updated to the 1.2.1 README @ f7d8984 (draft, CC0). Standard library only; Ed25519 from ../x402-receipt-private-opening.

    python3 war_check.py <vector.json>...      # prints our result next to the vector's `expected`, field by field

Where the README is silent this checker says what it assumed (ASSUMED below) instead of copying a vector.
"""
import base64
import hashlib
import importlib.util
import json
import os
import sys

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


def jcs(v):
    """RFC 8785 for the values in these records (objects, arrays, strings, integers, booleans, null)."""
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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
    """(hash_oid, imprint_hex, gen_time 'YYYYMMDDHHMMSSZ') from an RFC 3161 TimeStampResp/token, or None."""
    if not token_b64:
        return None
    raw = base64.b64decode(token_b64)
    info = _find_tstinfo(raw)
    if info is None:
        return None
    f = _children(info)
    if len(f) == 1 and f[0][0] == 0x30:              # eContent holds the DER TSTInfo SEQUENCE: step inside it
        f = _children(f[0][1])
    mi = _children(f[2][1])
    alg = _oid(_children(mi[0][1])[0][1])
    gen = next(v.decode() for t, v in f if t == 0x18)
    return alg, mi[1][1].hex(), gen


def _iso(t):
    """'2026-03-01T00:00:00Z' or '20260301000000Z' -> comparable 'YYYYMMDDHHMMSS'."""
    return "".join(c for c in t if c.isdigit())[:14]


def check(inputs):
    """Profile 1.2.1 (README @ f7d8984). Step numbers below are that README's."""
    rec = inputs["receipt"]
    r = rec["receipt"]
    out = {"problem_codes": [], "warning_codes": []}
    P, W = out["problem_codes"].append, out["warning_codes"].append
    # step 1
    if r.get("schema") not in SCHEMAS or r.get("canonicalization") != "JCS-RFC8785" or \
            r.get("suite") != {"digest": "sha-256", "signature": "Ed25519"}:
        return {"refused": True, "reason": "unknown schema, canonicalization or suite"}
    # step 2: signature over the canonical inner `receipt`, with the key the SIGNED receipt names (receipt.key_id). An envelope
    # signature.key_id that names a different key is not accepted: the signed bytes would then misname their own signer.
    keys = {k["key_id"]: base64.b64decode(k["public_key_base64"]) for k in inputs["keys"]["keys"]}
    pub = keys.get(r.get("key_id"))
    sig = base64.b64decode(rec["signature"]["value"])
    out["signature_valid"] = bool(pub) and rec["signature"].get("key_id") == r.get("key_id") and ed.verify(pub, jcs(r), sig)
    if not out["signature_valid"]:
        P("SIGNATURE_INVALID")
    checker, producer = r["parties"]["checker"], r["parties"].get("producer") or {}
    if out["signature_valid"] and checker.get("key_id") != r.get("key_id"):
        P("CHECKER_NOT_SIGNER")
    # step 4: criteria document hash, then results against the criteria
    cb = base64.b64decode(inputs["criteria_file_base64"]) if inputs.get("criteria_file_base64") else None
    out["criteria_hash"] = "absent" if cb is None else (
        "match" if hashlib.sha256(cb).hexdigest() == r["criteria"]["sha256"] else "mismatch")
    if out["criteria_hash"] == "mismatch":
        P("CRITERIA_HASH_MISMATCH")
    elif out["criteria_hash"] == "match":
        crit = {c["id"]: bool(c.get("required")) for c in json.loads(cb)["criteria"]}
        got = {x["id"]: bool(x.get("required")) for x in r["results"]}
        if got != crit:                                   # ASSUMED: same ids, same required flags, one result each
            P("CRITERIA_RESULTS_MISMATCH")
    # step 6 (needed by step 5's reference time): the record's own token
    rt = tst(inputs.get("receipt_tsr_base64"))
    out["receipt_timestamp"] = "none" if rt is None else (
        "imprint_match" if rt[0] == OID_SHA256 and rt[1] == hashlib.sha256(jcs(r)).hexdigest() else "imprint_mismatch")
    # step 5: criteria commitment. Token over criteria.sha256 is authoritative; a token over other bytes is
    # CRITERIA_TIMESTAMP_MISMATCH and is not evidence of time, so fall back to committed_at with the unverified warning.
    ct = tst(inputs.get("criteria_tsr_base64"))
    if ct is not None and ct[0] == OID_SHA256 and ct[1] == r["criteria"]["sha256"]:
        commit = _iso(ct[2])
        if commit != _iso(r["criteria"]["committed_at"]):
            P("CRITERIA_TIME_MISMATCH")
    else:
        if ct is not None:
            P("CRITERIA_TIMESTAMP_MISMATCH")
        commit = _iso(r["criteria"]["committed_at"])
        W("CRITERIA_COMMITMENT_UNVERIFIED")
    # Reference time. 1.2.1 says: a covering token's genTime, else issued_utc. PROPOSED (vector 22): the EARLIER of the two. A covering
    # token only bounds the check from above; issued_utc is the checker's own signed statement of when it checked, and a checker has no
    # reason to state an earlier time than the truth. Taking the later token time lets criteria committed after the signed check time
    # count as "committed first". Set REF_RULE = "1.2.1" to reproduce the profile as written.
    issued = _iso(r["issued_utc"])
    if out["receipt_timestamp"] == "imprint_match":
        ref = _iso(rt[2]) if REF_RULE == "1.2.1" else min(issued, _iso(rt[2]))
    else:
        ref = issued
    out["_times"] = {"commitment": commit, "reference": ref, "issued_utc": _iso(r["issued_utc"])}
    before = commit < ref
    out["criteria_committed_before_check"] = "yes" if before else "no"
    if not before:
        P("CRITERIA_COMMITTED_AFTER_CHECK")
    # independence (property 3)
    collision = producer.get("key_id") is not None and producer.get("key_id") == checker.get("key_id")
    if collision:
        P("KEY_COLLISION")
    self_checked = r.get("independence") == "self-checked" or collision
    out["independence"] = "self-checked" if self_checked else "independent"
    if self_checked:
        W("SELF_CHECKED")
    elif producer.get("name") is not None and producer.get("name") == checker.get("name"):
        P("INDEPENDENCE_INCONSISTENT")                    # labelled independent, same party named on both sides
    if not producer.get("name") and not producer.get("key_id"):
        W("PRODUCER_UNDECLARED")
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
        agree_all &= not diffs
        print(f"{'agree' if not diffs else 'DISAGREE'} {os.path.basename(p)}" + "".join(f"\n    {k}: ours {a!r} vector {b!r}" for k, (a, b) in diffs.items()))
        if diffs and got.get("_times"):
            print(f"    times: {got['_times']}")
    return 0 if agree_all else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
