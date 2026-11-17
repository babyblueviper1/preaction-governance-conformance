"""Held by the checker: one evidence format and one rule for invinoveritas work-acceptance records.

Source: babyblueviper1/preaction-governance-conformance, examples/verdict-record-work-acceptance/README.md, sections
"Format" and "Rule", at the commit in SOURCE. The format is the signed record of an independent work-acceptance check:
a receipt in Trilatic's acceptance-receipt/1.2 schema, signed with Ed25519 over its RFC 8785 (JCS) form by a checker key
the checker holds as a trust anchor. The rule re-derives the receipt's verdict from its per-criterion results.

Trust anchor (checker input, never read from the record or the item): anchors["invinoveritas-checker-keys"], the key
document published at https://api.babyblueviper.com/.well-known/invinoveritas-checker-keys.json, as bytes the
presenter pins.

What this format does NOT give: an upper time bound. The receipt's issued_utc is the checker's own signed statement,
and the RFC 3161 token for the receipt is not inside the item's bytes, so check_item returns None for the bound.
"""
import base64
import json
import math

SOURCE = {"url": "https://github.com/babyblueviper1/preaction-governance-conformance/blob/"
                 "main/examples/verdict-record-work-acceptance/README.md",
          "sections": ["Format", "Rule"],
          "trust_anchor": "anchors['invinoveritas-checker-keys']: the published checker-key document"}

BASE = "https://github.com/babyblueviper1/preaction-governance-conformance/blob/main/examples/verdict-record-work-acceptance/README.md"
SCHEMA = "trilatic.acceptance-receipt/1.2"


def _es_number(x):
    """RFC 8785 3.2.2.3: ECMAScript Number::toString."""
    if isinstance(x, int):
        if abs(x) <= 2 ** 53:
            return str(x)
        x = float(x)
    if math.isnan(x) or math.isinf(x):
        raise ValueError("NaN/Infinity are not JSON")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))
    mant, ex = (r.split("e")[0], int(r.split("e")[1])) if "e" in r else (r, 0)
    ip, fp = mant.split(".") if "." in mant else (mant, "")
    if fp == "0":
        fp = ""
    digits = (ip + fp).lstrip("0")
    lead = len(ip + fp) - len(digits)
    n = len(ip) - lead + ex
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


def jcs(o):
    """RFC 8785: keys sorted by UTF-16 code units, ECMAScript numbers, JSON.stringify string escaping."""
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, (int, float)):
        return _es_number(o)
    if isinstance(o, str):
        return json.dumps(o, ensure_ascii=False)
    if isinstance(o, list):
        return "[" + ",".join(jcs(x) for x in o) + "]"
    if isinstance(o, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(o[k])
                              for k in sorted(o, key=lambda s: s.encode("utf-16-be"))) + "}"
    raise TypeError(type(o).__name__)


def recompute(results):
    """The receipt's verdict rule (Trilatic, ruled on x402-foundation/tsc#4, 2026-10-17): any required fail -> fail;
    else any required not-evaluated or error -> incomplete; else pass."""
    req = [r["result"] for r in results if r.get("required") is True]
    if "fail" in req:
        return "fail"
    return "incomplete" if any(x in ("not-evaluated", "error") for x in req) else "pass"


def results_problem(results):
    if not isinstance(results, list) or not results:
        return "results is not a non-empty array"
    for i, r in enumerate(results):
        if not isinstance(r, dict) or not isinstance(r.get("required"), bool) or not isinstance(r.get("result"), str):
            return "results[%d] has no boolean required and string result" % i
    return None


class WorkAcceptanceRecord:
    """The item is the JSON object {"receipt", "signature"[, "timestamp"]} the checker publishes at
    /work-acceptance/record/{receipt_sha256} (member "record"). It meets the format's rules when: receipt.schema is
    trilatic.acceptance-receipt/1.2; signature.alg is Ed25519 and signature.key_id equals receipt.key_id; that key_id
    is an active key in the held key document; the signature verifies over JCS(receipt) under that key; and
    receipt.verdict equals the verdict re-derived from receipt.results."""
    NAME = BASE + "#format"

    @staticmethod
    def check_item(b, ctx):
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            rec = json.loads(b.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return (False, "the item is not JSON", None)
        if not isinstance(rec, dict) or not isinstance(rec.get("receipt"), dict) or not isinstance(rec.get("signature"), dict):
            return (False, "the item has no receipt and signature objects", None)
        rc, sg = rec["receipt"], rec["signature"]
        if rc.get("schema") != SCHEMA:
            return (False, "receipt.schema is not %s" % SCHEMA, None)
        if sg.get("alg") != "Ed25519" or sg.get("key_id") != rc.get("key_id"):
            return (False, "the signature is not Ed25519 by the receipt's key_id", None)
        doc = (ctx.get("anchors") or {}).get("invinoveritas-checker-keys") or {}
        keys = {k.get("key_id"): k for k in doc.get("keys", []) if isinstance(k, dict)}
        k = keys.get(sg.get("key_id"))
        if k is None or k.get("alg") != "Ed25519" or k.get("status") != "active":
            return (False, "no active Ed25519 key with this key_id in the held key document", None)
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(k["public_key_base64"])).verify(
                base64.b64decode(sg["value"]), jcs(rc).encode("utf-8"))
        except (InvalidSignature, ValueError, KeyError, TypeError):
            return (False, "the signature does not verify over the JCS form of the receipt", None)
        p = results_problem(rc.get("results"))
        if p:
            return (False, "receipt." + p, None)
        if rc.get("verdict") != recompute(rc["results"]):
            return (False, "receipt.verdict is not the verdict its results give", None)
        return (True, None, None)   # no upper time bound: see the module docstring


class AcceptanceVerdict:
    """check.inputs has exactly the member results: the receipt's per-criterion results, bound to the cited record
    (pointer /receipt/results). Each result is an object with a boolean required and a string result. The rule's
    result is "pass", "fail" or "incomplete", by recompute() above."""
    NAME = BASE + "#rule"

    @staticmethod
    def input_problems(values, names):
        if names != ["results"]:
            return ["the rule's input is exactly results"]
        p = results_problem(values.get("results")) if "results" in values else None
        return [p] if p else []

    @staticmethod
    def rerun(values, ctx):
        return recompute(values["results"])


RULES = (AcceptanceVerdict,)
FORMATS = (WorkAcceptanceRecord,)
