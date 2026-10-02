"""RFC 8785 (JCS) canonicalization, stdlib only. Numbers follow ECMAScript Number::toString (what JSON.stringify emits);
strings use JSON.stringify escaping; object keys sort by UTF-16 code units. Verified against Node on 4,017 fuzzed doubles
(see scripts/geomacro_verify_gro.py in babyblueviper1/invinoveritas) and against the vector_d cases via check_cross_layer.py.
"""
import math


def js_number(x):
    """ECMAScript Number::toString(10) (what JSON.stringify emits for finite numbers)."""
    if isinstance(x, bool):
        raise TypeError
    if isinstance(x, int):
        x = float(x) if abs(x) >= 2**53 else x
        if isinstance(x, int):
            return str(x)
    if not math.isfinite(x):
        raise ValueError("non-finite")
    if x == 0:
        return "0"                       # spec: negative zero -> 0
    sign = "-" if x < 0 else ""
    r = repr(abs(x))                     # shortest round-trip digits, same as JS
    m, _, e = r.lower().partition("e")
    exp10 = int(e) if e else 0
    if "." in m:
        ip, fp = m.split(".")
    else:
        ip, fp = m, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    n = len(ip) - lead_zeros + exp10     # decimal point position relative to digits
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e_ = n - 1
        es = ("+" if e_ >= 0 else "-") + str(abs(e_))
        out = digits[0] + ("" if k == 1 else "." + digits[1:]) + "e" + es
    return sign + out


def js_string(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == "\\": out.append("\\\\")
        elif ch == "\b": out.append("\\b")
        elif ch == "\f": out.append("\\f")
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif o < 0x20: out.append("\\u%04x" % o)
        else: out.append(ch)             # JSON.stringify does not escape non-ASCII
    out.append('"')
    return "".join(out)


def jcs(v):
    if v is None: return "null"
    if v is True: return "true"
    if v is False: return "false"
    if isinstance(v, (int, float)): return js_number(v)
    if isinstance(v, str): return js_string(v)
    if isinstance(v, list): return "[" + ",".join(jcs(i) for i in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-16-be"))   # UTF-16 code-unit order
        return "{" + ",".join(js_string(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise TypeError(type(v))

