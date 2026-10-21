"""Remove one step-9 rule at a time and list the 1.4.1 vectors (31-46) that stop agreeing: each rule should be load-bearing.
    python3 -I tsa_sig_mutations.py <work-acceptance-record checkout>/vectors"""
import glob, json, os, sys, importlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import war_check, tsa_sig as T
VEC = sorted(glob.glob(os.path.join(sys.argv[1], "3[1-9]*.json")) + glob.glob(os.path.join(sys.argv[1], "4*.json")))


def failing():
    out = []
    for p in VEC:
        v = json.load(open(p)); got = war_check.check(v["inputs"]).get("tsa_signature"); exp = v["expected"]["tsa_signature"]
        acc = v.get("tsa_signature_accepted") or {}
        if not all(got.get(t) == exp[t] or got.get(t) in acc.get(t, []) for t in exp):
            out.append(os.path.basename(p)[:2])
    return out


orig = {k: getattr(T, k) for k in ("_ess_binding", "_signature_ok", "_valid_at", "_is_anchor", "_is_ca")}
src_evaluate = T.evaluate
MUT = {
    "ESS binding": lambda: setattr(T, "_ess_binding", lambda tok, der: True),
    "signature": lambda: setattr(T, "_signature_ok", lambda tok, c: True),
    "validity at genTime": lambda: setattr(T, "_valid_at", lambda c, t: True),
    "anchor = name + key (DER-only instead)": lambda: setattr(T, "_is_anchor", lambda c, a: any(T._same_cert(c, x) for x in a)),
    "unsupported curve (treat P-521 as signable)": lambda: setattr(T, "REQUIRED_CURVES", ("secp256r1", "secp384r1", "secp521r1")),
}
print("baseline failing:", failing() or "none")
for name, apply in MUT.items():
    apply(); f = failing(); print(f"{name:45s} -> fails {f or 'NONE (not load-bearing)'}")
    for k, v in orig.items():
        setattr(T, k, v)
    T.REQUIRED_CURVES = ("secp256r1", "secp384r1")
for name in ("contentType", "messageDigest"):
    T._SKIP.add(name); f = failing(); print(f"{name + ' check removed':45s} -> fails {f or 'NONE (not load-bearing)'}"); T._SKIP.discard(name)
