"""Check vectors.json, then show that each of five lax verifiers fails at least one vector.

    python3 run_vectors.py        # standard library only
"""
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ed25519_ref as ed  # noqa: E402
import statement as S  # noqa: E402

D = json.load(open(os.path.join(HERE, "vectors.json")))
CHAIN = D["chain"]


def run(v, impl):
    k = v["kind"]
    if k == "assess":
        return {"result": impl["assess"](v["receipt"], v["opening"], v["rater"], v["agent_wallets"], v.get("chain", CHAIN))}
    if k == "privacy":
        return {"leaks": impl["leaks"](impl["restate"](v["statement"]), v["secrets"])}
    if k == "challenge":
        return {"result": impl["challenge"](v["statement"], v["receipt"], v["public_opening"], v["agent_wallets"], CHAIN)}
    if k == "log":
        return {"ok": S.log_ok(v["statements"])}
    if k == "count":
        return {"pairs": sorted([list(p) for p in impl["count"](v["statements"], set(v["trusted"]))])}
    raise ValueError(k)


HONEST = {"assess": S.assess, "leaks": S.leaks, "restate": lambda st: st, "challenge": S.challenge, "count": S.grounded_pairs}


def _skips_rater(receipt, opening, rater, wallets, chain):
    return S.assess(receipt, opening, receipt["payer"], wallets, chain)


def _unbound(st, receipt, opening, wallets, chain):
    return "upheld" if S.assess(receipt, opening, st["rater"], wallets, chain) == st["result"] else "refuted"


def _counts_ratings(statements, trusted):
    return [(s["rater"], s["agent"], i) for i, s in enumerate(statements)
            if s.get("result") == "opens_to_settlement" and s.get("verifier") in trusted]


def _nonce_of(st):
    # what a verifier that "helpfully" records which settlement it found would sign
    n = next(k for k, v in CHAIN["nonces"].items() if v["transfers"])
    return {**st, "nonce": n}


def _unavailable_as_no_settlement(receipt, opening, rater, wallets, chain):
    r = S.assess(receipt, opening, rater, wallets, chain)
    return "no_settlement" if r == "incomplete_check" else r


MUTANTS = {
    "unavailable_as_no_settlement": {**HONEST, "assess": _unavailable_as_no_settlement},
    "skips_rater_check": {**HONEST, "assess": _skips_rater},
    "leaks_nonce": {**HONEST, "restate": _nonce_of},
    "unbound_statement": {**HONEST, "challenge": _unbound},
    "trusts_statement": {**HONEST, "challenge": lambda st, *a: "upheld" if S.signature_ok(st) else "bad_signature"},
    "counts_ratings": {**HONEST, "count": _counts_ratings},
}


def main():
    ok = True
    # RFC 8032 sec 7.1 TEST 1
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    rfc = (ed.public_key(sk).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
           and ed.sign(sk, b"").hex() == "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    print(f"  {'PASS' if rfc else 'FAIL'} ed25519 RFC 8032 TEST 1"); ok &= rfc
    passed = 0
    for v in D["vectors"]:
        got = run(v, HONEST)
        good = got == v["expect"]
        passed += good; ok &= good
        print(f"  {'PASS' if good else 'FAIL'} {v['id']}" + ("" if good else f"  got {got} want {v['expect']}"))
    print(f"{passed}/{len(D['vectors'])} vectors")
    for name, impl in MUTANTS.items():
        caught = [v["id"] for v in D["vectors"] if run(v, impl) != v["expect"]]
        print(f"  {'caught' if caught else 'MISSED'} {name}: {', '.join(caught) or '-'}")
        ok &= bool(caught)
    import build_vectors
    same = build_vectors.vectors() == D
    print(f"  {'PASS' if same else 'FAIL'} vectors.json reproduces from build_vectors.py"); ok &= same
    print("ALL PASS" if ok else "FAILURES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
