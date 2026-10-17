"""Check vectors.json, then show that each lax checker fails at least one vector.

    python3 run_vectors.py        # standard library only
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mandate_check as M  # noqa: E402

D = json.load(open(os.path.join(HERE, "vectors.json")))


def honest(b, chain, trusted):
    return M.check(b, chain, trusted)


def skips_consent(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "consented_and_settled" if r == "consent_invalid" else r


def skips_cart_binding(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "consented_and_settled" if r == "consent_not_bound" else r


def skips_merchant(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "consented_and_settled" if r == "cart_not_merchant_signed" else r


def trusts_mandate_terms(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "consented_and_settled" if r == "terms_mismatch" else r


def skips_receipt_link(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "consented_and_settled" if r == "receipt_not_this_authorization" else r


def consent_is_settlement(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "consented_and_settled" if r in ("no_settlement", "settlement_terms_mismatch", "incomplete_check") else r


def unavailable_as_no_settlement(b, chain, trusted):
    r = M.check(b, chain, trusted)
    return "no_settlement" if r == "incomplete_check" else r


MUTANTS = {"skips_consent_signature": skips_consent, "skips_cart_binding": skips_cart_binding,
           "skips_merchant_signature": skips_merchant, "trusts_mandate_terms": trusts_mandate_terms,
           "skips_receipt_link": skips_receipt_link, "consent_is_settlement": consent_is_settlement,
           "unavailable_as_no_settlement": unavailable_as_no_settlement}


def main():
    ok, passed = True, 0
    for v in D["vectors"]:
        got = honest(v["bundle"], v["chain"], D["trusted"])
        good = got == v["expect"]
        passed += good
        ok &= good
        print(f"  {'PASS' if good else 'FAIL'} {v['id']}" + ("" if good else f"  got {got} want {v['expect']}"))
    print(f"{passed}/{len(D['vectors'])} vectors")
    for name, impl in MUTANTS.items():
        caught = [v["id"] for v in D["vectors"] if impl(v["bundle"], v["chain"], D["trusted"]) != v["expect"]]
        print(f"  {'caught' if caught else 'MISSED'} {name}: {', '.join(caught) or '-'}")
        ok &= bool(caught)
    import build_vectors
    same = build_vectors.vectors() == D
    print(f"  {'PASS' if same else 'FAIL'} vectors.json reproduces from build_vectors.py")
    ok &= same
    print("ALL PASS" if ok else "FAILURES")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
