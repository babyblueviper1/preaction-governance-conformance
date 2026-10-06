#!/usr/bin/env python3
"""ERC-8309 mesh-sync conformance checker (stdlib only). Three rules, proposed for the 8309-vantage companion §10:

  R1 ENUMERATE   a sync check reads a node's records through its cursor to the end; any page that still carries a cursor is a SAMPLE,
                 and a sample cannot pass or fail a conformance check (it is INCOMPLETE). A cursor that repeats is an ERROR (fail closed).
  R2 PER-ORIGIN  convergence is checked per origin and per namespace the origin declares: every participating node holds the complete
                 set that origin produced in that namespace. Node totals are not a valid predicate (locally-originated records make two
                 correct nodes differ, and two broken ones can match).
  R3 ENVELOPE    every field a peer acts on (nodeType included) is inside the signed envelope. A behaviour-affecting field outside it is
                 an unverifiable claim (NONCONFORMANT); a served value that differs from the signed one is a MISMATCH (fail closed).

Findings by Echo (damon:receiptos, topic 16, 2026-10-05/06): the silently clamped page, the hidden namespace, the per-origin predicate,
nodeType outside the signed envelope. Vectors are STRUCTURAL: they test the rules over record ids and declared field sets, not the
signature scheme itself.

usage: python3 check_mesh_sync.py [vectors.json]   -> one line per vector, exit 1 on any mismatch with the expected result"""
import json, sys


def enumerate_pages(pages):
    """pages: {"start": token, "<token>": {"records": [...], "cursor": next_token|null}} -> (status, records)."""
    out, seen, tok = [], set(), pages["start"]
    while True:
        if tok in seen:
            return "ERROR", out          # cursor cycle: fail closed
        seen.add(tok)
        page = pages.get(tok)
        if page is None:
            return "ERROR", out          # cursor points nowhere: fail closed
        out.extend(page["records"])
        tok = page.get("cursor")
        if tok is None:
            return "COMPLETE", out


def single_read(pages):
    """What a non-enumerating checker sees: the first page only."""
    p = pages[pages["start"]]
    return ("INCOMPLETE" if p.get("cursor") is not None else "COMPLETE"), p["records"]


def per_origin(v):
    """R2: {"origins": {O: {ns: [ids]}}, "nodes": {node: {ns: pages}}} -> verdict per (origin, ns) and overall."""
    detail, ok = {}, True
    for o, by_ns in v["origins"].items():
        for ns, produced in by_ns.items():
            missing = {}
            for node, served in v["nodes"].items():
                if ns not in served:
                    missing[node] = "namespace_absent"; continue
                st, recs = enumerate_pages(served[ns])
                if st != "COMPLETE":
                    missing[node] = st; continue
                lack = sorted(set(produced) - set(recs))
                if lack:
                    missing[node] = len(lack)
            detail[f"{o}/{ns}"] = "CONVERGED" if not missing else {"MISSING": missing}
            ok = ok and not missing
    return ("CONVERGED" if ok else "NOT_CONVERGED"), detail


def totals_equal(v):
    """The invalid predicate, reported for contrast only."""
    tots = []
    for node, served in v["nodes"].items():
        n = 0
        for ns, pages in served.items():
            n += len(enumerate_pages(pages)[1])
        tots.append(n)
    return len(set(tots)) == 1


def envelope(v):
    """R3: {"signed_fields": {...}, "served_fields": {...}, "acted_on": [...]}."""
    signed, served = v["signed_fields"], v["served_fields"]
    for f in v["acted_on"]:
        if f not in signed:
            return f"NONCONFORMANT:unsigned_behaviour_field:{f}"
        if f in served and served[f] != signed[f]:
            return f"MISMATCH:{f}"
    return "CONFORMANT"


def run(path):
    V = json.load(open(path)); bad = 0
    for v in V["vectors"]:
        k = v["kind"]
        if k == "enumerate":
            st, recs = enumerate_pages(v["pages"]); one = single_read(v["pages"])[0]
            got = {"enumerated": st, "count": len(recs), "single_page_read": one}
        elif k == "convergence":
            st, det = per_origin(v)
            got = {"per_origin": st, "detail": det, "totals_equal": totals_equal(v)}
        elif k == "envelope":
            got = {"result": envelope(v)}
        else:
            got = {"error": "unknown kind"}
        exp = v["expected"]
        match = all(got.get(x) == exp[x] for x in exp)
        bad += not match
        print(f"{'PASS' if match else 'FAIL'} {v['id']}: {json.dumps({x: got.get(x) for x in exp})}")
    print(f"{len(V['vectors']) - bad}/{len(V['vectors'])} vectors match")
    return 1 if bad else 0




# --- mutation gate (companion §10): each rule's checker, broken on purpose, must turn at least one of its vectors RED ---
def _mutants(path):
    import copy
    global enumerate_pages, per_origin, envelope
    real = (enumerate_pages, per_origin, envelope)
    def m1(pages):                       # M1: read one page and call it complete (the silent-clamp trap)
        return "COMPLETE", pages[pages["start"]]["records"]
    def m2(v):                           # M2: totals predicate instead of per-origin
        return ("CONVERGED" if totals_equal(v) else "NOT_CONVERGED"), {}
    def m3(v):                           # M3: ignore whether acted-on fields are signed
        return "CONFORMANT"
    res = {}
    for name, patch in (("M1-single-page-read", ("enumerate_pages", m1)), ("M2-totals-predicate", ("per_origin", m2)), ("M3-unsigned-field-accepted", ("envelope", m3))):
        enumerate_pages, per_origin, envelope = real
        globals()[patch[0]] = patch[1]
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(path)
        res[name] = "KILLED" if rc else "SURVIVED"
    enumerate_pages, per_origin, envelope = real
    for k, s in res.items(): print(f"{s} {k}")
    return 0 if all(s == "KILLED" for s in res.values()) else 1


if __name__ == "__main__" and "--mutants" in sys.argv:
    sys.exit(_mutants("vectors.json"))


if __name__ == "__main__" and "--mutants" not in sys.argv:
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else "vectors.json"))
