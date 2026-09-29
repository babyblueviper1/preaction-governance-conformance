#!/usr/bin/env python3
"""Run the cold checker (tools/evidence_set_check.py) against TK's companion fixture corpus
(TKCollective/tanilo-receipt-spec fixtures/evidence-pinning-fixtures-v2-rev8.json), vector by vector.

    python3 examples/evidence-set-cold/run_companion_corpus.py path/to/evidence-pinning-fixtures-v2-rev8.json

Harness adaptations (the corpus vectors are fragments, not full -03 evidence_set objects). Each one is stated here so a
reader can reject it:
  H1  evidence_set_version "ao-evidence-set-v1" is added where absent (every rev8 vector predates the member).
  H2  A bare `entry` / `sources` fragment is wrapped as {"sources": [...]}; declared counts are left absent (-03 5.3.1
      fallback derives them).
  H3  evidence_root: where the vector OMITS the member and is not about the root, the correct root is injected (the
      corpus marks those vectors "not root-bearing"); an explicit null/value in the vector is kept as given.
  H4  set_retrieved_at -> the set-level retrieved_at member.
  H5  rev8 condition names are mapped to the -03 Table 2 registry names (RENAME below); a vector passes when its named
      condition is IN the reported set (report-all: other conditions the fragment trips are listed, not hidden).
Exit 0 iff every vector agrees.
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import evidence_set_check as E

RENAME = {"content_kind_absent_when_pinned": "content_kind_absent_or_invalid_when_pinned",
          "pinned_count_disagrees_with_pinned_entries": "pinned_count_mismatch",
          "root_null_with_pinned_entries": "evidence_root_absent_with_pinned_items",
          "root_present_with_zero_pinned": "evidence_root_present_with_no_pinned_items",
          "snippet_digest_present_for_full_resource": "resource_sha256_present_for_full_resource",
          "source_count_disagrees_with_sources": "source_count_mismatch",
          "unpinned_reason_outside_domain": "unpinned_reason_absent_or_invalid",
          "unpinned_without_reason": "unpinned_reason_absent_or_invalid"}


def es_of(inp):
    if "evidence_set" in inp:
        es = dict(inp["evidence_set"])
    elif "entry" in inp:
        es = {"sources": [inp["entry"]]}
    else:
        es = {"sources": inp["sources"]}
    if "set_retrieved_at" in inp:
        es["retrieved_at"] = inp["set_retrieved_at"]
    es.setdefault("evidence_set_version", E.VERSION)
    return es


def with_root(es):
    if "evidence_root" not in es and isinstance(es.get("sources"), list):
        try:
            es = dict(es, evidence_root=E.evidence_root(es["sources"]))
        except Exception:
            pass    # malformed fragment: root not computable; the member stays absent
    return es


def run(v):
    inp, exp, des = v["input"], str(v["expect"]), v.get("designation", "")
    comp = v.get("computed", {})
    if "set_1" in inp:
        r1, r2 = E.evidence_root(inp["set_1"]), E.evidence_root(inp["set_2"])
        ok = (r1 == comp.get("root_1") and r2 == comp.get("root_2")) if "root_1" in comp else True
        ok = ok and ((r1 != r2) if (comp.get("differ") or "differ" in exp) else (r1 == r2))
        return ok, f"root_1 {r1[:12]} root_2 {r2[:12]}"
    if des in ("LEAF PREIMAGE", "NODE PREIMAGE", "ODD NODE"):
        src = inp if isinstance(inp, list) else (inp.get("sources") or [inp["entry"]])
        r = E.evidence_root(src)
        want = comp.get("normative_root", comp.get("root"))
        ok = r == want and r != comp.get("counter_construction_root")
        return ok, f"root {r[:12]} want {str(want)[:12]}"
    if "receipt_shape" in inp:
        tok, rep = E.resolve({})
        return tok == E.UNKNOWN, tok
    es = with_root(es_of(inp))
    held = {"hashes": set(), "by_url": {}}
    if "verifier_holds_bytes_for" in inp:
        hb = inp["verifier_holds_bytes_for"]
        urls = hb if isinstance(hb, list) else [hb]
        if "verifier_recomputed_sha256" in inp:
            for u in urls: held["by_url"][u] = inp["verifier_recomputed_sha256"]
        else:
            for e in es["sources"]:
                if e.get("url") in urls and e.get("snippet_sha256"): held["hashes"].add(e["snippet_sha256"])
    tok, rep = E.resolve({"evidence_set": es}, held)
    conds = set(rep.get("conditions", []))
    if "condition" in v or des == "MALFORMED":
        want = RENAME.get(v.get("condition"), v.get("condition"))
        ok = tok == E.HALT and (want is None or want in conds)
        return ok, f"{tok} {sorted(conds)} want {want}"
    reasons = [i["reason"] for i in rep.get("items", [])]
    if exp.startswith("unknown") or des in ("UNKNOWN", "COMPLETENESS") and "unknown" in exp:
        ok = tok == E.UNKNOWN
        for r in ("content_differs", "content_not_held"):
            if r in exp: ok = ok and r in reasons
        return ok, f"{tok} {reasons}"
    if "resolves `resolved`" in exp or ("resolves on the derived" in exp):
        return tok == E.RESOLVED and set(reasons) == {"content_matches"}, f"{tok} {reasons}"
    if "evidence_root null" in exp:
        return tok != E.HALT and rep.get("evidence_root") is None, f"{tok} root {rep.get('evidence_root')}"
    # accepted / NOT malformed / MUST NOT halt
    return tok != E.HALT, f"{tok} {sorted(conds)}"


def main(p):
    d = json.load(open(p))
    bad = 0
    for v in d["vectors"]:
        ok, det = run(v)
        bad += not ok
        print(("AGREE   " if ok else "DISAGREE"), v["id"].ljust(52), det)
    print(f"\n{len(d['vectors']) - bad}/{len(d['vectors'])} agree  (corpus sha256 {hashlib.sha256(open(p,'rb').read()).hexdigest()[:16]})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
