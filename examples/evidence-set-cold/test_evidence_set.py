#!/usr/bin/env python3
"""Tests for tools/evidence_set_check.py (cold implementation of draft-krausz-verification-state-03 5.3 / 5.4.1)."""
import copy, hashlib, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import evidence_set_check as E


def h(b):
    return hashlib.sha256(b).hexdigest()


def P(url, content, ts="2026-09-24T12:00:00.000Z", kind="snippet"):
    return {"url": url, "snippet_sha256": h(content), "retrieved_at": ts, "pinned": True, "content_kind": kind}


def U(url, ts="2026-09-24T12:00:05.000Z", reason="no_content_returned"):
    return {"url": url, "snippet_sha256": None, "retrieved_at": ts, "pinned": False, "unpinned_reason": reason}


A, B, C = P("https://a.example/x", b"alpha"), P("https://b.example/y", b"beta", "2026-09-24T12:00:01.000Z"), P("https://c.example/z", b"gamma", "2026-09-24T12:00:02.000Z")


def halt(es):
    """Reported condition SET (conformance compares sets, never order), or None if not malformed."""
    tok, rep = E.resolve({"evidence_set": es})
    return set(rep["conditions"]) if tok == E.HALT else None


class Root(unittest.TestCase):
    def test_single_item_root_is_its_leaf(self):
        self.assertEqual(E.evidence_root([A]), E.leaf(A).hex())

    def test_odd_node_promoted_not_duplicated(self):
        la, lb, lc = (E.leaf(x) for x in (A, B, C))
        self.assertEqual(E.evidence_root([C, A, B]), E.node(E.node(la, lb), lc).hex())
        self.assertNotEqual(E.evidence_root([A, B, C]), E.node(E.node(la, lb), E.node(lc, lc)).hex())

    def test_root_independent_of_order_and_of_unpinned_items(self):
        r = E.evidence_root([A, B, C])
        self.assertEqual(r, E.evidence_root([C, B, A]))
        self.assertEqual(r, E.evidence_root([B, U("https://d.example/"), C, A]))

    def test_empty_pinned_set_has_no_root(self):
        self.assertIsNone(E.evidence_root([U("https://d.example/")]))

    def test_leaf_uses_hex_text_and_node_uses_raw_octets(self):
        want = hashlib.sha256(b"ao-evidence-leaf-v2\x00https://a.example/x\x00" + h(b"alpha").encode() + b"\x00snippet\x002026-09-24T12:00:00.000Z").digest()
        self.assertEqual(E.leaf(A), want)
        self.assertEqual(E.node(b"\x01" * 32, b"\x02" * 32), hashlib.sha256(b"ao-evidence-node-v1\x00" + b"\x01" * 32 + b"\x00" + b"\x02" * 32).digest())


class Resolution(unittest.TestCase):
    def test_fully_pinned_and_all_content_held_resolves(self):
        es = E.build([A, B])
        tok, rep = E.resolve({"evidence_set": es}, {"hashes": {h(b"alpha"), h(b"beta")}})
        self.assertEqual(tok, E.RESOLVED)
        self.assertEqual({i["reason"] for i in rep["items"]}, {"content_matches"})

    def test_fully_pinned_content_not_held_is_unknown_not_failure(self):
        tok, rep = E.resolve({"evidence_set": E.build([A, B])})
        self.assertEqual(tok, E.UNKNOWN)
        self.assertEqual([i["reason"] for i in rep["items"]], ["content_not_held"] * 2)

    def test_content_differs_is_unknown_and_reported_per_item(self):
        tok, rep = E.resolve({"evidence_set": E.build([A, B])}, {"hashes": {h(b"alpha")}, "by_url": {B["url"]: h(b"BETA")}})
        self.assertEqual(tok, E.UNKNOWN)
        self.assertEqual([i["reason"] for i in rep["items"]], ["content_matches", "content_differs"])

    def test_partial_set_is_valid_unknown_and_every_entry_reported(self):
        es = E.build([A, U("https://d.example/")])
        tok, rep = E.resolve({"evidence_set": es}, {"hashes": {h(b"alpha")}})
        self.assertEqual(tok, E.UNKNOWN)
        self.assertEqual(len(rep["items"]), 2)
        self.assertEqual(rep["items"][1]["reason"], "content_not_held")

    def test_zero_pinned_is_legal(self):
        es = E.build([U("https://d.example/"), U("https://e.example/", reason="provider_metadata_only")])
        self.assertIsNone(es["evidence_root"]); self.assertFalse(es["fully_pinned"])
        self.assertEqual(E.resolve({"evidence_set": es})[0], E.UNKNOWN)

    def test_no_evidence_set_is_unknown(self):
        self.assertEqual(E.resolve({"v_verdict": "verified"})[0], E.UNKNOWN)

    def test_counts_absent_are_derived_not_halted(self):
        es = E.build([A, B])
        for k in ("source_count", "pinned_count", "fully_pinned"):
            es.pop(k)
        self.assertEqual(E.resolve({"evidence_set": es}, {"hashes": {h(b"alpha"), h(b"beta")}})[0], E.RESOLVED)


class Malformed(unittest.TestCase):
    def setUp(self):
        self.es = E.build([A, B, U("https://d.example/")])

    def m(self, f):
        es = copy.deepcopy(self.es); f(es); return halt(es)

    def test_named_conditions(self):
        cases = {
            "set_retrieved_at_not_bytewise_least": lambda es: es.update(retrieved_at="2026-09-24T12:00:01.000Z"),
            "evidence_set_names_no_sources": lambda es: es.update(sources=[], source_count=0),
            "sources_not_array": lambda es: es.update(sources={"0": A}),
            "retrieved_at_not_canonical_form": lambda es: es["sources"][2].update(retrieved_at="2026-09-24T12:00:05Z"),
            "pinned_absent_or_not_boolean": lambda es: es["sources"][2].update(pinned="false"),
            "resource_sha256_present_for_full_resource": lambda es: es["sources"][0].update(content_kind="full_resource", resource_sha256=h(b"r")) or es.update(evidence_root=E.evidence_root(es["sources"])),
            "duplicate_bound_tuple": lambda es: es["sources"].append(dict(es["sources"][2])) or es.update(source_count=4),
            "root_not_recomputable_from_sources": lambda es: es.update(evidence_root="0" * 64),
            "snippet_sha256_absent_when_pinned": lambda es: es["sources"][0].update(snippet_sha256=None),
        }
        for cond, f in cases.items():
            with self.subTest(cond):
                self.assertEqual(self.m(f), {cond})

    def test_pinned_and_unpinned_same_retrieval_is_duplicate(self):
        d = dict(U(A["url"], ts=A["retrieved_at"]))
        self.assertEqual(self.m(lambda es: es["sources"].append(d) or es.update(source_count=4)), {"duplicate_bound_tuple"})

    def test_same_content_different_time_is_not_duplicate(self):
        e = dict(A, retrieved_at="2026-09-24T13:00:00.000Z")
        self.assertIsNone(halt(E.build([A, e])))

    def test_unnamed_but_malformed_conditions_still_halt(self):
        for f in (lambda es: es.update(pinned_count=3),
                  lambda es: es.update(fully_pinned=True),
                  lambda es: es.update(source_count=5),
                  lambda es: es["sources"][2].pop("unpinned_reason"),
                  lambda es: es["sources"][2].update(snippet_sha256=h(b"held")),
                  lambda es: es["sources"][0].update(content_kind=None),
                  lambda es: es["sources"][0].update(snippet_sha256=h(b"alpha").upper()),
                  lambda es: es["sources"][0].update(url="https://a.example/\x00x"),
                  lambda es: es["sources"][2].update(retrieved_at="2026-02-30T12:00:05.000Z"),
                  lambda es: es.update(evidence_root=None)):
            with self.subTest(f=f):
                self.assertIsNotNone(self.m(f))


def es1(sources, **kw):
    d = {"evidence_set_version": E.VERSION, "sources": sources}
    d.update(kw)
    return d


class Dash03Vectors(unittest.TestCase):
    """The five report-all / (k)-stop vectors tabulated in DASH03-COLD-BUILD-RESOLUTIONS.md (TK 5a71863)."""

    def test_case1_pinned_not_boolean_suppresses_branch_and_count_rules(self):
        e = dict(A, pinned="yes")
        self.assertEqual(halt(es1([e], pinned_count=1, fully_pinned=True)), {"pinned_absent_or_not_boolean"})

    def test_case2_malformed_retrieved_at_suppresses_set_wide_rules(self):
        a = U("https://a.example/", ts="2026-09-01T00:00:00.000Z")
        b = U("https://b.example/", ts="2026-9-1")
        self.assertEqual(halt(es1([a, b], retrieved_at="2026-09-01T00:00:00.000Z")), {"retrieved_at_not_canonical_form"})

    def test_k_stop1_not_object(self):
        self.assertEqual(halt(["not", "an", "object"]), {"evidence_set_not_object"})

    def test_k_stop2_version_absent(self):
        self.assertEqual(halt({"sources": [A]}), {"evidence_set_version_absent_or_not_string"})

    def test_k_stop3_version_not_string(self):
        # also carries defects a version-specific rule would report; (k) stops before them
        self.assertEqual(halt({"evidence_set_version": 1, "sources": [], "pinned_count": 9}),
                         {"evidence_set_version_absent_or_not_string"})


class Dash03Rules(unittest.TestCase):
    def test_unsupported_version_is_unknown_and_stops_version_specific_rules(self):
        tok, rep = E.resolve({"evidence_set": es1([dict(A, pinned="yes")], evidence_set_version="ao-evidence-set-v9")})
        self.assertEqual((tok, rep["reason"]), (E.UNKNOWN, "evidence_set_version_unsupported"))

    def test_report_all_independent_defects(self):
        es = E.build([A, B, U("https://d.example/")])
        es["sources"][0]["url"] = 7
        es["sources"][2]["unpinned_reason"] = "paywall"
        es["source_count"] = 9
        self.assertEqual(halt(es), {"url_absent_or_not_string", "unpinned_reason_absent_or_invalid", "source_count_mismatch"})

    def test_root_not_checked_when_a_reports_anything(self):
        es = E.build([A, B]); es["evidence_root"] = "0" * 64; es["source_count"] = 3
        self.assertEqual(halt(es), {"source_count_mismatch"})

    def test_entry_not_object_skips_only_that_entry(self):
        es = E.build([A, B]); es["sources"][1] = "x"
        self.assertEqual(halt(es), {"source_entry_not_object"})

    def test_leap_second_rejected(self):
        self.assertEqual(halt(es1([U("https://d.example/", ts="2026-06-30T23:59:60.000Z")])), {"retrieved_at_not_canonical_form"})

    def test_snippet_absent_when_pinned_reported_with_null_root(self):
        e = dict(A, snippet_sha256=None)
        self.assertEqual(halt(es1([e], evidence_root=None)),
                         {"snippet_sha256_absent_when_pinned", "evidence_root_absent_with_pinned_items"})

    def test_unpinned_digest_and_kind(self):
        e = dict(U("https://d.example/"), snippet_sha256=h(b"x"), content_kind="snippet")
        self.assertEqual(halt(es1([e])), {"snippet_sha256_present_when_unpinned", "content_kind_present_when_unpinned"})


if __name__ == "__main__":
    unittest.main(verbosity=1)
