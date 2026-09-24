#!/usr/bin/env python3
"""Tests for tools/evidence_set_check.py (cold implementation of draft-krausz-verification-state-02 5.3 / 5.4.1)."""
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
    tok, rep = E.resolve({"evidence_set": es})
    return rep.get("condition") if tok == E.HALT else None


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
            "retrieved_at_not_canonical_form": lambda es: es["sources"][2].update(retrieved_at="2026-09-24T12:00:05Z"),
            "pinned_absent_or_not_boolean": lambda es: es["sources"][2].update(pinned="false"),
            "snippet_digest_present_for_full_resource": lambda es: es["sources"][2].update(content_kind="full_resource", resource_sha256=h(b"r")),
            "duplicate_bound_tuple": lambda es: es["sources"].append(dict(es["sources"][2])) or es.update(source_count=4),
            "root_not_recomputable_from_sources": lambda es: es.update(evidence_root="0" * 64),
            "snippet_sha256_absent_when_pinned": lambda es: es["sources"][0].update(snippet_sha256=None),
        }
        for cond, f in cases.items():
            with self.subTest(cond):
                self.assertEqual(self.m(f), cond)

    def test_pinned_and_unpinned_same_retrieval_is_duplicate(self):
        d = dict(U(A["url"], ts=A["retrieved_at"]))
        self.assertEqual(self.m(lambda es: es["sources"].append(d) or es.update(source_count=4)), "duplicate_bound_tuple")

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


if __name__ == "__main__":
    unittest.main(verbosity=1)
