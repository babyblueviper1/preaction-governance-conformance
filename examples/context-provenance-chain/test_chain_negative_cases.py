#!/usr/bin/env python3
"""Negative cases for tools/proof_chain_check.py (trace-spec#279 review): changed values and misleading text.

    python3 examples/context-provenance-chain/test_chain_negative_cases.py

Stdlib only, no network. Two layers:
  * comparison-layer tests feed payload dicts straight to compare_claim(), isolating the field comparison from the
    signature check (an edited claim inside a real signed event would fail id_integrity first -- tested separately);
  * end-to-end tests run check_chain() on the real published events, and on copies edited after signing.
Each comparison case also runs the SUPERSEDED substring check (`value in disclosed_summary`) to show which cases it
wrongly passed -- the reason it was replaced.
"""
import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
from proof_chain_check import CANNOT, FAIL, PASS, check_chain, check_label, compare_claim, parse_claim  # noqa: E402
from _bip340_nostr import verify_proof  # noqa: E402


def load(name):
    with open(os.path.join(HERE, "events", name)) as f:
        return json.load(f)


INNER_EV = load("inner_7aa10c97.json")
OUTER_EV = load("outer_303c3d92_bound.json")
REFFAIL_EV = load("outer_679b0a16_reference_failed_verification.json")
INNER = verify_proof(INNER_EV)["proof_payload"]
OUTER = verify_proof(OUTER_EV)["proof_payload"]
GOOD = OUTER["disclosed_summary"]


def legacy_substring_check(summary, inner, inner_event_id):
    """The superseded comparison: does each value appear ANYWHERE in the text?"""
    return all(v in summary for v in (inner["decision_ref"], inner_event_id, inner["artifact_hash"],
                                      inner["verdict"], str(inner["verified_at"]), inner["policy_version"]))


def statuses(summary, inner=INNER, event_id=INNER_EV["id"]):
    return compare_claim({"disclosed_summary": summary}, inner, event_id)


def by_name(results, field):
    return next(s for s, n, _ in results if n == f"claim {field} == inner {field}")


class BaselineAndGrammar(unittest.TestCase):
    def test_real_pair_passes_every_check(self):
        res = check_chain(OUTER_EV, INNER_EV)
        self.assertEqual({s for s, _, _ in res}, {PASS}, res)
        self.assertEqual(len(res), 10)

    def test_claim_parses_into_named_fields(self):
        c = parse_claim(GOOD)
        self.assertEqual(c["verdict"], INNER["verdict"])
        self.assertEqual(c["verified_at"], str(INNER["verified_at"]))
        self.assertEqual(c["event_id"], INNER_EV["id"])


class ChangedValues(unittest.TestCase):
    """One field changed at a time: exactly that field FAILs, the others still PASS."""

    def mutate(self, old, new):
        self.assertEqual(GOOD.count(old), 1, f"fixture must contain {old!r} exactly once")
        return GOOD.replace(old, new)

    def one_field_fails(self, summary, field):
        res = statuses(summary)
        self.assertEqual(by_name(res, field), FAIL, res)
        self.assertEqual([n for s, n, _ in res if s == FAIL], [f"claim {field} == inner {field}"], res)

    def test_verdict_changed(self):
        self.one_field_fails(self.mutate("verdict approve_with_concerns", "verdict reject"), "verdict")

    def test_artifact_hash_changed_one_char(self):
        h = INNER["artifact_hash"]
        self.one_field_fails(self.mutate(h, h[:-1] + ("0" if h[-1] != "0" else "1")), "artifact_hash")

    def test_verified_at_changed(self):
        self.one_field_fails(self.mutate(f"verified_at {INNER['verified_at']}", f"verified_at {INNER['verified_at'] + 1}"), "verified_at")

    def test_policy_version_changed(self):
        self.one_field_fails(self.mutate("policy_version invinoveritas.review.v19", "policy_version invinoveritas.review.v18"), "policy_version")

    def test_decision_ref_changed(self):
        d = INNER["decision_ref"]
        self.one_field_fails(self.mutate(d, d[:-1] + ("0" if d[-1] != "0" else "1")), "decision_ref")

    def test_event_id_changed(self):
        e = INNER_EV["id"]
        self.one_field_fails(self.mutate(e, e[:-1] + ("0" if e[-1] != "0" else "1")), "event_id")


class MisleadingText(unittest.TestCase):
    """Cases the substring check passed (or would) and the field comparison must not."""

    def test_approve_is_not_not_approve(self):
        inner = dict(INNER, verdict="approve")
        claim = GOOD.replace("verdict approve_with_concerns", "verdict not_approve")
        self.assertTrue(legacy_substring_check(claim, inner, INNER_EV["id"]), "old check wrongly passes this")
        self.assertEqual(by_name(statuses(claim, inner), "verdict"), FAIL)

    def test_verified_at_with_extra_digit(self):
        v = str(INNER["verified_at"])
        claim = GOOD.replace(f"verified_at {v}", f"verified_at {v}0")
        self.assertTrue(legacy_substring_check(claim, INNER, INNER_EV["id"]), "old check wrongly passes this")
        self.assertEqual(by_name(statuses(claim), "verified_at"), FAIL)

    def test_verified_at_with_leading_zero(self):
        v = str(INNER["verified_at"])
        claim = GOOD.replace(f"verified_at {v}", f"verified_at 0{v}")
        self.assertTrue(legacy_substring_check(claim, INNER, INNER_EV["id"]), "old check wrongly passes this")
        self.assertEqual(by_name(statuses(claim), "verified_at"), FAIL)

    def test_policy_version_with_longer_suffix(self):
        claim = GOOD.replace("policy_version invinoveritas.review.v19", "policy_version invinoveritas.review.v190")
        self.assertTrue(legacy_substring_check(claim, INNER, INNER_EV["id"]), "old check wrongly passes this")
        self.assertEqual(by_name(statuses(claim), "policy_version"), FAIL)

    def test_values_present_but_in_the_wrong_slots(self):
        eid, ah = INNER_EV["id"], INNER["artifact_hash"]
        claim = GOOD.replace(eid, "@@").replace(ah, eid).replace("@@", ah)  # swap event-id and artifact_hash slots
        self.assertTrue(legacy_substring_check(claim, INNER, eid), "old check wrongly passes this")
        res = statuses(claim)
        self.assertEqual(by_name(res, "event_id"), FAIL)
        self.assertEqual(by_name(res, "artifact_hash"), FAIL)

    def test_correct_values_appended_after_wrong_ones(self):
        claim = GOOD + f" (For the record: verdict {INNER['verdict']}, verified_at {INNER['verified_at']}.)"
        self.assertTrue(legacy_substring_check(claim, INNER, INNER_EV["id"]))
        self.assertEqual({s for s, _, _ in statuses(claim)}, {CANNOT})

    def test_contradicting_sentence_appended(self):
        claim = GOOD + " Correction: the referenced verdict was actually not_approve."
        self.assertTrue(legacy_substring_check(claim, INNER, INNER_EV["id"]))
        self.assertEqual({s for s, _, _ in statuses(claim)}, {CANNOT})

    def test_duplicate_conflicting_verdict_clause(self):
        claim = GOOD.replace(f"verdict {INNER['verdict']},", f"verdict {INNER['verdict']}, verdict not_approve,")
        self.assertTrue(legacy_substring_check(claim, INNER, INNER_EV["id"]))
        self.assertEqual({s for s, _, _ in statuses(claim)}, {CANNOT})

    def test_field_missing(self):
        claim = GOOD.replace(f", verified_at {INNER['verified_at']}", "")
        self.assertEqual({s for s, _, _ in statuses(claim)}, {CANNOT})

    def test_uppercase_hex_is_not_recognised(self):
        claim = GOOD.replace(INNER["artifact_hash"], INNER["artifact_hash"].upper())
        self.assertEqual({s for s, _, _ in statuses(claim)}, {CANNOT})

    def test_free_text_only_is_not_a_pass(self):
        res = statuses("looks fine to me, references the earlier verdict")
        self.assertEqual({s for s, _, _ in res}, {CANNOT})


class ChainAndLabel(unittest.TestCase):
    def test_related_decision_ref_mismatch_fails(self):
        d = dict(INNER, decision_ref="sha256:" + "0" * 64)
        e = INNER_EV["id"]
        res = compare_claim(OUTER, d, e)
        self.assertEqual(by_name(res, "decision_ref"), FAIL)

    def test_reference_that_failed_verification_is_not_upgraded(self):
        res = check_chain(REFFAIL_EV, INNER_EV)
        st = {n: s for s, n, _ in res}
        self.assertEqual(st["outer carries a related_decision_ref"], CANNOT)
        self.assertEqual(st["outer.context_provenance consistent with the signed related_decision_ref"], PASS)
        self.assertNotIn(FAIL, st.values())

    def test_edited_claim_inside_a_signed_event_breaks_the_signature_first(self):
        e = copy.deepcopy(OUTER_EV)
        e["content"] = e["content"].replace("verdict approve_with_concerns,", "verdict reject,")
        self.assertNotEqual(e["content"], OUTER_EV["content"])
        res = check_chain(e, INNER_EV)
        self.assertEqual(res[0][0], FAIL)
        self.assertIn("id_integrity", res[0][2])

    def test_label_inconsistent_with_reference_is_reported_as_inconsistency(self):
        bound_but_no_ref = dict(OUTER, related_decision_ref=None)          # label says bound, reference absent
        asserted_but_has_ref = dict(OUTER, context_provenance="caller_asserted_unverified")  # reference present
        for payload in (bound_but_no_ref, asserted_but_has_ref):
            status, _, detail = check_label(payload)
            self.assertEqual(status, FAIL)
            self.assertIn("inconsistent with the signed reference", detail)
            self.assertNotIn("tamper", detail.lower())
        self.assertEqual(check_label(OUTER)[0], PASS)
        self.assertEqual(check_label(verify_proof(REFFAIL_EV)["proof_payload"])[0], PASS)


class ManifestMatches(unittest.TestCase):
    def test_published_files_match_manifest(self):
        import hashlib
        with open(os.path.join(HERE, "MANIFEST.sha256")) as m:
            entries = [line.split() for line in m if line.strip()]
        self.assertEqual(len(entries), 3)
        for digest, path in entries:
            with open(os.path.join(HERE, path), "rb") as f:
                self.assertEqual(hashlib.sha256(f.read()).hexdigest(), digest, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
