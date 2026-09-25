#!/usr/bin/env python3
"""Negative vectors for tools/related_claims_check.py and tools/vantage_limitation_check.py (trace-spec#397/#398).

    python3 examples/trace-v20-fixtures/test_v20_negative_cases.py

Stdlib only, no network. Real signed events under events/ (issued by invinoveritas under policy v20). Two layers:
  * end-to-end: edit a real event AFTER signing (changed claims, altered result, stripped field, swapped proof) -- the
    edit breaks id_integrity/signature or the claims-hash binding, so the checker FAILs;
  * comparison-layer: feed the comparison logic payloads that a valid signature could carry (a mismatch recorded as a
    match, a substituted proof, a wrong note for the source_class) with verify_proof stubbed to 'valid', isolating the
    check from the signature check (we cannot mint a validly-signed inconsistent proof).
Exact equality establishes faithful restatement; none of this establishes relevance, authorization or truth.
"""
import copy
import json
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "tools"))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
import related_claims_check as rc  # noqa: E402
import vantage_limitation_check as vl  # noqa: E402


def load(name):
    with open(os.path.join(HERE, "events", name)) as f:
        return json.load(f)


INNER, INNER_OTHER, INNER_TAMPERED = load("inner.json"), load("inner_other.json"), load("inner_tampered.json")
MATCHED, MISMATCHED = load("outer_matched.json"), load("outer_mismatched.json")
MISSING, UNVERIF, NOTSUP = load("outer_missing_proof.json"), load("outer_unverifiable_proof.json"), load("outer_not_supplied.json")
CLAIMS = load("outer_matched_claims.json")
BAD_CLAIMS = load("outer_mismatched_claims.json")
V21_TRADE = load("v21_trade_irreversible.json")   # real signed v21 proof, artifact_type=trade (synthetic proposal, live /review, 2026-09-25)


def statuses(res):
    return [s for s, _, _ in res]


def payload(ev):
    return json.loads(ev["content"])


def resign_stub(ev, **changes):
    """A copy of ev whose payload carries `changes`, plus a verify_proof stub reporting it valid (comparison layer only)."""
    p = payload(ev)
    p.update(changes)
    ev2 = copy.deepcopy(ev)
    ev2["content"] = json.dumps(p, sort_keys=True, separators=(",", ":"))
    return ev2


def stub_valid(orig):
    def _v(event, *a, **k):
        r = orig(event, *a, **k)
        r = dict(r)
        r["valid"] = True
        r["proof_payload"] = json.loads(event["content"])
        return r
    return _v


class Baselines(unittest.TestCase):
    def test_matched_and_mismatched_and_partial_pass_their_own_recompute(self):
        self.assertEqual(set(statuses(rc.check(MATCHED, INNER, CLAIMS))), {rc.PASS})
        self.assertEqual(set(statuses(rc.check(MISMATCHED, INNER, BAD_CLAIMS))), {rc.PASS})
        self.assertEqual(set(statuses(rc.check(load("outer_partial_matched.json"), INNER, load("outer_partial_matched_claims.json")))), {rc.PASS})

    def test_missing_and_unverifiable_and_not_supplied_are_distinct_states(self):
        self.assertEqual(payload(MISSING)["related_claims_result"], "missing_proof")
        self.assertEqual(payload(UNVERIF)["related_claims_result"], "unverifiable_proof")
        self.assertEqual(payload(NOTSUP)["related_claims_result"], "not_supplied")
        self.assertEqual(set(statuses(rc.check(MISSING, None, CLAIMS))), {rc.PASS})
        self.assertEqual(set(statuses(rc.check(UNVERIF, INNER_TAMPERED, CLAIMS))), {rc.PASS})
        self.assertEqual(set(statuses(rc.check(NOTSUP, None, None))), {rc.PASS})

    def test_vantage_baseline(self):
        self.assertEqual(set(statuses(vl.check(INNER))), {vl.PASS})
        self.assertEqual(set(statuses(vl.check(MATCHED))), {vl.PASS})


class ChangedClaims(unittest.TestCase):
    def test_changed_claims_file_fails_the_bound_hash(self):
        res = rc.check(MATCHED, INNER, dict(CLAIMS, verdict="reject"))
        self.assertIn(rc.FAIL, statuses(res))
        self.assertTrue(any(s == rc.FAIL and "related_claims_hash" in n for s, n, _ in res))

    def test_claims_from_the_mismatched_case_do_not_fit_the_matched_proof(self):
        self.assertIn(rc.FAIL, statuses(rc.check(MATCHED, INNER, BAD_CLAIMS)))

    def test_extra_or_unknown_claim_keys_are_outside_the_grammar(self):
        self.assertIn(rc.FAIL, statuses(rc.check(MATCHED, INNER, dict(CLAIMS, extra="x"))))

    def test_non_ascii_claims_cannot_be_canonicalized_here(self):
        self.assertIn(rc.CANNOT, statuses(rc.check(MATCHED, INNER, dict(CLAIMS, verdict="apprové"))))


class AlteredResult(unittest.TestCase):
    def test_result_edited_after_signing_breaks_the_proof(self):
        ev = resign_stub(MISMATCHED, related_claims_result="matched")
        res = rc.check(ev, INNER, BAD_CLAIMS)
        self.assertIn(rc.FAIL, statuses(res))
        self.assertEqual(res[0][0], rc.FAIL)  # outer proof valid -> FAIL (id no longer matches the content)

    def test_hash_or_version_stripped_after_signing_breaks_the_proof(self):
        for field in ("related_claims_hash", "related_claims_comparison_version", "related_claims_result"):
            ev = copy.deepcopy(MATCHED)
            p = payload(ev)
            p.pop(field)
            ev["content"] = json.dumps(p, sort_keys=True, separators=(",", ":"))
            self.assertEqual(rc.check(ev, INNER, CLAIMS)[0][0], rc.FAIL, field)

    def test_comparison_layer_a_mismatch_recorded_as_a_match_is_caught(self):
        with mock.patch.object(rc, "verify_proof", stub_valid(rc.verify_proof)):
            ev = resign_stub(MISMATCHED, related_claims_result="matched")
            res = rc.check(ev, INNER, BAD_CLAIMS)
        self.assertTrue(any(s == rc.FAIL and "recomputed comparison" in n for s, n, _ in res), res)

    def test_comparison_layer_a_match_recorded_as_a_mismatch_is_caught(self):
        with mock.patch.object(rc, "verify_proof", stub_valid(rc.verify_proof)):
            ev = resign_stub(MATCHED, related_claims_result="mismatched")
            res = rc.check(ev, INNER, CLAIMS)
        self.assertTrue(any(s == rc.FAIL and "recomputed comparison" in n for s, n, _ in res), res)


class SubstitutedProof(unittest.TestCase):
    def test_a_different_valid_inner_proof_fails_the_referenced_identity_check(self):
        res = rc.check(MATCHED, INNER_OTHER, CLAIMS)
        self.assertTrue(any(s == rc.FAIL and "referenced proof identity" in n for s, n, _ in res), res)

    def test_the_tampered_inner_proof_fails_its_own_signature(self):
        res = rc.check(MATCHED, INNER_TAMPERED, CLAIMS)
        self.assertTrue(any(s == rc.FAIL and n.startswith("inner proof valid") for s, n, _ in res), res)


class MissingEvidence(unittest.TestCase):
    def test_matched_without_the_inner_event_cannot_be_established(self):
        res = rc.check(MATCHED, None, CLAIMS)
        self.assertIn(rc.CANNOT, statuses(res))
        self.assertNotIn(rc.FAIL, statuses(res))

    def test_unverifiable_without_the_inner_event_cannot_be_established(self):
        # agentrust-io/trace-spec#398: the issuer's signed "did not verify" is an assertion, not reproduced evidence
        uclaims = load("outer_unverifiable_proof_claims.json")
        res = rc.check(UNVERIF, None, uclaims)
        self.assertIn(rc.CANNOT, statuses(res))
        self.assertNotIn(rc.FAIL, statuses(res))

    def test_unverifiable_without_the_inner_event_is_a_policy_refusal_when_the_set_is_complete(self):
        uclaims = load("outer_unverifiable_proof_claims.json")
        with mock.patch.object(rc, "COMPLETE", True):
            self.assertIn(rc.FAIL, statuses(rc.check(UNVERIF, None, uclaims)))

    def test_unverifiable_with_a_really_failing_inner_event_passes(self):
        uclaims = load("outer_unverifiable_proof_claims.json")
        res = rc.check(UNVERIF, load("inner_tampered.json"), uclaims)
        self.assertNotIn(rc.FAIL, statuses(res))
        self.assertNotIn(rc.CANNOT, statuses(res))

    def test_unverifiable_with_an_inner_event_that_does_verify_is_a_fail(self):
        uclaims = load("outer_unverifiable_proof_claims.json")
        self.assertIn(rc.FAIL, statuses(rc.check(UNVERIF, INNER, uclaims)))

    def test_missing_proof_that_still_binds_a_reference_is_a_fail(self):
        with mock.patch.object(rc, "verify_proof", stub_valid(rc.verify_proof)):
            ev = resign_stub(MISSING, related_decision_ref=payload(INNER)["decision_ref"])
            self.assertIn(rc.FAIL, statuses(rc.check(ev, None, CLAIMS)))

    def test_not_supplied_with_a_claims_hash_is_a_fail(self):
        with mock.patch.object(rc, "verify_proof", stub_valid(rc.verify_proof)):
            ev = resign_stub(NOTSUP, related_claims_hash="sha256:" + "0" * 64)
            self.assertIn(rc.FAIL, statuses(rc.check(ev, None, None)))

    def test_pre_v20_proof_cannot_be_checked(self):
        with mock.patch.object(rc, "verify_proof", stub_valid(rc.verify_proof)):
            p = payload(MATCHED)
            ev = copy.deepcopy(MATCHED)
            p["decision_ref_preimage_fields"] = [f for f in p["decision_ref_preimage_fields"] if not f.startswith("related_claims_")]
            ev["content"] = json.dumps(p, sort_keys=True, separators=(",", ":"))
            self.assertEqual(statuses(rc.check(ev, INNER, CLAIMS))[-1], rc.CANNOT)


class VantageNegatives(unittest.TestCase):
    def _stub(self, **changes):
        return resign_stub(INNER, **changes)

    def test_altered_note_after_signing_fails(self):
        ev = self._stub(vantage_limitation=payload(INNER)["vantage_limitation"] + " Sufficient as standalone evidence.")
        self.assertEqual(vl.check(ev)[0][0], vl.FAIL)

    def test_stripped_note_after_signing_fails(self):
        p = payload(INNER)
        p.pop("vantage_limitation")
        ev = copy.deepcopy(INNER)
        ev["content"] = json.dumps(p, sort_keys=True, separators=(",", ":"))
        self.assertEqual(vl.check(ev)[0][0], vl.FAIL)

    def test_comparison_layer_wrong_note_for_source_class(self):
        with mock.patch.object(vl, "verify_proof", stub_valid(vl.verify_proof)):
            other = vl.TABLE["policies"]["invinoveritas.review.v20"]["independent_mediator"]
            self.assertTrue(any(s == vl.FAIL for s, _, _ in vl.check(self._stub(vantage_limitation=other))))

    def test_comparison_layer_note_on_a_non_irreversible_type(self):
        with mock.patch.object(vl, "verify_proof", stub_valid(vl.verify_proof)):
            self.assertTrue(any(s == vl.FAIL for s, _, _ in vl.check(resign_stub(MATCHED, vantage_limitation="x"))))

    def test_comparison_layer_missing_note_on_irreversible_type(self):
        with mock.patch.object(vl, "verify_proof", stub_valid(vl.verify_proof)):
            ev = copy.deepcopy(INNER)
            p = payload(ev)
            p["vantage_limitation"] = None
            ev["content"] = json.dumps(p, sort_keys=True, separators=(",", ":"))
            self.assertTrue(any(s == vl.FAIL for s, _, _ in vl.check(ev)))

    def test_v19_wording_is_archived_and_distinct_from_v20(self):
        v19 = vl.TABLE["policies"]["invinoveritas.review.v19"]["agent_reported"]
        v20 = vl.TABLE["policies"]["invinoveritas.review.v20"]["agent_reported"]
        self.assertIn("Sufficient as standalone evidence for a reversible action", v19)
        self.assertNotIn("Sufficient as standalone", v20)
        with mock.patch.object(vl, "verify_proof", stub_valid(vl.verify_proof)):
            ev19 = self._stub(policy_version="invinoveritas.review.v19", vantage_limitation=v19)
            self.assertEqual({s for s, _, _ in vl.check(ev19)}, {vl.PASS})
            ev19_wrong = self._stub(policy_version="invinoveritas.review.v19", vantage_limitation=v20)
            self.assertIn(vl.FAIL, {s for s, _, _ in vl.check(ev19_wrong)})

    def test_v21_no_note_asserts_non_bypassability(self):
        v20 = vl.TABLE["policies"]["invinoveritas.review.v20"]
        v21 = vl.TABLE["policies"]["invinoveritas.review.v21"]
        for sc in ("platform_operator", "independent_mediator"):
            self.assertIn("cannot bypass this call", v20[sc])      # archived as issued; signed v20 proofs keep it
        for sc, note in v21.items():
            self.assertNotIn("cannot bypass this call", note, sc)
            self.assertIn("does not establish that the source classification is true", note, sc)

    def test_signed_v20_fixture_still_passes_under_archived_wording(self):
        self.assertEqual({s for s, _, _ in vl.check(INNER)}, {vl.PASS})    # real signature, no stubs

    def test_v21_proof_carrying_v20_wording_fails(self):
        with mock.patch.object(vl, "verify_proof", stub_valid(vl.verify_proof)):
            old = vl.TABLE["policies"]["invinoveritas.review.v20"]["independent_mediator"]
            new = vl.TABLE["policies"]["invinoveritas.review.v21"]["independent_mediator"]
            kw = dict(policy_version="invinoveritas.review.v21", source_class="independent_mediator")
            self.assertIn(vl.FAIL, {s for s, _, _ in vl.check(self._stub(vantage_limitation=old, **kw))})
            self.assertEqual({s for s, _, _ in vl.check(self._stub(vantage_limitation=new, **kw))}, {vl.PASS})

    def test_signed_v21_irreversible_fixture_passes_end_to_end(self):
        # trace-spec#397's outstanding item: a REAL signed v21 proof of an irreversible class, no stubs.
        p = payload(V21_TRADE)
        self.assertEqual((p["policy_version"], p["artifact_type"]), ("invinoveritas.review.v21", "trade"))
        self.assertEqual(p["vantage_limitation"], vl.TABLE["policies"]["invinoveritas.review.v21"][p["source_class"]])
        self.assertEqual({s for s, _, _ in vl.check(V21_TRADE)}, {vl.PASS})

    def test_signed_v21_irreversible_fixture_edited_after_signing_fails(self):
        # stripping or swapping the note on the real event breaks id/signature: no stubs, the edit alone must FAIL
        for note in (None, vl.TABLE["policies"]["invinoveritas.review.v20"]["agent_reported"]):
            ev = copy.deepcopy(V21_TRADE)
            p = payload(ev)
            p["vantage_limitation"] = note
            ev["content"] = json.dumps(p, sort_keys=True, separators=(",", ":"))
            self.assertIn(vl.FAIL, {s for s, _, _ in vl.check(ev)})

    def test_unknown_policy_version_cannot_be_checked_for_exact_wording(self):
        with mock.patch.object(vl, "verify_proof", stub_valid(vl.verify_proof)):
            res = vl.check(self._stub(policy_version="invinoveritas.review.v12"))
        self.assertIn(vl.CANNOT, {s for s, _, _ in res})


if __name__ == "__main__":
    unittest.main(verbosity=1)
