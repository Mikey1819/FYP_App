import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

from hardening.demo import CATALOGUE, CURRENT_RESULTS, PREVIOUS_RESULTS, RISKS
from hardening.domain import (
    EvidenceMode, Operator, RiskFactors, Rule, Status, assess, change_kind,
    comparable, drift_factor, prioritise, risk_level, summarise,
)


def with_value(result, value, **changes):
    return assess(result.assessment_id, result.control, replace(result.evidence, value=value, **changes))


class ComparisonTests(unittest.TestCase):
    def test_password_minimum_accepts_stronger_values(self):
        result = CURRENT_RESULTS[1]
        for value, status in ((13, Status.NON_COMPLIANT), (14, Status.COMPLIANT), (20, Status.COMPLIANT)):
            with self.subTest(value=value):
                self.assertEqual(with_value(result, value).status, status)

    def test_lockout_range_includes_bounds_and_rejects_zero(self):
        result = CURRENT_RESULTS[0]
        for value, compliant in ((0, False), (1, True), (10, True), (11, False)):
            self.assertEqual(with_value(result, value).status == Status.COMPLIANT, compliant)

    def test_missing_failed_and_malformed_evidence_are_not_compliance(self):
        result = CURRENT_RESULTS[1]
        self.assertEqual(with_value(result, None).status, Status.UNKNOWN)
        self.assertEqual(with_value(result, 14, error="Access denied").status, Status.ERROR)
        self.assertEqual(with_value(result, 14, error="").status, Status.ERROR)
        for value in ("14", True, 14.0, [14], {"value": 14}):
            with self.subTest(value=value):
                self.assertEqual(with_value(result, value).status, Status.ERROR)

    def test_boolean_configuration_rejects_integer_aliases(self):
        self.assertEqual(with_value(CURRENT_RESULTS[4], True).status, Status.COMPLIANT)
        self.assertEqual(with_value(CURRENT_RESULTS[4], 1).status, Status.ERROR)

    def test_bad_rules_fail_at_catalogue_creation(self):
        for operator, value in ((Operator.AT_LEAST, "14"), (Operator.BETWEEN, (10, 1)),
                                (Operator.BETWEEN, (False, 10)), (Operator.EQUALS, [1]),
                                ("at_least", 14)):
            with self.subTest(operator=operator, value=value), self.assertRaises(ValueError):
                Rule(operator, value)

    def test_evidence_identity_and_metadata_required(self):
        result = CURRENT_RESULTS[0]
        with self.assertRaises(ValueError):
            assess("new", CATALOGUE[1], result.evidence)
        with self.assertRaises(ValueError):
            replace(result.evidence, collected_at=result.evidence.collected_at.replace(tzinfo=None))
        with self.assertRaises(ValueError):
            replace(result.evidence, mode="live")
        with self.assertRaises(ValueError):
            replace(result.evidence, target_id="")

    def test_assessment_snapshot_is_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            CURRENT_RESULTS[0].evidence.value = 10

    def test_coverage_separates_unavailable_evidence(self):
        results = (CURRENT_RESULTS[2], CURRENT_RESULTS[0],
                   with_value(CURRENT_RESULTS[1], None),
                   with_value(CURRENT_RESULTS[3], None, error="Permission denied"))
        summary = summarise(results)
        self.assertEqual((summary.selected, summary.evaluated, summary.errors, summary.unknown), (4, 2, 1, 1))
        self.assertEqual(summary.compliance_percent, 50)
        self.assertIsNone(summarise((with_value(CURRENT_RESULTS[0], None),)).compliance_percent)
        self.assertIsNone(summarise(()).compliance_percent)

    def test_summary_rejects_duplicate_and_mixed_assessments(self):
        with self.assertRaises(ValueError):
            summarise((CURRENT_RESULTS[0], CURRENT_RESULTS[0]))
        with self.assertRaises(ValueError):
            summarise((CURRENT_RESULTS[0], PREVIOUS_RESULTS[1]))


class HistoryAndRiskTests(unittest.TestCase):
    def test_regression_and_improvement_have_distinct_meanings(self):
        self.assertEqual(change_kind(PREVIOUS_RESULTS[0], CURRENT_RESULTS[0]), "Regression")
        self.assertEqual(drift_factor(CURRENT_RESULTS[0], PREVIOUS_RESULTS[0]), 5)
        self.assertEqual(change_kind(PREVIOUS_RESULTS[3], CURRENT_RESULTS[3]), "Improvement")
        with self.assertRaises(ValueError):
            drift_factor(CURRENT_RESULTS[3], PREVIOUS_RESULTS[3])

    def test_changed_but_still_noncompliant_receives_documented_factor(self):
        current = with_value(CURRENT_RESULTS[1], 10)
        self.assertEqual(change_kind(PREVIOUS_RESULTS[1], current), "Changed; compliance unchanged")
        self.assertEqual(drift_factor(current, PREVIOUS_RESULTS[1]), 3)
        self.assertEqual(drift_factor(CURRENT_RESULTS[1], PREVIOUS_RESULTS[1]), 3)
        self.assertEqual(drift_factor(current), 1)

    def test_incompatible_history_is_not_used_to_invent_regression(self):
        current = CURRENT_RESULTS[0]
        previous = PREVIOUS_RESULTS[0]
        alternatives = (
            replace(previous, evidence=replace(previous.evidence, target_id="OTHER")),
            replace(previous, evidence=replace(previous.evidence, mode=EvidenceMode.LIVE)),
            replace(previous, control=replace(previous.control, catalogue_version="other")),
            replace(previous, control=replace(previous.control, profile="other")),
            replace(previous, control=replace(previous.control, rule=Rule(Operator.AT_LEAST, 1))),
            replace(previous, evidence=replace(previous.evidence, collected_at=current.evidence.collected_at + timedelta(seconds=1))),
            replace(previous, assessment_id=current.assessment_id),
            with_value(previous, None),
        )
        for other in alternatives:
            with self.subTest(previous=other):
                self.assertFalse(comparable(other, current))
                self.assertEqual(drift_factor(current, other), 1)

    def test_unavailable_and_compliant_results_have_no_risk(self):
        for result in (CURRENT_RESULTS[2], with_value(CURRENT_RESULTS[0], None),
                       with_value(CURRENT_RESULTS[0], None, error="Access denied")):
            with self.assertRaises(ValueError):
                prioritise(result, impact=4, exposure=3, privilege=3, likelihood=3)

    def test_risk_factor_validation(self):
        for bad in (None, True, "3", 0, 6, 2.5):
            with self.subTest(exposure=bad), self.assertRaises(ValueError):
                RiskFactors(4, bad, 3, 3, 1)
        with self.assertRaises(ValueError):
            RiskFactors(4, 3, 3, 3, 2)

    def test_score_extremes_and_classification_boundaries(self):
        self.assertEqual(RiskFactors(1, 1, 1, 1, 1).score, 20)
        self.assertEqual(RiskFactors(5, 5, 5, 5, 5).score, 100)
        for score, level in ((20, "Low"), (39, "Low"), (40, "Moderate"), (59, "Moderate"),
                             (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical")):
            self.assertEqual(risk_level(score), level)
        for score in (0, 19, 101, True, 80.0):
            with self.assertRaises(ValueError):
                risk_level(score)

    def test_demo_risk_uses_history_and_repeatable_calculation(self):
        first = prioritise(CURRENT_RESULTS[0], impact=4, exposure=3, privilege=3,
                           likelihood=3, previous=PREVIOUS_RESULTS[0])
        second = prioritise(CURRENT_RESULTS[0], impact=4, exposure=3, privilege=3,
                            likelihood=3, previous=PREVIOUS_RESULTS[0])
        self.assertEqual(first, second)
        self.assertEqual(first.score, 70)
        self.assertEqual(RISKS["DEMO-LOCKOUT"]["score"], 70)
        self.assertEqual(RISKS["DEMO-NLA"]["score"], 85)
        self.assertEqual(RISKS["DEMO-PASSWORD"]["score"], 56)
        self.assertTrue(all(not control.source_verified for control in CATALOGUE))


if __name__ == "__main__":
    unittest.main()
