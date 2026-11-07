"""Independent cross-check (task 17): the direct-probe result, computed with the SCAP results removed, against
OpenSCAP's own verdict (ComplianceAsCode content, a separate implementation). Expected before any run: agreement,
except the documented SSH explicit-line category (decision 2026-11-07). Synthetic observations; no store or VM."""
import unittest

from tests.integration.ubuntu_fixtures import FAILURES, cases, observation

RULE = 'xccdf_org.ssgproject.content_rule_'


def facts(cid, *, failing=False, scap=None):
    obs = cases()[cid]
    if failing:
        key, value = FAILURES[cid]
        obs[key] = observation(value)
    if scap is not None:
        obs['scap_rules'] = observation(scap)
    return obs


def rules(cid, result):
    from backends.ubuntu.predicates import SCAP_RULES
    return {r: result for r in SCAP_RULES[cid]}


class ScapVerdictTests(unittest.TestCase):
    def test_openscap_results_aggregate_like_xccdf(self):
        from tools.scap_cross_check import scap_verdict
        cases_ = [({'a': 'pass', 'b': 'pass'}, 'Compliant'), ({'a': 'pass', 'b': 'fail'}, 'Non-Compliant'),
                  ({'a': 'pass', 'b': 'notapplicable'}, 'Compliant'), ({'a': 'notapplicable'}, 'Not applicable'),
                  ({'a': 'fail', 'b': 'error'}, 'Non-Compliant'), ({'a': 'pass', 'b': 'error'}, 'Unresolved'),
                  ({}, 'Unresolved')]
        for results, verdict in cases_:
            with self.subTest(results=results):
                self.assertEqual(scap_verdict(results), verdict)


class CompareTests(unittest.TestCase):
    def compare(self, cid, obs):
        from tools.scap_cross_check import compare
        return compare(cid, obs)

    def test_the_direct_side_never_sees_the_scap_results(self):
        # A SCAP failure alone would make the full predicate Unknown (conflict); the direct side stays Compliant.
        row = self.compare('3.3.2', facts('3.3.2', scap=rules('3.3.2', 'fail')))
        self.assertEqual((row['direct'], row['scap'], row['verdict']), ('Compliant', 'Non-Compliant', 'Disagree'))

    def test_agreement_both_ways(self):
        self.assertEqual(self.compare('3.3.2', facts('3.3.2', scap=rules('3.3.2', 'pass')))['verdict'], 'Agree')
        self.assertEqual(self.compare('3.3.2', facts('3.3.2', failing=True, scap=rules('3.3.2', 'fail')))['verdict'],
                         'Agree')

    def test_the_documented_ssh_explicit_line_category_is_labelled_not_hidden(self):
        row = self.compare('5.1.20', facts('5.1.20', scap=rules('5.1.20', 'fail')))
        self.assertEqual((row['direct'], row['scap']), ('Compliant', 'Non-Compliant'))
        self.assertEqual(row['verdict'], 'Expected disagreement (SSH explicit line)')

    def test_an_ssh_failure_seen_by_both_is_plain_agreement(self):
        row = self.compare('5.1.20', facts('5.1.20', failing=True, scap=rules('5.1.20', 'fail')))
        self.assertEqual(row['verdict'], 'Agree')

    def test_not_applicable_or_unresolved_sides_are_not_comparable(self):
        self.assertEqual(self.compare('3.3.2', facts('3.3.2', scap=rules('3.3.2', 'notapplicable')))['verdict'],
                         'Not comparable')
        self.assertEqual(self.compare('1.2.2.1', facts('1.2.2.1'))['verdict'], 'Not comparable')  # Manual: no SCAP


if __name__ == '__main__':
    unittest.main()
