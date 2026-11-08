"""The 32-control catalogue with fixture evidence only."""
import unittest

from hardening.domain import Operator, Rule, Status, summarise
from hardening.server2022_catalogue import CATALOGUE, CATALOGUE_ID, SOURCES
from evidence_fixture import evidence_fixture, load, observation


class CatalogueTests(unittest.TestCase):
    def test_thirty_two_controls_across_the_five_report_areas(self):
        result = load(evidence_fixture())
        self.assertEqual(summarise(result.results).compliant, 32)
        areas = {}
        for r in result.results:
            areas[r.control.area] = areas.get(r.control.area, 0) + 1
        self.assertEqual(areas, {'Account Policies': 9, 'Local Security Options': 5, 'Windows Defender Firewall': 8,
                                 'Advanced Audit Policy': 5, 'Remote Desktop Services': 5})
        self.assertEqual({r.control.catalogue_version for r in result.results}, {CATALOGUE_ID})
        self.assertTrue(all(r.control.source_verified for r in result.results))

    def test_audit_include_semantics(self):
        include_success = Rule(Operator.HAS_FLAGS, 1)
        self.assertEqual([include_success.matches(v) for v in (0, 1, 2, 3)], [False, True, False, True])
        both = Rule(Operator.HAS_FLAGS, 3)
        self.assertEqual([both.matches(v) for v in (0, 1, 2, 3)], [False, False, False, True])
        with self.assertRaises(ValueError):
            Rule(Operator.HAS_FLAGS, 0)
        with self.assertRaises(ValueError):
            both.matches(True)  # bool is not an audit flag value.

    def test_default_audit_and_unconfigured_policies(self):
        data = evidence_fixture()
        observation(data, '17.1.1')['value'] = 1      # Windows default: Success only.
        observation(data, '17.5.1')['value'] = 1      # Success only does not include Failure.
        observation(data, '17.2.2')['value'] = 3      # Success and Failure includes Success.
        observation(data, '9.2.6').update(state='missing', value=None)      # Group Policy: Not configured.
        observation(data, '2.3.10.2').update(state='missing', value=None)   # Non-policy LSA value.
        status = {r.control.control_id: r.status for r in load(data).results}
        self.assertEqual(status['17.1.1'], Status.NON_COMPLIANT)
        self.assertEqual(status['17.5.1'], Status.NON_COMPLIANT)
        self.assertEqual(status['17.2.2'], Status.COMPLIANT)
        self.assertEqual(status['9.2.6'], Status.NON_COMPLIANT)
        self.assertEqual(status['2.3.10.2'], Status.UNKNOWN)

    def test_not_configured_rule_applies_exactly_to_group_policy_sources(self):
        for control in CATALOGUE:
            with self.subTest(control=control.control_id):
                self.assertEqual(control.not_configured_fails,
                                 SOURCES[control.control_id].startswith('HKLM\\SOFTWARE\\Policies\\'))

    def test_registered_sources_and_incomplete_exports_are_enforced(self):
        data = evidence_fixture()
        observation(data, '18.10.57.3.9.3')['source'] = r'HKLM\SOFTWARE\Elsewhere:SecurityLayer'
        with self.assertRaises(ValueError):
            load(data)
        data = evidence_fixture()
        data['observations'] = [o for o in data['observations'] if o['control_id'] != '17.5.4']
        with self.assertRaisesRegex(ValueError, 'all 32 selected controls'):
            load(data)

    def test_every_control_has_one_source_in_catalogue_order(self):
        self.assertEqual([c.control_id for c in CATALOGUE], list(SOURCES))

    def test_catalogue_has_no_report_ids_absent_from_the_standalone_edition(self):
        ids = {c.control_id for c in CATALOGUE}
        self.assertFalse(ids & {'9.1.1', '9.1.2', '9.1.6', '9.3.8', '17.2.5', '17.2.6'})


if __name__ == '__main__':
    unittest.main()
