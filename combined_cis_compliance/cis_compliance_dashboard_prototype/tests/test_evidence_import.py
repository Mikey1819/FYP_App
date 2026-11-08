"""Evidence format validation with fixture exports; no VM."""
from datetime import datetime, timezone
import json
import unittest

from hardening.domain import Status, summarise
from hardening.evidence_import import load_evidence
from hardening.server2022_catalogue import CATALOGUE
from evidence_fixture import MACHINE_UUID, NOW, evidence_fixture, load, observation, result


class EvidenceImportTests(unittest.TestCase):
    def test_valid_export_uses_reviewed_rules_and_is_repeatable(self):
        payload = evidence_fixture()
        a, b = load(payload), load(payload)
        self.assertEqual(a, b)
        self.assertEqual(summarise(a.results).compliant, 32)
        self.assertTrue(all(r.control.source_verified for r in a.results))
        self.assertTrue(all(r.evidence.mode.value == 'Imported' for r in a.results))
        self.assertEqual(a.target_id, 'windows:' + MACHINE_UUID)

    def test_real_lockout_and_password_boundaries(self):
        for control, cases in (('1.1.4', [(13, False), (14, True), (15, True)]),
                               ('1.2.2', [(0, False), (1, True), (5, True), (6, False), (10, False)])):
            for value, passes in cases:
                with self.subTest(control=control, value=value):
                    data = evidence_fixture()
                    observation(data, control)['value'] = value
                    self.assertEqual(result(load(data), control).status,
                                     Status.COMPLIANT if passes else Status.NON_COMPLIANT)

    def test_guest_and_policy_dword_comparisons(self):
        for control, value in [('2.3.1.1', True), ('9.3.1', 0), ('9.3.1', 2),
                               ('18.10.57.3.9.4', 0), ('18.10.57.3.9.4', 2)]:
            data = evidence_fixture()
            observation(data, control)['value'] = value
            self.assertEqual(result(load(data), control).status, Status.NON_COMPLIANT)

    def test_missing_policy_and_failed_export_are_not_passes(self):
        data = evidence_fixture()
        for control in ('1.1.4', '1.2.2'):
            observation(data, control).update(state='error', value=None, error='timeout')
        for control in ('2.3.1.1', '9.3.1', '18.10.57.3.9.4'):  # Guest (non-policy), Public firewall and NLA (Group Policy).
            observation(data, control).update(state='missing', value=None)
        summary = summarise(load(data).results)
        # D5: absent policies fail as Non-Compliant; an absent non-policy value stays Unknown. Neither passes.
        self.assertEqual((summary.selected, summary.compliant, summary.non_compliant, summary.errors, summary.unknown),
                         (32, 27, 2, 2, 1))

    def test_rejects_other_platforms_roles_and_boolean_identity_fields(self):
        for key, value in [('os_caption', 'Windows 11'), ('os_version', '10.0.26100'),
                           ('build_number', '26100'), ('os_architecture', '32-bit'),
                           ('product_type', 1), ('product_type', True), ('domain_role', 3),
                           ('domain_role', True), ('part_of_domain', True), ('part_of_domain', 0)]:
            data = evidence_fixture()
            data['target'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): load(data)

    def test_rejects_wrong_host_or_uuid(self):
        for key, value in [('hostname', 'OTHER'), ('machine_uuid', 'cb095a4c-5a1c-48fe-b199-fda775b130a8'),
                           ('machine_uuid', '00000000-0000-0000-0000-000000000000')]:
            data = evidence_fixture()
            data['target'][key] = value
            with self.assertRaises(ValueError): load(data)

    def test_format_and_catalogue_identity_cannot_be_overridden(self):
        for key, value in [('schema_version', True), ('schema_version', 4), ('schema_version', 6),
                           ('collector_id', 'shell'), ('collector_id', 'server2022-readonly-v4'),
                           ('catalogue_id', 'demo-v1'), ('benchmark_sha256', 'anything'), ('profile', 'L2'),
                           ('evidence_mode', 'Live'), ('command', 'Set-Something')]:
            data = evidence_fixture()
            data[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): load(data)
        data = evidence_fixture(); del data['effective_context']
        with self.assertRaises(ValueError): load(data)

    def test_every_control_required_once_with_its_fixed_source(self):
        variants = []
        data = evidence_fixture(); data['observations'].pop(); variants.append(data)
        data = evidence_fixture(); data['observations'][1] = dict(data['observations'][0]); variants.append(data)
        data = evidence_fixture(); data['observations'][1]['control_id'] = 'unknown'; variants.append(data)
        data = evidence_fixture(); data['observations'][1]['source'] = 'model guessed'; variants.append(data)
        data = evidence_fixture(); data['observations'][1]['approved'] = True; variants.append(data)
        for data in variants:
            with self.assertRaises(ValueError): load(data)

    def test_no_string_bool_float_or_negative_coercion(self):
        for control, values in [('1.1.4', [True, '14', 14.0, -1, None, {}]),
                                ('2.3.1.1', [0, 'false', None, []]), ('18.10.57.3.9.4', [True, '1', 1.0, 2**32])]:
            for value in values:
                data = evidence_fixture(); observation(data, control)['value'] = value
                with self.subTest(control=control, value=value), self.assertRaises(ValueError): load(data)

    def test_invalid_observation_states_and_errors(self):
        for state, value, error in [('ok', 14, 'timeout'), ('missing', 0, None),
                                    ('missing', None, 'timeout'), ('error', 14, 'timeout'),
                                    ('error', None, 'secret raw exception'), ('error', None, []),
                                    ('unknown', None, None)]:
            data = evidence_fixture(); observation(data, '1.1.4').update(state=state, value=value, error=error)
            with self.subTest(state=state, error=error), self.assertRaises(ValueError): load(data)

    def test_timestamp_order_timezone_and_future_bounds(self):
        for key, value in [('started_at', '2026-10-19T01:01:00Z'),
                           ('started_at', '2026-10-19T00:00:00Z'),
                           ('completed_at', '2026-10-19T01:00:30'), ('completed_at', 'invalid')]:
            data = evidence_fixture(); data[key] = value
            with self.assertRaises(ValueError): load(data)
        data = evidence_fixture(); observation(data, '1.1.4')['collected_at'] = '2026-10-19T01:00:31Z'
        with self.assertRaises(ValueError): load(data)
        with self.assertRaises(ValueError):
            load_evidence(json.dumps(evidence_fixture()).encode(), expected_hostname='FIXTURE-SERVER',
                          expected_machine_uuid=MACHINE_UUID, now=datetime(2020, 1, 1, tzinfo=timezone.utc))

    def test_malformed_oversized_duplicate_and_nonfinite_json(self):
        for raw in [b'', b'{}' * 40000, b'\xff', b'{', b'{"x":1,"x":2}', b'NaN', b'[]']:
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                load_evidence(raw, expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID, now=NOW)

    def test_nested_malformed_identity_and_metadata_raise_validation_errors(self):
        for key in evidence_fixture()['target']:
            data = evidence_fixture(); data['target'][key] = {'untrusted': True}
            with self.subTest(key=key), self.assertRaises(ValueError): load(data)

    def test_bom_and_different_observation_order_supported(self):
        data = evidence_fixture(); data['observations'].reverse()
        loaded = load_evidence(b'\xef\xbb\xbf' + json.dumps(data).encode(), expected_hostname='fixture-server',
                               expected_machine_uuid=MACHINE_UUID.upper(), now=NOW)
        self.assertEqual([r.control.control_id for r in loaded.results], [c.control_id for c in CATALOGUE])


if __name__ == '__main__':
    unittest.main()
