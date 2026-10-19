from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.domain import Status, summarise
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.evidence_import import load_evidence
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.server2022_catalogue import BENCHMARK_SHA256, CATALOGUE_ID, COLLECTOR_ID, PROFILE, SOURCES


NOW = datetime(2026, 10, 19, 2, tzinfo=timezone.utc)
MACHINE_UUID = '2ca18359-73dc-49ef-9dd3-18602c0d9b55'


def export_fixture():
    return {
        'schema_version': 1, 'collector_id': COLLECTOR_ID, 'catalogue_id': CATALOGUE_ID,
        'benchmark_sha256': BENCHMARK_SHA256, 'profile': PROFILE, 'evidence_mode': 'Imported',
        'started_at': '2026-10-19T01:00:00+00:00', 'completed_at': '2026-10-19T01:00:30+00:00',
        'target': {'hostname': 'FIXTURE-SERVER', 'machine_uuid': MACHINE_UUID,
                   'os_caption': 'Microsoft Windows Server 2022 Standard Evaluation',
                   'os_version': '10.0.20348', 'build_number': '20348', 'os_architecture': '64-bit',
                   'product_type': 3, 'part_of_domain': False, 'domain_role': 2},
        'observations': [dict(control_id=key, source=source, state='ok', value=value, error=None,
                              collected_at='2026-10-19T01:00:15+00:00')
                         for (key, source), value in zip(SOURCES.items(), [14, 5, False, 1, 1])],
    }


def load(payload, **kwargs):
    return load_evidence(json.dumps(payload).encode(), expected_hostname='FIXTURE-SERVER',
                         expected_machine_uuid=MACHINE_UUID, now=NOW, **kwargs)


class EvidenceImportTests(unittest.TestCase):
    def test_valid_import_uses_reviewed_rules_not_demo_and_is_repeatable(self):
        payload = export_fixture()
        a, b = load(payload), load(payload)
        self.assertEqual(a, b)
        self.assertEqual(summarise(a.results).compliant, 5)
        self.assertTrue(all(r.control.source_verified for r in a.results))
        self.assertTrue(all(r.evidence.mode.value == 'Imported' for r in a.results))
        self.assertEqual(a.target_id, 'windows:' + MACHINE_UUID)

    def test_real_lockout_and_password_boundaries(self):
        for index, cases in ((0, [(13, False), (14, True), (15, True)]),
                             (1, [(0, False), (1, True), (5, True), (6, False), (10, False)])):
            for value, passes in cases:
                with self.subTest(index=index, value=value):
                    data = export_fixture()
                    data['observations'][index]['value'] = value
                    self.assertEqual(load(data).results[index].status,
                                     Status.COMPLIANT if passes else Status.NON_COMPLIANT)

    def test_guest_and_policy_dword_comparisons(self):
        for index, value in [(2, True), (3, 0), (3, 2), (4, 0), (4, 2)]:
            data = export_fixture()
            data['observations'][index]['value'] = value
            self.assertEqual(load(data).results[index].status, Status.NON_COMPLIANT)

    def test_missing_policy_and_failed_export_are_not_passes(self):
        data = export_fixture()
        for index in (0, 1):
            data['observations'][index].update(state='error', value=None, error='timeout')
        for index in (3, 4):
            data['observations'][index].update(state='missing', value=None)
        summary = summarise(load(data).results)
        self.assertEqual((summary.selected, summary.evaluated, summary.errors, summary.unknown), (5, 1, 2, 2))

    def test_rejects_other_platforms_roles_and_boolean_identity_fields(self):
        for key, value in [('os_caption', 'Windows 11'), ('os_version', '10.0.26100'),
                           ('build_number', '26100'), ('os_architecture', '32-bit'),
                           ('product_type', 1), ('product_type', True), ('domain_role', 3),
                           ('domain_role', True), ('part_of_domain', True), ('part_of_domain', 0)]:
            data = export_fixture()
            data['target'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError): load(data)

    def test_rejects_wrong_host_or_uuid(self):
        for key, value in [('hostname', 'OTHER'), ('machine_uuid', 'cb095a4c-5a1c-48fe-b199-fda775b130a8'),
                           ('machine_uuid', '00000000-0000-0000-0000-000000000000')]:
            data = export_fixture()
            data['target'][key] = value
            with self.assertRaises(ValueError): load(data)

    def test_catalogue_provenance_and_extra_fields_cannot_be_overridden(self):
        for key, value in [('schema_version', True), ('collector_id', 'shell'), ('catalogue_id', 'demo-v1'),
                           ('benchmark_sha256', 'anything'), ('profile', 'L2'), ('evidence_mode', 'Live'),
                           ('command', 'Set-Something')]:
            data = export_fixture()
            data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): load(data)

    def test_all_five_unique_controls_required_and_sources_fixed(self):
        variants = []
        data = export_fixture(); data['observations'].pop(); variants.append(data)
        data = export_fixture(); data['observations'][1] = deepcopy(data['observations'][0]); variants.append(data)
        data = export_fixture(); data['observations'][1]['control_id'] = 'unknown'; variants.append(data)
        data = export_fixture(); data['observations'][1]['source'] = 'model guessed'; variants.append(data)
        data = export_fixture(); data['observations'][1]['approved'] = True; variants.append(data)
        for data in variants:
            with self.assertRaises(ValueError): load(data)

    def test_no_string_bool_float_or_negative_coercion(self):
        for index, values in [(0, [True, '14', 14.0, -1, None, {}]),
                              (2, [0, 'false', None, []]), (4, [True, '1', 1.0, 2**32])]:
            for value in values:
                data = export_fixture(); data['observations'][index]['value'] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError): load(data)

    def test_invalid_observation_states_and_errors(self):
        for state, value, error in [('ok', 14, 'timeout'), ('missing', 0, None),
                                    ('missing', None, 'timeout'), ('error', 14, 'timeout'),
                                    ('error', None, 'secret raw exception'), ('error', None, []),
                                    ('unknown', None, None)]:
            data = export_fixture(); data['observations'][0].update(state=state, value=value, error=error)
            with self.subTest(state=state, error=error), self.assertRaises(ValueError): load(data)

    def test_timestamp_order_timezone_and_future_bounds(self):
        for key, value in [('started_at', '2026-10-19T01:01:00Z'),
                           ('started_at', '2026-10-19T00:00:00Z'),
                           ('completed_at', '2026-10-19T01:00:30'), ('completed_at', 'invalid')]:
            data = export_fixture(); data[key] = value
            with self.assertRaises(ValueError): load(data)
        data = export_fixture(); data['observations'][0]['collected_at'] = '2026-10-19T01:00:31Z'
        with self.assertRaises(ValueError): load(data)
        with self.assertRaises(ValueError):
            load_evidence(json.dumps(export_fixture()).encode(), expected_hostname='FIXTURE-SERVER',
                          expected_machine_uuid=MACHINE_UUID, now=datetime(2020, 1, 1, tzinfo=timezone.utc))

    def test_malformed_oversized_duplicate_and_nonfinite_json(self):
        for raw in [b'', b'{}' * 40000, b'\xff', b'{', b'{"x":1,"x":2}', b'NaN', b'[]']:
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                load_evidence(raw, expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID, now=NOW)

    def test_nested_malformed_identity_and_metadata_raise_validation_errors(self):
        for key in export_fixture()['target']:
            data = export_fixture(); data['target'][key] = {'untrusted': True}
            with self.subTest(key=key), self.assertRaises(ValueError): load(data)

    def test_bom_and_different_observation_order_supported(self):
        data = export_fixture(); data['observations'].reverse()
        result = load_evidence(b'\xef\xbb\xbf' + json.dumps(data).encode(), expected_hostname='fixture-server',
                               expected_machine_uuid=MACHINE_UUID.upper(), now=NOW)
        self.assertEqual([r.control.control_id for r in result.results], list(SOURCES))

    def test_cli_is_read_only_and_rejects_mismatched_target(self):
        # Old fixture timestamps are historical evidence, not today's scan.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.json'
            path.write_text(json.dumps(export_fixture()), encoding='utf-8')
            original = path.read_bytes()
            script = Path(__file__).resolve().parents[2] / 'scripts' / 'inspect_server_evidence.py'
            command = [sys.executable, '-B', str(script), str(path), '--expected-hostname', 'FIXTURE-SERVER',
                       '--expected-machine-uuid', MACHINE_UUID]
            run = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)['coverage']['compliant'], 5)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [path])
            command[-1] = 'cb095a4c-5a1c-48fe-b199-fda775b130a8'
            rejected = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn('selected target', rejected.stderr)


if __name__ == '__main__':
    unittest.main()
