"""Synthetic account-policy coverage; never collects or changes host policy."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from hardening.domain import Status, summarise
from hardening.evidence_import import CONTEXT_SOURCES, encode
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.server2022_catalogue import EXPANDED_CATALOGUE_ID, EXPANDED_SOURCES
from test_evidence_import import export_fixture, load, MACHINE_UUID, NOW


def expanded_fixture():
    data = export_fixture()
    data.update(schema_version=3, collector_id='server2022-readonly-v3',
                catalogue_id=EXPANDED_CATALOGUE_ID)
    values = {'1.1.1': 24, '1.1.2': 365, '1.1.3': 1, '1.1.5': 1,
              '1.1.7': 0, '1.2.1': 15, '1.2.4': 15}
    data['observations'] += [dict(control_id=k, source=EXPANDED_SOURCES[k], state='ok',
        value=v, error=None, collected_at=data['observations'][0]['collected_at']) for k, v in values.items()]
    data['effective_context'] = [dict(control_id=k, source=s, state='ok', value=v,
        error=None, collected_at=data['observations'][0]['collected_at'])
        for (k, s), v in zip(CONTEXT_SOURCES.items(), [True, 1, 0])]
    return data


def observation(data, identifier):
    return next(r for r in data['observations'] if r['control_id'] == identifier)


class ExpandedControlTests(unittest.TestCase):
    def test_twelve_source_bound_results_and_legacy_preserved(self):
        data = expanded_fixture()
        data['observations'].reverse()
        result = load(data)
        self.assertEqual(summarise(result.results).compliant, 12)
        self.assertEqual({r.control.catalogue_version for r in result.results}, {EXPANDED_CATALOGUE_ID})
        self.assertEqual(len(load(export_fixture()).results), 5)

    def test_all_seven_rule_boundaries_and_never_sentinels(self):
        cases = {'1.1.1': [(0, False), (23, False), (24, True)],
                 '1.1.2': [(-1, False), (0, False), (1, True), (365, True), (366, False)],
                 '1.1.3': [(0, False), (1, True)],
                 '1.1.5': [(0, False), (1, True), (2, False)],
                 '1.1.7': [(0, True), (1, False)],
                 '1.2.1': [(-1, False), (0, False), (14, False), (15, True)],
                 '1.2.4': [(0, False), (14, False), (15, True)]}
        for identifier, values in cases.items():
            for value, compliant in values:
                with self.subTest(control=identifier, value=value):
                    data = expanded_fixture()
                    observation(data, identifier)['value'] = value
                    result = next(r for r in load(data).results if r.control.control_id == identifier)
                    self.assertEqual(result.evidence.value, value)
                    self.assertEqual(result.status, Status.COMPLIANT if compliant else Status.NON_COMPLIANT)

    def test_missing_and_error_remain_in_coverage(self):
        data = expanded_fixture()
        observation(data, '1.1.2').update(state='missing', value=None)
        observation(data, '1.2.4').update(state='error', value=None, error='timeout')
        summary = summarise(load(data).results)
        self.assertEqual((summary.selected, summary.evaluated, summary.unknown, summary.errors), (12, 10, 1, 1))

    def test_version_and_observation_contract_cannot_be_mixed(self):
        for field, value in [('schema_version', 2), ('collector_id', 'server2022-readonly-v2'),
                             ('catalogue_id', export_fixture()['catalogue_id'])]:
            data = expanded_fixture(); data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): load(data)
        for mode in ('omitted', 'duplicate', 'source', 'context'):
            data = expanded_fixture()
            if mode == 'omitted': data['observations'].pop()
            elif mode == 'duplicate': data['observations'][-1] = data['observations'][0]
            elif mode == 'source': data['observations'][-1]['source'] = 'guessed'
            else: del data['effective_context']
            with self.subTest(mode=mode), self.assertRaises(ValueError): load(data)

    def test_new_readings_reject_wrong_types_and_unregistered_negatives(self):
        for identifier in ('1.1.1', '1.1.2', '1.1.3', '1.1.5', '1.1.7', '1.2.1', '1.2.4'):
            for value in (True, '1', 1.0, -2, 2**32):
                data = expanded_fixture(); observation(data, identifier)['value'] = value
                with self.subTest(control=identifier, value=value), self.assertRaises(ValueError): load(data)
        for identifier in ('1.1.1', '1.1.3', '1.1.5', '1.1.7', '1.2.4'):
            data = expanded_fixture(); observation(data, identifier)['value'] = -1
            with self.assertRaises(ValueError): load(data)

    def test_framework_restart_preserves_twelve_checks_and_one_supported_action(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'imports.sqlite3'
            data = expanded_fixture()
            observation(data, '1.1.4')['value'] = 0
            observation(data, '1.1.1')['value'] = 0
            runtime = AssessmentOrchestrator(ImportedEvidenceStore(path))
            run = runtime.start(json.dumps(data).encode(), expected_hostname='FIXTURE-SERVER',
                                expected_machine_uuid=MACHINE_UUID)
            runtime = AssessmentOrchestrator(ImportedEvidenceStore(path))
            done = runtime.complete_assessment(run.run_id)
            self.assertEqual(done.state, 'ready_for_review')
            self.assertEqual(len(done.tasks[-1]['output']['candidates']), 1)
            self.assertEqual(done.tasks[-1]['output']['candidates'][0]['control_id'], '1.1.4')
            record = runtime.imports.get(run.evidence_sha256)
            self.assertEqual(len(record.assessment.results), 12)
            self.assertEqual(json.loads(record.raw), data)

    def test_powershell_account_records_match_python_contract(self):
        script = Path(__file__).resolve().parents[2] / 'scripts' / 'Collect-Server2022Evidence.ps1'
        data = expanded_fixture()
        lines = ['[System Access]'] + [r['source'].split('/')[-1] + '=' + str(r['value'])
            for r in data['observations'] if r['source'].startswith('secedit-export:')]
        command = "$ErrorActionPreference = 'Stop'\n. '" + str(script).replace("'", "''") + "' -FunctionsOnly\n"
        command += "@(Get-AccountPolicyObservations -Lines @(" + ','.join("'" + s + "'" for s in lines) + ")) | ConvertTo-Json -Depth 5"
        process = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = json.loads(process.stdout)
        self.assertEqual(len(rows), 9)
        for row in rows:
            expected = observation(data, row['control_id'])
            self.assertEqual({k: v for k, v in row.items() if k != 'collected_at'},
                             {k: v for k, v in expected.items() if k != 'collected_at'})
            row['collected_at'] = expected['collected_at']
        data['observations'] = rows + [r for r in data['observations'] if not r['source'].startswith('secedit-export:')]
        self.assertEqual(summarise(load(data).results).compliant, 12)

