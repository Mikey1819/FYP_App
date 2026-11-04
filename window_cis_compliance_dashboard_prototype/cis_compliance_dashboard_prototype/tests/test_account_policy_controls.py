"""Account Policies controls (1.1.x, 1.2.x) with fixture evidence; never collects or changes host policy."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from hardening.domain import Status, summarise
from hardening.framework import AssessmentRuns, describe
from hardening.import_storage import ImportedEvidenceStore
from evidence_fixture import HOSTNAME, MACHINE_UUID, evidence_fixture, load, observation, result

ACCOUNT_CONTROLS = ('1.1.1', '1.1.2', '1.1.3', '1.1.4', '1.1.5', '1.1.7', '1.2.1', '1.2.2', '1.2.4')


class AccountPolicyTests(unittest.TestCase):
    def test_rule_boundaries_and_never_sentinels(self):
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
                    data = evidence_fixture()
                    observation(data, identifier)['value'] = value
                    found = result(load(data), identifier)
                    self.assertEqual(found.evidence.value, value)
                    self.assertEqual(found.status, Status.COMPLIANT if compliant else Status.NON_COMPLIANT)

    def test_missing_and_error_remain_in_coverage(self):
        data = evidence_fixture()
        observation(data, '1.1.2').update(state='missing', value=None)
        observation(data, '1.2.4').update(state='error', value=None, error='timeout')
        summary = summarise(load(data).results)
        self.assertEqual((summary.selected, summary.evaluated, summary.unknown, summary.errors), (32, 30, 1, 1))

    def test_readings_reject_wrong_types_and_unregistered_negatives(self):
        for identifier in ('1.1.1', '1.1.2', '1.1.3', '1.1.5', '1.1.7', '1.2.1', '1.2.4'):
            for value in (True, '1', 1.0, -2, 2**32):
                data = evidence_fixture(); observation(data, identifier)['value'] = value
                with self.subTest(control=identifier, value=value), self.assertRaises(ValueError): load(data)
        for identifier in ('1.1.1', '1.1.3', '1.1.5', '1.1.7', '1.2.4'):  # Only 1.1.2 and 1.2.1 have a -1 sentinel.
            data = evidence_fixture(); observation(data, identifier)['value'] = -1
            with self.assertRaises(ValueError): load(data)

    def test_framework_restart_keeps_all_checks_and_ranks_both_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'imports.sqlite3'
            data = evidence_fixture()
            observation(data, '1.1.4')['value'] = 0
            observation(data, '1.1.1')['value'] = 0
            runtime = AssessmentRuns(ImportedEvidenceStore(path))
            run = runtime.start(json.dumps(data).encode(), expected_hostname=HOSTNAME,
                                expected_machine_uuid=MACHINE_UUID)
            runtime = AssessmentRuns(ImportedEvidenceStore(path))
            self.assertEqual(runtime.get(run.run_id), run)
            self.assertEqual({f['control_id'] for f in describe(runtime, run.run_id)['ranking']}, {'1.1.4', '1.1.1'})
            record = runtime.record(run.run_id)
            self.assertEqual(len(record.assessment.results), 32)
            self.assertEqual(json.loads(record.raw), data)

    def test_powershell_account_records_match_python_contract(self):
        script = Path(__file__).resolve().parents[2] / 'scripts' / 'vm' / 'Collect-Server2022Evidence.ps1'
        data = evidence_fixture()
        lines = ['[System Access]'] + [observation(data, c)['source'].split('/')[-1] + '='
                                       + str(observation(data, c)['value']) for c in ACCOUNT_CONTROLS]
        command = "$ErrorActionPreference = 'Stop'\n. '" + str(script).replace("'", "''") + "' -FunctionsOnly\n"
        command += "@(Get-AccountPolicyObservations -Lines @(" + ','.join("'" + s + "'" for s in lines) + ")) | ConvertTo-Json -Depth 5"
        process = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        rows = json.loads(process.stdout)
        self.assertEqual(sorted(r['control_id'] for r in rows), sorted(ACCOUNT_CONTROLS))
        for row in rows:
            expected = observation(data, row['control_id'])
            self.assertEqual({k: v for k, v in row.items() if k != 'collected_at'},
                             {k: v for k, v in expected.items() if k != 'collected_at'})
            row['collected_at'] = expected['collected_at']
        data['observations'] = rows + [r for r in data['observations'] if r['control_id'] not in ACCOUNT_CONTROLS]
        self.assertEqual(summarise(load(data).results).compliant, 32)


if __name__ == '__main__':
    unittest.main()
