"""Local-security assessments use fixture evidence and mocked registry access only."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from hardening.domain import Status, summarise
from hardening.evidence_import import encode
from hardening.framework import AssessmentRuns
from hardening.import_storage import ImportedEvidenceStore
from hardening.server2022_catalogue import LOCAL_SECURITY_CATALOGUE_ID, LATEST_SOURCES
from test_evidence_import import export_fixture, load, MACHINE_UUID
from test_expanded_controls import expanded_fixture, observation


LOCAL_VALUES = {'2.3.1.2': 1, '2.3.10.1': 0, '2.3.10.2': 1, '2.3.10.3': 1}


def local_security_fixture():
    data = expanded_fixture()
    data.update(schema_version=4, collector_id='server2022-readonly-v4',
                catalogue_id=LOCAL_SECURITY_CATALOGUE_ID)
    data['observations'] += [dict(control_id=k, source=LATEST_SOURCES[k], state='ok',
        value=v, error=None, collected_at=data['observations'][0]['collected_at']) for k, v in LOCAL_VALUES.items()]
    return data


class LocalSecurityTests(unittest.TestCase):
    def test_sixteen_checks_and_historical_catalogues_remain_distinct(self):
        for fixture, count in ((export_fixture, 5), (expanded_fixture, 12), (local_security_fixture, 16)):
            data = fixture()
            data['observations'].reverse()
            result = load(data)
            self.assertEqual(summarise(result.results).compliant, count)
            self.assertEqual({r.control.catalogue_version for r in result.results}, {data['catalogue_id']})

    def test_exact_local_security_rules_no_nonzero_coercion(self):
        for identifier, expected in LOCAL_VALUES.items():
            for value in (0, 1, 2, 4294967295):
                with self.subTest(control=identifier, value=value):
                    data = local_security_fixture(); observation(data, identifier)['value'] = value
                    result = next(r for r in load(data).results if r.control.control_id == identifier)
                    self.assertEqual(result.status, Status.COMPLIANT if value == expected else Status.NON_COMPLIANT)

    def test_uncollected_and_errors_never_become_defaults(self):
        data = local_security_fixture()
        for identifier in ('2.3.1.2', '2.3.10.1'):
            observation(data, identifier).update(state='missing', value=None)
        for identifier in ('2.3.10.2', '2.3.10.3'):
            observation(data, identifier).update(state='error', value=None, error='invalid_value')
        summary = summarise(load(data).results)
        self.assertEqual((summary.selected, summary.evaluated, summary.unknown, summary.errors), (16, 12, 2, 2))

    def test_type_source_completeness_and_version_guards(self):
        for identifier in LOCAL_VALUES:
            for value in (True, False, '1', 1.0, -1, 2**32):
                data = local_security_fixture(); observation(data, identifier)['value'] = value
                with self.subTest(control=identifier, value=value), self.assertRaises(ValueError): load(data)
        base = local_security_fixture()
        cases = []
        for field, value in [('schema_version', 3), ('collector_id', 'server2022-readonly-v3'),
                             ('catalogue_id', expanded_fixture()['catalogue_id'])]:
            data = deepcopy(base); data[field] = value; cases.append(data)
        data = deepcopy(base); data['observations'].pop(); cases.append(data)
        data = deepcopy(base); data['observations'][-1] = data['observations'][0]; cases.append(data)
        data = deepcopy(base); data['observations'][-1]['source'] = 'guessed'; cases.append(data)
        for data in cases:
            with self.assertRaises(ValueError): load(data)

    def test_framework_stores_expansion_without_granting_new_actions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'imports.sqlite3'
            runtime = AssessmentRuns(ImportedEvidenceStore(path))
            data = local_security_fixture()
            observation(data, '2.3.1.2')['value'] = 0
            run = runtime.start(encode(data), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
            self.assertEqual(runtime.get(run.run_id).state, 'assessed')
            reopened = ImportedEvidenceStore(path).get(run.evidence_sha256)
            self.assertEqual(reopened.raw, encode(data))
            self.assertEqual(len(reopened.assessment.results), 16)

    def test_powershell_sources_and_independent_failure_records(self):
        collector = Path(__file__).resolve().parents[2] / 'scripts' / 'vm' / 'Collect-Server2022Evidence.ps1'
        command = "$ErrorActionPreference='Stop'\n. '" + str(collector).replace("'", "''") + "' -FunctionsOnly\n"
        command += r"""
function Read-PolicyDword {
    param($SubKey, $ValueName)
    if ($SubKey -ne 'SYSTEM\CurrentControlSet\Control\Lsa') { throw 'Unexpected mock registry key' }
    if ($script:failed -and $ValueName -eq 'LimitBlankPasswordUse') { return $null }
    if ($script:failed -and $ValueName -eq 'RestrictAnonymousSAM') { throw 'invalid_value' }
    return 1
}
$script:failed=$false
$success=@(Get-LocalSecurityObservations -Lines @('[System Access]', 'LSAAnonymousNameLookup=0'))
$script:failed=$true
$failed=@(Get-LocalSecurityObservations -Lines @() -PolicyError 'timeout')
$duplicate=@(Get-LocalSecurityObservations -Lines @('[System Access]', 'LSAAnonymousNameLookup=0', 'LSAAnonymousNameLookup=1'))
@{success=$success; failed=$failed; duplicate=$duplicate} | ConvertTo-Json -Depth 6
"""
        process = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', command],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        data = local_security_fixture()
        self.assertEqual(len(result['success']), 4)
        for row in result['success']:
            expected = observation(data, row['control_id'])
            self.assertEqual({k: v for k, v in row.items() if k != 'collected_at'},
                             {k: v for k, v in expected.items() if k != 'collected_at'})
        failures = {r['control_id']: r for r in result['failed']}
        self.assertEqual(failures['2.3.10.1']['error'], 'timeout')
        self.assertEqual(failures['2.3.1.2']['state'], 'missing')
        self.assertEqual(failures['2.3.10.2']['error'], 'invalid_value')
        self.assertEqual(failures['2.3.10.3']['state'], 'ok')
        self.assertEqual(next(r for r in result['duplicate'] if r['control_id'] == '2.3.10.1')['error'], 'invalid_value')
