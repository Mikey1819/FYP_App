"""Local-security assessments use fixture evidence and mocked registry access only."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from hardening.domain import Status, summarise
from hardening.evidence_import import encode
from hardening.framework import AssessmentRuns
from hardening.import_storage import ImportedEvidenceStore
from evidence_fixture import HOSTNAME, MACHINE_UUID, evidence_fixture, load, observation, result


LOCAL_VALUES = {'2.3.1.2': 1, '2.3.10.1': 0, '2.3.10.2': 1, '2.3.10.3': 1}


class LocalSecurityTests(unittest.TestCase):
    def test_exact_local_security_rules_no_nonzero_coercion(self):
        for identifier, expected in LOCAL_VALUES.items():
            for value in (0, 1, 2, 4294967295):
                with self.subTest(control=identifier, value=value):
                    data = evidence_fixture(); observation(data, identifier)['value'] = value
                    self.assertEqual(result(load(data), identifier).status,
                                     Status.COMPLIANT if value == expected else Status.NON_COMPLIANT)

    def test_uncollected_and_errors_never_become_defaults(self):
        data = evidence_fixture()
        for identifier in ('2.3.1.2', '2.3.10.1'):
            observation(data, identifier).update(state='missing', value=None)
        for identifier in ('2.3.10.2', '2.3.10.3'):
            observation(data, identifier).update(state='error', value=None, error='invalid_value')
        summary = summarise(load(data).results)
        self.assertEqual((summary.selected, summary.evaluated, summary.unknown, summary.errors), (32, 28, 2, 2))

    def test_type_and_source_guards(self):
        for identifier in LOCAL_VALUES:
            for value in (True, False, '1', 1.0, -1, 2**32):
                data = evidence_fixture(); observation(data, identifier)['value'] = value
                with self.subTest(control=identifier, value=value), self.assertRaises(ValueError): load(data)
            data = evidence_fixture(); observation(data, identifier)['source'] = 'guessed'
            with self.subTest(control=identifier, source='guessed'), self.assertRaises(ValueError): load(data)

    def test_framework_stores_local_security_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'imports.sqlite3'
            runtime = AssessmentRuns(ImportedEvidenceStore(path))
            data = evidence_fixture()
            observation(data, '2.3.1.2')['value'] = 0
            run = runtime.start(encode(data), expected_hostname=HOSTNAME, expected_machine_uuid=MACHINE_UUID)
            reopened = ImportedEvidenceStore(path).get(run.evidence_sha256)
            self.assertEqual(reopened.raw, encode(data))
            self.assertEqual(result(reopened.assessment, '2.3.1.2').status, Status.NON_COMPLIANT)

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
        output = json.loads(process.stdout)
        data = evidence_fixture()
        self.assertEqual(len(output['success']), 4)
        for row in output['success']:
            expected = observation(data, row['control_id'])
            self.assertEqual({k: v for k, v in row.items() if k != 'collected_at'},
                             {k: v for k, v in expected.items() if k != 'collected_at'})
        failures = {r['control_id']: r for r in output['failed']}
        self.assertEqual(failures['2.3.10.1']['error'], 'timeout')
        self.assertEqual(failures['2.3.1.2']['state'], 'missing')
        self.assertEqual(failures['2.3.10.2']['error'], 'invalid_value')
        self.assertEqual(failures['2.3.10.3']['state'], 'ok')
        self.assertEqual(next(r for r in output['duplicate'] if r['control_id'] == '2.3.10.1')['error'], 'invalid_value')
