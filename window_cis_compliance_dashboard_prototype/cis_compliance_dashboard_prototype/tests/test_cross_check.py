"""Cross-check comparison against a stored fixture scan, over a simulated WinRM session. No VM."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hardening.evidence_import import encode
from hardening.import_storage import ImportedEvidenceStore
from hardening.winrm_channel import LiveScanner
from test_evidence_import import MACHINE_UUID, NOW
from test_full_controls import full_fixture
from test_winrm_channel import IDENTITY, FakeSession

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'tools' / 'cross_check_controls.py'
spec = importlib.util.spec_from_file_location('cross_check_controls', SCRIPT)
cross_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cross_check)


class CrossCheckSession(FakeSession):
    def __init__(self, report, **kwargs):
        super().__init__(**kwargs)
        self.report = report

    def run(self, script, parameters=None):
        if script == cross_check.SCRIPT.read_text(encoding='utf-8-sig'):
            self.calls.append((script, parameters))
            return [json.dumps(self.report)], False, []
        return super().run(script, parameters)


class CrossCheckTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.store = ImportedEvidenceStore(self.folder / 'imports.sqlite3')
        saved, _ = self.store.save(encode(full_fixture()), expected_hostname='FIXTURE-SERVER',
                                   expected_machine_uuid=MACHINE_UUID, now=NOW)
        rows = [dict(control_id=r.control.control_id, value=r.evidence.value, raw=str(r.evidence.value),
                     method='fixture') for r in saved.assessment.results]
        # The fixture scan ran at 01:00; the cross-check at 03:30 is stale enough to warn.
        self.report = dict(hostname='FIXTURE-SERVER', collected_at='2026-10-19T03:30:00+00:00', rows=rows)

    def run_script(self, *arguments):
        output = io.StringIO()
        with patch('sys.argv', ['cross_check_controls.py', '--db', str(self.store.path), *arguments]), \
                redirect_stdout(output):
            cross_check.main()
        return output.getvalue()

    def run_live(self):
        session = CrossCheckSession(self.report)
        with patch.object(cross_check, 'getpass', return_value='secret'), \
                patch.object(cross_check, 'LiveScanner', lambda runtime, target: LiveScanner(
                    runtime, target, session_factory=session)):
            return self.run_script(), session

    def test_matching_values_agree_and_changed_values_are_flagged(self):
        self.assertIn('**32 of 32 controls agree.**', self.run_live()[0])
        rows = self.report['rows']
        next(r for r in rows if r['control_id'] == '1.1.4')['value'] = 7
        guest = next(r for r in rows if r['control_id'] == '2.3.1.1')
        guest['value'] = int(guest['value'])  # Same number, different type: not an agreement.
        rows[:] = [r for r in rows if r['control_id'] != '17.5.4']
        output = self.run_live()[0]
        self.assertIn('**29 of 32 controls agree.**', output)
        self.assertRegex(output, r'\| 1\.1\.4 \| \d+ \| 7 \| .* \| \*\*Disagree\*\* \|')
        self.assertIn('missing from cross-check', output)
        self.assertIn('minutes apart', output)

    def test_live_mode_checks_identity_before_running_the_read_only_script(self):
        output, session = self.run_live()
        self.assertIn('**32 of 32 controls agree.**', output)
        self.assertEqual(session.target.machine_uuid, MACHINE_UUID)
        (first, _), (second, parameters) = session.calls
        self.assertNotEqual(first, second)
        self.assertIsNone(parameters)  # The script takes no parameters: it always returns JSON.

    def test_live_mode_stops_on_the_wrong_vm(self):
        session = CrossCheckSession(self.report, identity=dict(IDENTITY, hostname='OTHER'))
        with patch.object(cross_check, 'getpass', return_value='secret'), \
                patch.object(cross_check, 'LiveScanner', lambda runtime, target: LiveScanner(
                    runtime, target, session_factory=session)), \
                self.assertRaises(SystemExit), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.run_script()
        self.assertEqual(len(session.calls), 1)  # Only the identity probe ran.


if __name__ == '__main__':
    unittest.main()
