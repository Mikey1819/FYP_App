"""Agentic page walkthrough with a simulated VM and scripted model. No real VM or model."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from hardening import agentic, agentic_view
from hardening.scan_view import LIVE_TARGET
from hardening.winrm_channel import LiveScanner
from test_agentic import FakeVm, call
from test_winrm_channel import MACHINE_UUID, target

APP = Path(__file__).resolve().parents[1] / 'app.py'


class ScriptedModel:
    """Orchestrator and Scanner requests arrive in a fixed order, so one shared script suffices."""
    model, provenance = 'mock-model', 'Mock model (test only)'
    script = []

    def __init__(self, num_predict=384):
        self.num_predict = num_predict

    def chat(self, messages, tools, *, timeout):
        return ScriptedModel.script.pop(0)


class AgenticPageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        for patcher in (patch.dict(os.environ, {'CIS_DASHBOARD_DB': str(Path(folder.name) / 'preview.sqlite3')}),
                        patch.object(agentic, 'OllamaClient', ScriptedModel)):
            patcher.start(); self.addCleanup(patcher.stop)
        self.vm = FakeVm()
        vm = self.vm

        class FakeChannel(LiveScanner):
            def __init__(self, runtime, live_target, session_factory=None):
                super().__init__(runtime, live_target, session_factory=vm)
        scanner_patch = patch.object(agentic_view, 'LiveScanner', FakeChannel)
        scanner_patch.start(); self.addCleanup(scanner_patch.stop)
        t = 'windows:' + MACHINE_UUID
        ScriptedModel.script = [
            call('delegate_scanner', t),
            call('scan_target', t), call('read_coverage', t), call('handoff_analysis', t, reason='Coverage read.'),
            call('delegate_analysis', t),
            call('submit_plan', t, fixes=[
                dict(control_id='1.2.2', action_id='REM-1.2.2', reason_code='high_risk'),
                dict(control_id='1.1.1', action_id='REM-1.1.1', reason_code='low_impact')],
                skipped=[dict(control_id='2.3.10.3', reason_code='needs_review'),
                         dict(control_id='1.1.3', reason_code='lower_priority'),
                         dict(control_id='18.10.57.3.9.4', reason_code='needs_review')])]

    def test_round_approval_execution_and_verification_through_the_page(self):
        app = AppTest.from_file(str(APP), default_timeout=60)
        app.session_state[LIVE_TARGET] = target()
        app.run()
        app.text_input(key='agentic_host').input('FIXTURE-SERVER')
        app.text_input(key='agentic_uuid').input(MACHINE_UUID).run()
        self.assertEqual(len(app.exception), 0)
        app.button(key='agentic_run').click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any(s.value.startswith('Proposed for your approval, in order: 1.2.2') for s in app.success))
        self.assertEqual(self.vm.writes, [])
        operator = next(w for w in app.text_input if w.key.startswith('agentic_operator_'))
        operator.input('admin01').run()
        approve = [b for b in app.button if b.key.startswith('agentic_approve_')]
        reject = [b for b in app.button if b.key.startswith('agentic_reject_')]
        approve[0].click().run()
        reject = [b for b in app.button if b.key.startswith('agentic_reject_')]
        reject[0].click().run()
        app.button(key='agentic_execute').click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(self.vm.writes, ['1.2.2'])
        self.assertIn('6. Verification', [h.value for h in app.subheader])
        verdicts = [row for frame in app.dataframe for row in frame.value.to_dict('records') if 'Verdict' in row]
        self.assertEqual([v['Verdict'] for v in verdicts], ['Verified compliant'])
        self.assertIn('Run next round (rescan, re-rank, re-propose)', [b.label for b in app.button])

    def test_page_without_connection_asks_to_connect(self):
        app = AppTest.from_file(str(APP), default_timeout=30).run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('Connect to the VM' in i.value for i in app.info))


if __name__ == '__main__':
    unittest.main()
