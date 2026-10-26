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


def agentic_page():
    import legacy_app
    from hardening.agentic_view import render_agentic
    render_agentic(legacy_app.imports_database())


def overview_page():
    import legacy_app
    from hardening.overview_view import render_overview
    render_overview(legacy_app.imports_database())


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
        app = AppTest.from_function(agentic_page, default_timeout=60)
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

        overview = AppTest.from_function(overview_page, default_timeout=60).run()
        self.assertEqual(len(overview.exception), 0, [e.value for e in overview.exception])
        metrics = {m.label: m.value for m in overview.metric}
        self.assertEqual(metrics['Fixes awaiting you'], '0')  # One approved and executed, one rejected.
        # 1.2.2 is fixed; 9.3.1 (firewall effectively on) leads: 65 plus D=3 for persisting non-compliance = 69.
        self.assertEqual(metrics['Highest risk'], '69')
        areas = {row['Security area']: row for row in overview.dataframe[0].value.to_dict('records')}
        self.assertEqual(set(areas), {'Account Policies', 'Local Security Options', 'Windows Defender Firewall',
                                      'Advanced Audit Policy', 'Remote Desktop Services'})
        top = overview.dataframe[1].value.to_dict('records')
        self.assertEqual(top[0]['Control'], '9.3.1')
        self.assertEqual(top[0]['Fix'], 'Manual review (no library action)')
        self.assertTrue(any('Remediation and verification' in m.value for m in overview.markdown))

    def test_page_without_connection_asks_to_connect(self):
        app = AppTest.from_function(agentic_page, default_timeout=30).run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('Connect to the VM' in i.value for i in app.info))

    def test_app_opens_on_overview_with_empty_state(self):
        app = AppTest.from_file(str(APP), default_timeout=30).run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(app.title[0].value, 'Overview')
        self.assertTrue(any('No assessments yet' in i.value for i in app.info))


if __name__ == '__main__':
    unittest.main()
