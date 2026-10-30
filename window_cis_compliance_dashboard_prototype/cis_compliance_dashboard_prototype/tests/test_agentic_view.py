"""Agentic page walkthrough with a simulated VM and scripted model. No real VM or model."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from hardening import agentic, agentic_view
from hardening.connection_view import LIVE_TARGET
from hardening.winrm_channel import LiveScanner
from test_agentic import FakeVm, TeamDouble, call, clients
from test_winrm_channel import MACHINE_UUID, target

APP = Path(__file__).resolve().parents[1] / 'app.py'


def agentic_page():
    from hardening.databases import imports_database
    from hardening.agentic_view import render_agentic
    render_agentic(imports_database())


def overview_page():
    from hardening.databases import imports_database
    from hardening.overview_view import render_overview
    render_overview(imports_database())


class ScriptedModel:
    """Stands in for OllamaClient; every role's request is routed to that role's test double."""
    model, provenance = 'mock-model', 'Mock model (test only)'
    team = None

    def __init__(self, num_predict=384):
        self.num_predict = num_predict

    def chat(self, messages, tools, *, timeout):
        return ScriptedModel.team.chat(messages, tools, timeout=timeout)


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
        ScriptedModel.team = TeamDouble(clients(t, [
            call('delegate_scanner', t),
            call('delegate_analysis', t),
            call('submit_plan', t, fixes=[
                dict(control_id='1.2.2', action_id='REM-1.2.2', reason_code='high_risk'),
                dict(control_id='1.1.1', action_id='REM-1.1.1', reason_code='low_impact')],
                skipped=[dict(control_id='2.3.10.3', reason_code='needs_review'),
                         dict(control_id='1.1.3', reason_code='lower_priority'),
                         dict(control_id='18.10.57.3.9.4', reason_code='needs_review')])]))

    def _page(self, **state):
        app = AppTest.from_function(agentic_page, default_timeout=60)
        app.session_state[LIVE_TARGET] = target()
        for key, value in state.items():
            app.session_state[key] = value
        return app.run()

    def _start_round(self):
        app = self._page()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        app.button(key='agentic_run').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        return app

    def test_round_approval_execution_and_verification_through_the_page(self):
        app = self._start_round()
        summary = [c.value.replace('\\', '') for c in app.caption if c.value.startswith('Orchestrator summary')]
        self.assertIn('Proposed for your approval, in order: 1.2.2', summary[0])
        self.assertEqual(app.session_state[agentic_view.TAB], 'Fixes')
        self.assertEqual(self.vm.writes, [])
        app.text_input(key='agentic_operator').input('admin01').run()
        approve = [b for b in app.button if b.key.startswith('agentic_approve_') and b.key != 'agentic_approve_all']
        approve[0].click().run()
        reject = [b for b in app.button if b.key.startswith('agentic_reject_') and b.key != 'agentic_reject_all']
        reject[0].click().run()
        # Execution needs a second, explicit confirmation that lists the changes.
        app.button(key='agentic_execute_review').click().run()
        self.assertEqual(self.vm.writes, [])
        app.button(key='agentic_execute').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(self.vm.writes, ['1.2.2'])
        self.assertEqual(app.session_state[agentic_view.TAB], 'Results')
        self.assertTrue(any('Next step (next round)' in i.value for i in app.info))
        verdicts = [row for frame in app.dataframe for row in frame.value.to_dict('records') if 'Verdict' in row]
        self.assertEqual([v['Verdict'] for v in verdicts], ['Verified compliant'])
        self.assertIn('Run next round', [b.label for b in app.button])

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
        activity = overview.dataframe[2].value.to_dict('records')
        self.assertEqual([(a['Activity'], a['Result'], a['Status']) for a in activity],
                         [('Remediation and verification', '1 verified', 'Next round recommended'),
                          ('Assessment round', '2 fix(es) proposed, 3 deferred', 'All decided')])

    def test_results_survive_a_page_switch(self):
        """Streamlit drops widget state on a page switch; only plain session keys survive. The round must still show."""
        first = self._start_round()
        app = self._page(**{agentic_view.SESSION: first.session_state[agentic_view.SESSION]})
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(len([b for b in app.button if b.key.startswith('agentic_approve_')
                              and b.key != 'agentic_approve_all']), 2)
        self.assertNotIn('agentic_run', [b.key for b in app.button])  # Fixes still await a decision.

    def test_goal_is_passed_to_the_round_and_its_reading_shown(self):
        t = 'windows:' + MACHINE_UUID
        ScriptedModel.team = TeamDouble(clients(t, [
            call('interpret_goal', t, only_areas=[], exclude_areas=['remote_desktop'], exclude_controls=[],
                 focus='none', max_fixes=0, unclear=False),
            call('delegate_scanner', t), call('delegate_analysis', t),
            call('submit_plan', t, fixes=[dict(control_id='1.2.2', action_id='REM-1.2.2', reason_code='high_risk')],
                 skipped=[dict(control_id='18.10.57.3.9.4', reason_code='outside_goal')]
                 + [dict(control_id=c, reason_code='lower_priority') for c in ('2.3.10.3', '1.1.1', '1.1.3')])]))
        app = self._page()
        app.text_input(key='agentic_goal').input('Keep RDP usable for remote support').run()
        app.button(key='agentic_run').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        shown = [m.value.replace('\\', '') for m in app.markdown if m.value.startswith('**Your goal:**')]
        self.assertEqual(shown, ['**Your goal:** Keep RDP usable for remote support  \n'
                                 '**Read by the Orchestrator as:** leave Remote Desktop Services unchanged'])
        app.text_input(key='agentic_operator').input('admin01').run()
        next(b for b in app.button if b.key.startswith('agentic_reject_') and b.key != 'agentic_reject_all').click().run()
        self.assertEqual(app.text_input(key='agentic_goal').value, '')  # A goal is for one round only.

    def test_session_of_another_vm_is_not_shown(self):
        first = self._start_round()
        app = AppTest.from_function(agentic_page, default_timeout=60)
        app.session_state[LIVE_TARGET] = target(hostname='OTHER-SERVER',
                                                machine_uuid='11111111-2222-3333-4444-555555555555')
        app.session_state[agentic_view.SESSION] = first.session_state[agentic_view.SESSION]
        app.run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertNotIn(agentic_view.SESSION, app.session_state)
        self.assertEqual([b.key for b in app.button if b.key.startswith('agentic_approve_')], [])
        self.assertNotIn('agentic_resume', [b.key for b in app.button])  # The earlier session is on another VM.

    def test_earlier_session_can_be_resumed_after_a_refresh(self):
        self._start_round()
        app = self._page()  # A browser refresh: no session at all.
        self.assertTrue(any('2 fix(es) still open' in c.value for c in app.caption))
        app.button(key='agentic_resume').click().run()
        self.assertEqual(len([b for b in app.button if b.key.startswith('agentic_approve_')
                              and b.key != 'agentic_approve_all']), 2)

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
