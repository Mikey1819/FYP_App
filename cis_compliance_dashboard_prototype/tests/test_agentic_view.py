"""Agentic page walkthrough with a simulated VM and scripted model. No real VM or model."""
from datetime import timedelta
from pathlib import Path
import os
import tempfile
import threading
import unittest
from unittest.mock import patch

from streamlit.runtime.scriptrunner import get_script_run_ctx
from streamlit.testing.v1 import AppTest

from hardening import agentic, agentic_view, background
from hardening.connection_view import LIVE_TARGET
from hardening.ui import md_escape
from hardening.winrm_channel import LiveScanner
from test_agentic import FakeVm, TeamDouble, call, clients, plan
from test_winrm_channel import MACHINE_UUID, target



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
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk'), ('1.1.1', 'REM-1.1.1', 'low_impact')],
                 skipped=[('2.3.10.3', 'needs_review'), ('1.1.3', 'needs_review'), ('18.10.57.3.9.4', 'needs_review')])]))

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
        # Stored outcome text is Markdown-escaped on the page: it is data, not formatting.
        self.assertTrue(any(md_escape('Next step (next round)') in i.value for i in app.info))
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

    def test_a_round_runs_in_the_background_so_opening_another_page_cannot_stop_it(self):
        """Streamlit stops a page's own run when another page is opened. The round therefore runs in a worker with no
        Streamlit context; the page shows it running, offers nothing else to start, and shows the result after."""
        self.addCleanup(background._jobs.clear)
        gate, contexts = threading.Event(), []
        team = ScriptedModel.team

        class Gated:
            def chat(self, messages, tools, *, timeout):
                contexts.append(get_script_run_ctx(suppress_warning=True))
                gate.wait(30)
                return team.chat(messages, tools, timeout=timeout)
        ScriptedModel.team = Gated()
        self.addCleanup(setattr, ScriptedModel, 'team', team)
        with patch.object(agentic_view, 'WAIT_SECONDS', 0.05):
            app = self._start_round()
        self.assertTrue(any('Running' in m.value and 'Orchestrator' in m.value for m in app.markdown))
        self.assertNotIn('agentic_run', [b.key for b in app.button])
        self.assertTrue(app.button(key='agentic_disconnect').disabled)
        # Another page opens and works while the round goes on.
        overview = AppTest.from_function(overview_page, default_timeout=60).run()
        self.assertEqual(len(overview.exception), 0, [e.value for e in overview.exception])
        with self.assertRaisesRegex(ValueError, 'still running on this server'):
            background.start('windows:' + MACHINE_UUID, 'Another round', lambda: None)
        gate.set()
        self.assertTrue(background._jobs['windows:' + MACHINE_UUID].wait(60))
        app.run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        summary = [c.value.replace('\\', '') for c in app.caption if c.value.startswith('Orchestrator summary')]
        self.assertIn('Proposed for your approval, in order: 1.2.2', summary[0])
        self.assertEqual(app.session_state[agentic_view.TAB], 'Fixes')
        self.assertFalse(app.button(key='agentic_disconnect').disabled)
        self.assertTrue(contexts)
        self.assertEqual(set(contexts), {None})  # The agents never ran inside a page's run.

    def test_a_background_round_that_fails_is_reported_once(self):
        self.addCleanup(background._jobs.clear)
        with patch.object(agentic.AgenticHardening, 'run_round', side_effect=ValueError('model stopped answering')):
            app = self._start_round()
        self.assertEqual([e.value for e in app.error], ['Agentic workflow: model stopped answering'])
        app.run()
        self.assertEqual([e.value for e in app.error], [])
        self.assertIn('agentic_run', [b.key for b in app.button])  # Nothing is left running: it can start again.

    def test_the_clock_is_checked_before_a_round_and_can_be_synced_in_one_click(self):
        self.vm.clock_ahead = timedelta(minutes=7)
        app = self._page()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        shown = ' '.join(m.value for m in app.markdown)
        self.assertIn('Clocks differ', shown)
        self.assertIn('7 min 0 s ahead of this laptop', shown)
        self.assertTrue(any('Before you continue, check that the clocks match' in c.value for c in app.caption))
        self.assertTrue(app.button(key='agentic_run').disabled)
        app.button(key='agentic_clock_sync').click().run()
        self.assertEqual(len(self.vm.clock_sets), 1)
        self.assertTrue(any('Server clock set from' in m.value for m in app.success))
        self.assertIn('Clocks match', ' '.join(m.value for m in app.markdown))
        self.assertNotIn('agentic_clock_sync', [b.key for b in app.button])
        self.assertFalse(app.button(key='agentic_run').disabled)
        self.assertEqual(self.vm.writes, [])  # The clock is the only thing that changed.

    def test_start_checks_the_clock_again_when_clicked(self):
        app = self._page()
        self.assertFalse(app.button(key='agentic_run').disabled)
        self.vm.clock_ahead = timedelta(minutes=-9)  # The clock jumped after the page was drawn.
        app.button(key='agentic_run').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertNotIn(self.vm.scripts[-1], (agentic_view.LiveScanner.collector_text(),))  # Nothing was scanned.
        self.assertIn('9 min 0 s behind this laptop', ' '.join(m.value for m in app.markdown))
        self.assertNotIn(agentic_view.SESSION, app.session_state)
        self.assertTrue(app.button(key='agentic_run').disabled)

    def test_page_without_connection_asks_to_connect(self):
        app = AppTest.from_function(agentic_page, default_timeout=30).run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('Open **Servers** to pair a server' in i.value for i in app.info))


if __name__ == '__main__':
    unittest.main()
