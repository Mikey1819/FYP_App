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

    def _approve_all(self, app):
        app.text_input(key='agentic_operator').input('admin01').run()
        app.button(key='agentic_approve_all').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        return app

    def test_the_risk_ranking_says_for_every_finding_whether_this_program_fixes_it(self):
        # Live 9 Nov: only three of 9.2.1, 9.2.2, 9.3.1, 9.3.2 said "needs a manual fix": that column is the Analysis
        # Agent's flags, at most three. The Fix column is set by code for every row.
        app = self._start_round()
        rows = [r for frame in app.dataframe for r in frame.value.to_dict('records') if 'Priority band' in r]
        self.assertTrue(rows)
        fixes = {r['Control']: r['Fix'] for r in rows}
        self.assertEqual(fixes['9.3.1'], 'Manual: not automated')
        self.assertEqual(fixes['1.2.2'], 'Program fix')
        self.assertTrue(all(r['Fix'] for r in rows))
        self.assertTrue(any('flags at most 3 findings' in c.value for c in app.caption))

    def test_complete_hardening_needs_a_final_scan_with_nothing_open_then_closes_the_session(self):
        from hardening.databases import imports_database
        from hardening.manual_controls import ManualDecisionStore
        app = self._start_round()
        app.text_input(key='agentic_operator').input('kk').run()
        app.button(key='agentic_reject_all').click().run()  # Rejected fixes stay open: they block completion.
        app.button(key='agentic_complete').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertTrue(any('still open' in m.value for m in app.markdown))
        labels = {e.label for e in app.expander}
        self.assertIn('How to fix it on the server', labels)  # The firewall controls: the gpedit steps, here too.
        self.assertIn('How to close it', labels)  # A rejected fix: run the next round, approve and execute it.
        app.text_input(key='agentic_complete_operator').input('kk').run()
        app.button(key='agentic_complete_run').click().run()  # The final scan still finds open controls.
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertTrue(any('Not completed: the final scan' in w.value for w in app.warning), [w.value for w in app.warning])
        session = app.session_state[agentic_view.SESSION]
        decisions = ManualDecisionStore(Path(imports_database()).with_name('manual_decisions.sqlite3'))
        server = 'windows:' + MACHINE_UUID.lower()
        self.assertIsNone(decisions.completion(server, session))
        # Accepting one open control on the panel records it for this session only.
        first = next(b.key for b in app.button if b.key.startswith('agentic_complete_accept_'))
        control = first.rsplit('_', 1)[1]
        app.text_input(key='agentic_complete_reason_' + control).input('Accepted for the lab').run()
        app.button(key=first).click().run()
        self.assertEqual(decisions.latest(server, session)[control]['reason'], 'Accepted for the lab')
        for key in [b.key for b in app.button if b.key.startswith('agentic_complete_accept_')]:
            decisions.record(server, key.rsplit('_', 1)[1], 'exception', operator='kk', reason='Lab', session_id=session)
        app.run()
        self.assertTrue(any('every control is compliant or accepted' in s.value for s in app.success))
        writes = list(self.vm.writes)
        app.button(key='agentic_complete_run').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(self.vm.writes, writes, 'The final scan changes nothing on the server')
        done = decisions.completion(server, session)
        self.assertEqual(done['operator'], 'kk')
        self.assertEqual(done['compliant'] + len(done['exceptions']), done['total'])
        self.assertIn('Hardening complete for FIXTURE', app.session_state[agentic_view.COMPLETED].replace('\\', ''))
        self.assertTrue(app.session_state[agentic_view.GO_OVERVIEW])  # app.py opens Overview, which shows it.
        # The completed session is read-only, with its completion report; a new session starts with no choice.
        keys = [b.key for b in app.button]
        self.assertFalse([k for k in keys if k.startswith(('agentic_approve', 'agentic_manual', 'agentic_complete'))])
        self.assertNotIn('agentic_run', keys)
        self.assertIn('agentic_completion_report', [b.key for b in app.get('download_button')])
        app.button(key='agentic_reset').click().run()
        self.assertEqual(decisions.latest(server, app.session_state.get(agentic_view.SESSION, 'new')), {})

    def test_expired_approvals_do_not_hold_the_next_round(self):
        # Live check 9 Nov: expired approvals could only be cleared by "executing" them.
        from hardening import remediation
        with patch.object(remediation, 'APPROVAL_LIFETIME', timedelta(seconds=-1)):  # Expired as soon as approved.
            app = self._approve_all(self._start_round())
        app.run()
        keys = [b.key for b in app.button]
        self.assertNotIn('agentic_execute_review', keys)
        self.assertIn('agentic_run', keys)
        self.assertTrue(any('2 approval(s) expired before they ran; run the next round' in m.value for m in app.markdown))

    def test_after_a_failed_fix_the_next_round_is_offered(self):
        # Live check 9 Nov: the review said "a new proposal and approval are required", yet only Execute was offered.
        self.vm.fail_action = 'Access is denied.'
        app = self._approve_all(self._start_round())
        app.button(key='agentic_execute_review').click().run()
        app.button(key='agentic_execute').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertIn('agentic_run', [b.key for b in app.button])
        self.assertTrue(any('did not become compliant' in w.value.replace('\\', '') for w in app.warning))

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
        self.assertEqual(top[0]['Fix'], 'Manual: not automated')
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
        # The agents at work: the Orchestrator is asking the model, the Scanner and Analysis wait their turn.
        stage = [h.value for h in app.get('html') if 'fyp-stage' in h.value]
        self.assertEqual(len(stage), 1)
        self.assertIn('fyp-agent fyp-active"><span class="fyp-icon fyp-i-orchestrator"></span>Orchestrator', stage[0])
        self.assertIn('Scanner<span class="fyp-state">waiting', stage[0])
        self.assertTrue(any('AI Agent Orchestrator' in c.value and 'first step' in c.value for c in app.caption))
        # User report: buttons on the page could still be clicked while work ran. Now only Disconnect, and it waits.
        self.assertEqual([b.key for b in app.button], ['agentic_disconnect'])
        self.assertTrue(app.button(key='agentic_disconnect').disabled)
        self.assertEqual(app.get('download_button'), [])
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

    def test_controls_this_program_does_not_fix_are_listed_with_steps_and_a_choice(self):
        app = self._start_round()
        text = ' '.join(m.value for m in app.markdown)
        self.assertIn('**Not fixed by this program**', text)
        self.assertIn('1 control(s) this program does not fix need your choice in **Fixes**.', text)
        for control in ('9.2.1', '9.2.2', '9.3.1', '9.3.2'):
            self.assertIn(f'**{control} ·', text)
        self.assertEqual(text.count('Compliant now'), 3)  # Listed, never hidden or shown as Not applicable.
        self.assertEqual([b.key for b in app.button if b.key.startswith('agentic_manual_')],
                         ['agentic_manual_fix_9.3.1', 'agentic_manual_exception_9.3.1'])
        # The name comes first: a click without it records nothing and says why.
        app.button(key='agentic_manual_fix_9.3.1').click().run()
        self.assertTrue(any('Your name is recorded' in e.value for e in app.error))
        self.assertIn('need your choice in **Fixes**', ' '.join(m.value for m in app.markdown))
        steps = ' '.join(m.value.replace('\\', '') for e in app.expander if e.label == 'How to fix it on the server'
                         for m in e.markdown)
        self.assertIn('Press Win+R, type gpedit.msc and press Enter.', steps)

        app.text_input(key='agentic_operator').input('admin01').run()
        app.button(key='agentic_manual_exception_9.3.1').click().run()
        app.button(key='agentic_manual_accept_9.3.1').click().run()  # An exception needs a reason.
        self.assertTrue(any('An exception needs a reason' in e.value for e in app.error))
        app.button(key='agentic_manual_exception_9.3.1').click().run()
        app.text_input(key='agentic_manual_reason_9.3.1').input('Firewall run by the network team').run()
        app.button(key='agentic_manual_accept_9.3.1').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        captions = ' '.join(c.value for c in app.caption)
        self.assertIn('Accepted as an exception · admin01', captions)
        self.assertIn('Firewall run by the network team', captions)
        self.assertNotIn('need your choice in **Fixes**', ' '.join(m.value for m in app.markdown))

        app.button(key='agentic_manual_withdraw_9.3.1').click().run()
        self.assertIn('1 control(s) this program does not fix need your choice', ' '.join(m.value for m in app.markdown))
        app.button(key='agentic_manual_fix_9.3.1').click().run()
        self.assertIn('Will fix it by hand on the server · admin01', ' '.join(c.value for c in app.caption))
        self.assertEqual(self.vm.writes, [])  # A choice never changes the server.
        rows = {r['Control']: r for frame in app.dataframe for r in frame.value.to_dict('records')
                if 'Fix' in r and 'Area' in r}
        self.assertEqual((rows['9.3.1']['Fix'], rows['1.1.1']['Fix']), ('Manual: not automated', 'Program fix'))

    def test_typing_a_name_and_clicking_approve_works_in_one_click(self):
        # Streamlit commits typed text when the field loses focus, which a click on a button does. A button that
        # stayed disabled until then needed a second click; now the first click carries the name with it.
        app = self._start_round()
        approve = [b for b in app.button if b.key.startswith('agentic_approve_') and b.key != 'agentic_approve_all']
        self.assertFalse(approve[0].disabled)
        approve[0].click().run()  # No name yet: nothing is decided, and the page says what to type.
        self.assertEqual([w.value for w in app.warning], ['Type your name first: it is recorded with each decision.'])
        self.assertEqual(len([b for b in app.button if b.key.startswith('agentic_approve_')
                              and b.key != 'agentic_approve_all']), 2)
        app.text_input(key='agentic_operator').set_value('admin01')
        approve = [b for b in app.button if b.key.startswith('agentic_approve_') and b.key != 'agentic_approve_all']
        approve[0].click().run()  # Typed and clicked in one go.
        self.assertEqual(len([b for b in app.button if b.key.startswith('agentic_approve_')
                              and b.key != 'agentic_approve_all']), 1)
        self.assertTrue(any('by admin01' in c.value for c in app.caption))

    def test_page_without_connection_asks_to_connect(self):
        app = AppTest.from_function(agentic_page, default_timeout=30).run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('Open **Servers** to pair a server' in i.value for i in app.info))



class StepBadgeTests(unittest.TestCase):
    """The progress badges say what happened, not more (live check 9 Nov)."""

    def test_nothing_executed_is_not_a_failed_verification(self):
        from hardening.agentic_view import _steps
        refused = 'Refused before execution: approval expired'
        state = dict(records=[dict(decision='approved', verdict=refused)], undecided=[], pending=[],
                     verification=dict(framework_run_id=None, verdicts=[dict(proposal_id='p', verdict=refused)]))
        steps = _steps(dict(framework_run_id='run', outcome={'outcome': 'awaiting_approval'}), state, analysis={})
        self.assertEqual((steps['Execute'], steps['Verify']), ('skipped', 'skipped'))

    def test_an_executed_fix_without_a_rescan_is_a_failed_verification(self):
        from hardening.agentic_view import _steps
        uncertain = 'Unresolved: outcome uncertain (channel lost); rescan to observe'
        state = dict(records=[dict(decision='approved', verdict=uncertain)], undecided=[], pending=[],
                     verification=dict(framework_run_id=None, verdicts=[dict(proposal_id='p', verdict=uncertain)]))
        steps = _steps(dict(framework_run_id='run', outcome={'outcome': 'awaiting_approval'}), state, analysis={})
        self.assertEqual((steps['Execute'], steps['Verify']), ('done', 'failed'))

    def test_a_model_that_never_answered_is_not_a_failed_scan(self):
        from hardening.agentic_view import _steps
        steps = _steps(dict(framework_run_id=None, outcome={'outcome': 'incomplete', 'model_unavailable': True}),
                       {}, None)
        self.assertEqual(set(steps.values()), {'pending'})


if __name__ == '__main__':
    unittest.main()
