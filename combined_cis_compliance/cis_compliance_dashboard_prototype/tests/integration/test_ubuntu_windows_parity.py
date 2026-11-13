"""The Ubuntu page matches the Windows page (administrator request 2026-11-09): the Results message before anything
ran, the Agent log as a summary table plus one expandable card per agent, no "Refresh status" button, and the
remediation outcome at the end of the step bar ("→ Next round recommended" and the other Windows labels).
TEST-ONLY file-value family and scripted models; no VM."""
import unittest
from unittest import mock

from tests.integration import test_ubuntu_round_views as views  # module import: base tests are not collected twice

SUMMARY_COLUMNS = ['Agent', 'Status', 'Decision', 'Tool calls', 'Seconds', 'Engine']
STEP_COLUMNS = ['Step', 'Event', 'Tool', 'Arguments', 'Result or error']


class WindowsParityTests(views.RoundViewTests):
    @staticmethod
    def step_bar(app):
        [bar] = [m.value for m in app.markdown if '1 Scan' in m.value and '6 Verify' in m.value]
        return bar

    @staticmethod
    def infos(container):
        return [i.value for i in container.info]

    def agent_log(self, app):
        log = self.tab(app, 'Agent log')
        summaries = [f.value for f in log.dataframe if list(f.value.columns) == SUMMARY_COLUMNS]
        return log, summaries

    def test_results_agent_log_refresh_and_step_bar_follow_the_windows_page(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            app = self.page()
            self.ok(app.button(key='agentic_run').click().run())
            self.assertNotIn('ubuntu_refresh', self.keys(app))  # no "Refresh status" button
            # Results before anything ran: the Windows message.
            results = self.tab(app, 'Results')
            self.assertEqual(self.infos(results), ['Nothing has been executed for this round yet.'])
            # Agent log: per phase, a summary table, then one expandable card per agent with its steps.
            log, summaries = self.agent_log(app)
            self.assertIn('**Assessment phase**', [m.value for m in log.markdown])
            [summary] = summaries
            self.assertEqual(list(summary['Agent']), ['AI Agent Orchestrator', 'Scanner Agent', 'Analysis Agent'])
            self.assertEqual(len(log.expander), 3)
            self.assertEqual(log.expander[0].label, 'AI Agent Orchestrator: 3 tool calls, completed')
            # The Windows step columns, plus each step's model response time (module 2, Ubuntu only, 12 November).
            self.assertEqual(list(log.expander[0].dataframe[0].value.columns), STEP_COLUMNS + ['Model seconds'])
            self.assertEqual(list(log.expander[0].dataframe[0].value['Event'])[-1], 'Finished')
            self.assertIn('Every tool call was chosen by the agent and checked by code; rejected calls had no effect.',
                          [c.value for c in log.caption])
            self.assertNotIn(':material/flag:', self.step_bar(app))  # no remediation outcome yet
            # Execute: the Remediation Agent stops early, so the step bar ends with the Windows label.
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.ok(self.approve_buttons(app)[0].click().run())
            with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
                app.run()
                self.ok(app.button(key='ubuntu_execute_review').click().run())
                self.ok(app.button(key='ubuntu_execute').click().run())
                self.ok(app.run())
                self.assertIn(' → :orange-badge[:material/flag: Agents stopped early]', self.step_bar(app))
                log, summaries = self.agent_log(app)
                self.assertIn('**Remediation phase**', [m.value for m in log.markdown])
                self.assertEqual(len(summaries), 2)
                self.ok(app.button(key='ubuntu_execute_fallback').click().run())
                self.ok(app.run())
                self.assertIn(' → :blue-badge[:material/flag: Executed without AI]', self.step_bar(app))
                self.assertNotIn('Nothing has been executed', ' '.join(self.infos(self.tab(app, 'Results'))))
                # The next round proposes nothing: the Windows message for that, and no outcome yet.
                self.ok(app.button(key='agentic_run').click().run())
                self.assertEqual(self.infos(self.tab(app, 'Results')), ['Nothing to execute in this round.'])
                self.assertNotIn(':material/flag:', self.step_bar(app))
                # The earlier round keeps its own outcome in the step bar.
                self.ok(app.selectbox(key='ubuntu_round_view').select_index(1).run())
                self.assertIn(' → :blue-badge[:material/flag: Executed without AI]', self.step_bar(app))


class OutcomeTests(unittest.TestCase):
    """The Orchestrator's review as the Windows step bar's outcome key (labels in NEXT_STEP)."""

    def test_reviews_map_to_the_windows_outcomes(self):
        from hardening.agentic_view import NEXT_STEP, _ubuntu_outcome
        review = lambda step, code=None: {'next_step': step, 'reason_code': code, 'reason': 'r'}
        self.assertIsNone(_ubuntu_outcome(None))
        self.assertEqual(_ubuntu_outcome(review('next_round', 'remaining_findings')), 'next_round')
        self.assertEqual(NEXT_STEP['next_round'][1], 'Next round recommended')
        self.assertEqual(_ubuntu_outcome(review('finish', 'all_verified')), 'finish')
        self.assertEqual(_ubuntu_outcome(review('remediation_review', 'verification_failed')), 'remediation_review')
        self.assertEqual(_ubuntu_outcome(review('remediation_review', 'remediation_incomplete')), 'incomplete')
        self.assertEqual(_ubuntu_outcome(review(None)), 'incomplete')
        self.assertEqual(_ubuntu_outcome(review('fallback')), 'fallback')


for _name in [n for n in dir(views.RoundViewTests) if n.startswith('test')]:
    setattr(WindowsParityTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
