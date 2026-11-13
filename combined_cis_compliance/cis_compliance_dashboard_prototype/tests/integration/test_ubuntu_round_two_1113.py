"""Round 2 of the snapshot-restored VM and the remediation view (administrator, 13 November 2026).

- Round 2 (07:14 UTC) planned nothing: the five controls that waited for 4.1.3 and 6.3.1.1 now had their fixes, the
  Orchestrator proposed exactly those five, but it sent `"defers": {}` (an empty object), which the plan check
  refused three times ("defers entries take exactly: control_id, reason_code"). An empty object or null means none.
- (The 6.3.1.3 reboot note: since the batched execution no reboot is offered at all, test_ubuntu_batched_execution_1113.)
- The continuation of an execution showed only the Scanner card; it now shows Orchestrator -> Remediation -> Scanner
  like the first part, and every running view counts the time from the start of the whole execution.
Fakes only; no VM, no model.
"""
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as N
from unittest import mock

from tests.integration import test_ubuntu_remediation_flow_1113 as flow

ROUND_TWO = ['4.1.4', '4.1.7', '6.3.3.4', '6.3.3.6', '6.3.3.8']


class EmptyDefersTests(unittest.TestCase):
    def test_the_live_round_two_plan_is_accepted(self):
        from tests.integration.test_ubuntu_plan_errors import tools_for
        for empty in ({}, None, []):
            with self.subTest(defers=empty):
                tools = tools_for(ROUND_TWO, {c: 'ubuntu.%s.v1' % c for c in ROUND_TWO})
                result = tools.call('submit_plan', {'target_id': 'ubuntu:fixture', 'defers': empty, 'fixes': [
                    {'action_id': 'ubuntu.%s.v1' % c, 'control_id': c, 'reason_code': 'confirmed_failure'}
                    for c in ROUND_TWO]})  # before: refused three times, so no plan at all
                self.assertEqual(result['status'], 'accepted')
                self.assertEqual([f['control_id'] for f in tools.rounds.plan['fixes']], ROUND_TWO)

    def test_an_entry_missing_its_fields_is_still_refused(self):
        from tests.integration.test_ubuntu_plan_errors import tools_for
        tools = tools_for(ROUND_TWO, {c: 'ubuntu.%s.v1' % c for c in ROUND_TWO})
        with self.assertRaises(ValueError):
            tools.call('submit_plan', {'target_id': 'ubuntu:fixture', 'defers': [{}]})


class ThreeAgentsTests(unittest.TestCase):
    def test_the_continuation_shows_the_three_agents(self):
        from hardening import live_progress
        from hardening.agentic_view import UBUNTU_AGENTS_EXECUTE_LABEL, UBUNTU_CONTINUE_LABEL, _stage_for
        three = (live_progress.ORCHESTRATOR, live_progress.REMEDIATION, live_progress.SCANNER)
        self.assertEqual(_stage_for(N(label=UBUNTU_CONTINUE_LABEL), None)[0], three)  # before: the Scanner alone
        self.assertEqual(live_progress.phase_roles(UBUNTU_AGENTS_EXECUTE_LABEL), three)

    def test_the_time_counts_from_the_start_of_the_whole_execution(self):
        from hardening.agentic_view import (UBUNTU_CONTINUE_LABEL, UBUNTU_EXECUTION_SINCE, ROUND_LABEL,
                                            _running_since)
        first = datetime(2026, 11, 13, 7, 0, tzinfo=timezone.utc)
        later = first + timedelta(minutes=4)
        state = {UBUNTU_EXECUTION_SINCE: first}
        self.assertEqual(_running_since(N(label=UBUNTU_CONTINUE_LABEL, started_at=later), state), first)
        self.assertEqual(_running_since(N(label=ROUND_LABEL, started_at=later), state), later)  # a round: its own
        self.assertEqual(_running_since(N(label=UBUNTU_CONTINUE_LABEL, started_at=later), {}), later)


class HeldTotalTests(flow.HeldRemediationTests):
    def test_the_held_view_counts_the_whole_execution_and_forgets_it_when_done(self):
        from hardening.agentic_view import UBUNTU_EXECUTION_SINCE
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.page()
            app.button(key='agentic_run').click().run()
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            [b for b in app.button if b.key and b.key.startswith('ubuntu_approve_') and b.key != 'ubuntu_approve_all'][0] \
                .click().run()
            self.model_up = False
            app.button(key='ubuntu_execute_review').click().run()
            app.button(key='ubuntu_execute').click().run()
            app.run()
            self.assertIn(UBUNTU_EXECUTION_SINCE, app.session_state)
            self.assertTrue(any('so far' in m.value for m in app.markdown if 'Remediation' in m.value),
                            [m.value for m in app.markdown])
            [rid] = list(self.launcher.active)
            self.runner().run_job(rid)
            self.launcher.active.discard(rid)
            app.run()
            app.run()
            self.assertFalse(self.held(app))
            self.assertNotIn(UBUNTU_EXECUTION_SINCE, app.session_state)  # the next execution counts afresh


for _name in [n for n in dir(flow.HeldRemediationTests) if n.startswith('test')]:
    setattr(HeldTotalTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
