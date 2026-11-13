"""Group 2 of the 12 November round (user report, 13 November): 4.1.3 and 5.1.20 were deferred as
needs_manual_review, so they got no card at all. The Analysis Agent had flagged both persistent_failure, which only
meant "failing in an earlier scan too": neither fix had ever run.

- persistent_failure is now true only when an approved fix of that control was applied and the control still did not
  verify Compliant (the live-validation register's "Applied, not verified").
- A fixable control deferred as needs_manual_review without that fact is still proposed by code, with the
  Orchestrator's concern in its reason, so the administrator decides (as on Windows since 9 November).
Scripted agents and fakes only; no model, no VM.
"""
import unittest
from types import SimpleNamespace as N

from tests.integration import test_ubuntu_agents as agents
from tests.integration.test_ubuntu_agents import call, plan_call, scanner_ok, team

FINDING = N(control_id='5.1.20', rank=1, D=4, score=70, level='High')


class FlagTests(unittest.TestCase):
    def test_failing_before_is_not_enough_an_applied_fix_must_have_failed(self):
        from backends.ubuntu.agents import FLAGS, flag_is_true
        self.assertFalse(flag_is_true('persistent_failure', '5.1.20', FINDING))  # before: True (D >= 3)
        self.assertTrue(flag_is_true('persistent_failure', '5.1.20', FINDING, fix_failed={'5.1.20'}))
        self.assertIn('applied', FLAGS['persistent_failure'])


class DeferTests(agents.AgentRoundTests):
    def run_with(self, defers, fix_failed=(), eligible=None):
        from backends.ubuntu.agents import run_agentic_round
        from backends.ubuntu.adapter import _controls
        clients = team([call('delegate_scanner'), call('delegate_analysis'),
                        call('submit_plan', fixes=[], defers=defers)], scanner_ok(),
                       [call('read_ranking'), call('submit_analysis', flags=[], gap_triage=[
                           {'control_id': '2.4.1.2', 'triage_code': 'manual_review'}])])
        for client in clients.values():
            for item in getattr(client, 'script', []):
                item['tool_calls'][0]['function']['arguments']['target_id'] = agents.TARGET
        return run_agentic_round(client_factory=clients.__getitem__, collect=self.collect_with(), log_store=self.log,
                                 target_id=agents.TARGET, titles={c: x.title for c, x in _controls().items()},
                                 rank=lambda run_id, ev: [FINDING, N(control_id='1.5.1', rank=2, D=1, score=50,
                                                                    level='Moderate')],
                                 eligible=eligible or (lambda ev: {'1.5.1': 'ubuntu.1.5.1.v1', '5.1.20': 'ubuntu.5.1.20.v1'}),
                                 fix_failed=frozenset(fix_failed))

    def test_an_unsupported_review_deferral_of_a_fixable_control_still_gets_a_card(self):
        result = self.run_with([{'control_id': '5.1.20', 'reason_code': 'needs_manual_review'}])
        fixes = {f['control_id']: f['reason_code'] for f in result['plan']['fixes']}
        self.assertEqual(fixes.get('5.1.20'), 'review_unsupported')
        self.assertNotIn('5.1.20', [d['control_id'] for d in result['plan']['decisions']])

    def test_a_review_deferral_after_a_failed_fix_stands(self):
        result = self.run_with([{'control_id': '5.1.20', 'reason_code': 'needs_manual_review'}], fix_failed={'5.1.20'})
        self.assertIn({'control_id': '5.1.20', 'decision': 'defer', 'reason_code': 'needs_manual_review'},
                      result['plan']['decisions'])
        self.assertNotIn('5.1.20', [f['control_id'] for f in result['plan']['fixes']])

    def test_a_review_deferral_of_a_control_without_a_registered_fix_stands(self):
        result = self.run_with([{'control_id': '5.1.20', 'reason_code': 'needs_manual_review'}],
                               eligible=lambda ev: {'1.5.1': 'ubuntu.1.5.1.v1'})
        self.assertIn({'control_id': '5.1.20', 'decision': 'defer', 'reason_code': 'needs_manual_review'},
                      result['plan']['decisions'])
        self.assertEqual([f['control_id'] for f in result['plan']['fixes']], ['1.5.1'])

    def test_the_card_says_what_the_orchestrator_suggested(self):
        from backends.ubuntu.agents import DEFAULT_FIX_REASONS
        self.assertIn('manual review', DEFAULT_FIX_REASONS['review_unsupported'])


class BackendFactTests(unittest.TestCase):
    def test_the_fact_comes_from_applied_fixes_that_did_not_verify(self):
        from backends.ubuntu.adapter import _fix_failed
        rows = [{'control_id': '5.1.20', 'status': 'Applied, not verified'}, {'control_id': '4.1.3', 'status': 'Refused'},
                {'control_id': '1.5.1', 'status': 'Validated live'}, {'control_id': '3.3.2', 'status': 'Fixture-tested only'}]
        self.assertEqual(_fix_failed(rows), frozenset({'5.1.20'}))


for _name in [n for n in dir(agents.AgentRoundTests) if n.startswith('test')]:
    setattr(DeferTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
