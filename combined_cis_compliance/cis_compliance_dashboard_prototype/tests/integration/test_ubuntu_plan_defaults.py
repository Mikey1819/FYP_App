"""A plan decides by deferring. Live 2026-11-07 06:40, 06:42, 06:52 and 06:57: qwen3:8b's first plan always held
only the two flagged fixes; refusing it never recovered (a cut-off refusal, a false no_registered_action deferral,
then twice an identical resubmission, which the protected Coordinator blocks), so no plan was stored at all. Every
failure with a registered action that the orchestrator does not defer is now proposed as a fix, with a reason that
says so; the administrator still approves each one. No model or VM is contacted."""
import unittest

from tests.integration.test_ubuntu_plan_errors import LIVE_FAILING, fix, tools_for

ELIGIBLE = {c: 'ubuntu.%s.v1' % c for c in LIVE_FAILING if c != '6.3.1.2'}  # 6.3.1.2 waits for auditd (6.3.1.1)
LIVE_0657 = {'fixes': [dict(fix('5.1.20'), reason_code='highest_risk'), dict(fix('4.1.4'), reason_code='highest_risk')],
             'defers': [{'control_id': '6.3.1.2', 'reason_code': 'no_registered_action'}]}


def submit(arguments, eligible=ELIGIBLE):
    tools = tools_for(LIVE_FAILING, eligible)
    result = tools.call('submit_plan', {'target_id': 'ubuntu:fixture', **arguments})
    return tools, result


class PlanDefaultTests(unittest.TestCase):
    def test_the_live_first_plan_is_accepted_with_every_undeferred_fix_proposed(self):
        tools, result = submit(LIVE_0657)
        self.assertEqual(result['status'], 'accepted')
        plan = tools.rounds.plan
        by_reason = {}
        for entry in plan['fixes']:
            by_reason.setdefault(entry['reason_code'], []).append(entry['control_id'])
        self.assertEqual(sorted(by_reason['highest_risk']), ['4.1.4', '5.1.20'])
        self.assertEqual(sorted(by_reason['not_deferred']), sorted(c for c in ELIGIBLE if c not in ('4.1.4', '5.1.20')))
        self.assertEqual({e['action_id'] for e in plan['fixes']}, {ELIGIBLE[e['control_id']] for e in plan['fixes']})
        self.assertEqual([d['control_id'] for d in plan['decisions']], ['6.3.1.2'])
        self.assertEqual(plan['deferred_by_code'], [])
        self.assertEqual(plan['outcome'], 'fix_proposed')

    def test_a_deferral_is_still_the_orchestrators_decision(self):
        tools, _ = submit({'defers': [{'control_id': '5.1.20', 'reason_code': 'needs_manual_review'}]})
        self.assertNotIn('5.1.20', [e['control_id'] for e in tools.rounds.plan['fixes']])
        self.assertEqual(tools.rounds.plan['decisions'], [{'control_id': '5.1.20', 'decision': 'defer',
                                                           'reason_code': 'needs_manual_review'}])

    def test_the_model_cannot_claim_the_default_reason_itself(self):
        tools = tools_for(LIVE_FAILING, ELIGIBLE)
        with self.assertRaises(ValueError):
            tools.call('submit_plan', {'target_id': 'ubuntu:fixture', 'fixes': [dict(fix('5.1.20'), reason_code='not_deferred')]})
        enum = tools.schemas()[0]['function']['parameters']['properties']['fixes']['items']['properties']['reason_code']['enum']
        self.assertNotIn('not_deferred', enum)

    def test_a_false_no_registered_action_deferral_is_still_refused(self):
        tools = tools_for(LIVE_FAILING, ELIGIBLE)
        with self.assertRaises(ValueError):
            tools.call('submit_plan', {'target_id': 'ubuntu:fixture',
                                       'defers': [{'control_id': '6.3.3.4', 'reason_code': 'no_registered_action'}]})

    def test_the_fixes_card_reason_says_the_planner_did_not_defer_it(self):
        from backends.ubuntu.adapter import _plan_rows
        from backends.ubuntu.agents import FIX_REASONS
        tools, _ = submit(LIVE_0657)
        from types import SimpleNamespace as N
        from system.contracts import ComplianceStatus
        evidence = N(assessments=[N(control_id='1.5.1', status=ComplianceStatus.NON_COMPLIANT)])
        rows = _plan_rows({'plan': tools.rounds.plan}, evidence, {'1.5.1': N(title='ASLR')})
        self.assertEqual(rows[0].decision, 'Fix proposed')
        self.assertEqual(rows[0].reason, 'Confirmed CIS failure with a registered fix; the planner did not defer it')
        self.assertNotIn('not_deferred', FIX_REASONS)


if __name__ == '__main__':
    unittest.main()
