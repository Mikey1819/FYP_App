"""Plan refusals must reach the model whole. Live 2026-11-07 06:40 and 06:42 (after 3.3.2 was fixed): the
orchestrator submitted only the two flagged fixes; the refusal listed the 18 undecided controls, but the protected
Coordinator cuts every tool error at 200 characters, so the model never saw 6.3.3.4, 6.3.3.6 and 6.3.3.8, used its
retries on them and the round ended "Invalid calls blocked" with no plan. No model or VM is contacted."""
import types
import unittest

LIVE_FAILING = ['1.2.2.1', '1.5.1', '1.5.3', '2.1.2', '3.3.1', '3.3.8', '4.1.4', '4.1.7', '5.1.16', '5.1.20',
                '5.1.7', '5.2.3', '5.3.3.2.2', '5.4.1.1', '5.4.1.5', '6.3.1.1', '6.3.1.2', '6.3.1.3', '6.3.3.4',
                '6.3.3.6', '6.3.3.8']
COORDINATOR_LIMIT = 200  # hardening/investigation.py: output = {"error": str(error)[:200]}


def tools_for(failing, eligible):
    from backends.ubuntu.agents import OrchestratorTools
    evidence = types.SimpleNamespace(expected=types.SimpleNamespace(evidence_mode='fixture'), assessments=())
    rounds = types.SimpleNamespace(store=None, target_id='ubuntu:fixture', evidence=evidence, goal=None,
                                   eligible=eligible, failing=lambda: list(failing))
    tools = OrchestratorTools(rounds)
    tools.scanned = tools.analysed = True
    return tools


def refusal(tools, **arguments):
    try:
        tools.call('submit_plan', {'target_id': 'ubuntu:fixture', **arguments})
    except ValueError as error:
        return str(error)
    raise AssertionError('plan was accepted')


def fix(control):
    return {'control_id': control, 'action_id': 'ubuntu.%s.v1' % control, 'reason_code': 'confirmed_failure'}


class PlanErrorTests(unittest.TestCase):
    def test_the_live_partial_plan_refusal_names_every_undecided_control_within_the_limit(self):
        eligible = {c: 'ubuntu.%s.v1' % c for c in LIVE_FAILING if c != '6.3.1.2'}
        text = refusal(tools_for(LIVE_FAILING, eligible), fixes=[fix('5.1.20'), fix('4.1.4')],
                       defers=[{'control_id': '6.3.1.2', 'reason_code': 'no_registered_action'}])
        self.assertLessEqual(len(text), COORDINATOR_LIMIT)
        missing = [c for c in eligible if c not in ('5.1.20', '4.1.4')]
        self.assertEqual([c for c in missing if c not in text.replace(',', ' ').split()], [])

    def test_when_every_name_cannot_fit_the_refusal_says_how_many_more(self):
        from backends.ubuntu.actions import FAMILIES
        every = sorted(a[len('ubuntu.'):-len('.v1')] for a in FAMILIES if a.startswith('ubuntu.'))
        text = refusal(tools_for(every, {c: 'ubuntu.%s.v1' % c for c in every}))
        self.assertLessEqual(len(text), COORDINATOR_LIMIT)
        shown = [c for c in every if c in text.replace(',', ' ').split()]
        self.assertIn('+%d more' % (len(every) - len(shown)), text)
        self.assertIn('registered_actions', text)

    def test_every_other_plan_refusal_fits_the_limit(self):
        long_id = '5.3.3.2.2'
        tools = tools_for([long_id], {long_id: 'ubuntu.%s.v1' % long_id})
        cases = [dict(fixes=[{'control_id': long_id, 'action_id': 'x' * 200, 'reason_code': 'confirmed_failure'}]),
                 dict(fixes=[{'control_id': long_id, 'action_id': 'ubuntu.%s.v1' % long_id, 'reason_code': 'y' * 200}]),
                 dict(defers=[{'control_id': long_id, 'reason_code': 'z' * 200}]),
                 dict(defers=[{'control_id': long_id, 'reason_code': 'no_registered_action'}])]
        for arguments in cases:
            with self.subTest(arguments=str(arguments)[:60]):
                self.assertLessEqual(len(refusal(tools, **arguments)), COORDINATOR_LIMIT)


if __name__ == '__main__':
    unittest.main()
