"""Plan refusals must reach the model whole. Live 2026-11-07 06:40 and 06:42: the protected Coordinator cuts every
tool error at 200 characters, so a longer refusal (then the list of undecided controls) lost its last names and the
round ran out of retries. Undeferred controls are now proposed by default (test_ubuntu_plan_defaults); the refusals
that remain must still fit. No model or VM is contacted."""
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
