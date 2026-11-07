"""The plan list shapes qwen3:8b actually sends. Live 2026-11-07 07:11: `defers` came as one object of parallel lists
(and repeated fixes), the refusal was resubmitted identically and the Coordinator ended the round with no plan. An
offline trial with the real local model (10 of 10 rounds) sent a single deferral as one object instead of a list.
Unambiguous shapes are read as the list they mean and then validated as usual. Scripted models; no VM."""
import unittest

from tests.integration.test_ubuntu_plan_errors import COORDINATOR_LIMIT, LIVE_FAILING, tools_for
from tests.integration.test_ubuntu_plan_defaults import ELIGIBLE

LIVE_0711 = {'defers': {'control_id': ['5.1.20', '4.1.4'], 'reason_code': ['highest_risk', 'highest_risk']},
             'fixes': [{'action_id': 'ubuntu.5.1.20.v1', 'control_id': '5.1.20', 'reason_code': 'highest_risk'},
                       {'action_id': 'ubuntu.4.1.4.v1', 'control_id': '4.1.4', 'reason_code': 'highest_risk'}]}


def submit(arguments):
    tools = tools_for(LIVE_FAILING, ELIGIBLE)
    tools.call('submit_plan', {'target_id': 'ubuntu:fixture', **arguments})
    return tools.rounds.plan


def refusal(arguments):
    tools = tools_for(LIVE_FAILING, ELIGIBLE)
    try:
        tools.call('submit_plan', {'target_id': 'ubuntu:fixture', **arguments})
    except ValueError as error:
        return str(error)
    raise AssertionError('plan was accepted')


class PlanShapeTests(unittest.TestCase):
    def test_a_single_deferral_object_is_read_as_a_one_item_list(self):
        # The offline trial's exact call.
        plan = submit({'defers': {'control_id': '6.3.1.2', 'reason_code': 'no_registered_action'}, 'fixes': []})
        self.assertEqual(plan['decisions'], [{'control_id': '6.3.1.2', 'decision': 'defer',
                                              'reason_code': 'no_registered_action'}])
        self.assertEqual(len(plan['fixes']), len(ELIGIBLE))

    def test_a_single_fix_object_is_read_as_a_one_item_list(self):
        plan = submit({'fixes': {'control_id': '5.1.20', 'action_id': 'ubuntu.5.1.20.v1', 'reason_code': 'highest_risk'}})
        self.assertIn({'control_id': '5.1.20', 'decision': 'fix', 'action_id': 'ubuntu.5.1.20.v1',
                       'reason_code': 'highest_risk'}, plan['fixes'])

    def test_parallel_lists_are_read_as_entries(self):
        plan = submit({'defers': {'control_id': ['5.1.20', '4.1.4'],
                                  'reason_code': ['needs_manual_review', 'needs_manual_review']}})
        self.assertEqual([d['control_id'] for d in plan['decisions']], ['5.1.20', '4.1.4'])

    def test_parallel_lists_of_different_lengths_are_refused(self):
        text = refusal({'defers': {'control_id': ['5.1.20', '4.1.4'], 'reason_code': ['needs_manual_review']}})
        self.assertIn('defers', text)

    def test_the_live_0711_plan_is_refused_naming_the_contradiction(self):
        text = refusal(LIVE_0711)
        self.assertLessEqual(len(text), COORDINATOR_LIMIT)
        self.assertIn('5.1.20', text)
        self.assertIn('fixes', text)
        self.assertIn('defers', text)

    def test_an_identical_retry_of_a_refused_plan_is_refused_again_not_round_ending(self):
        from tests.integration.test_ubuntu_plan_format import PlanFormatTests
        case = PlanFormatTests('test_separate_lists_store_the_same_plan_as_before')
        case.setUp()
        self.addCleanup(case.doCleanups)
        bad = {'defers': [{'control_id': '5.1.20', 'reason_code': 'not_a_reason'}]}
        result, events = case.round_with(bad, bad, {})
        self.assertEqual([e['kind'] for e in events if e['kind'] in ('tool', 'tool_rejected')][-3:],
                         ['tool_rejected', 'tool_rejected', 'tool'])
        self.assertEqual(result['status'], 'Completed')
        self.assertIsNotNone(result['plan'])


if __name__ == '__main__':
    unittest.main()
