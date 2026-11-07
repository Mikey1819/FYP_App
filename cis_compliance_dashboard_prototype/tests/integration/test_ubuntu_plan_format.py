"""Live 2026-11-07 03:57: qwen3:8b offered all 22 fixes but gave each the defer reason "no_registered_action",
because fix and defer reasons shared one field; the identical retry was blocked and no plan was stored.
submit_plan now takes separate `fixes` and `defers` lists, each with only its own reasons.
Round goals are disabled for Ubuntu (to be removed). Scripted models; no VM is contacted."""
import unittest

ELIGIBLE = {'1.5.1': 'fixture.file_value.v1'}


class PlanFormatTests(unittest.TestCase):
    def setUp(self):
        from tests.integration.test_ubuntu_agents import AgentRoundTests
        self.case = AgentRoundTests('test_complete_round_delegates_in_order_and_defers_every_finding')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def round_with(self, *plans):
        from backends.ubuntu.agents import run_agentic_round
        from backends.ubuntu.adapter import _controls
        from tests.integration.test_ubuntu_agents import call, team, scanner_ok, analysis_ok
        script = [call('delegate_scanner'), call('delegate_analysis')] + [call('submit_plan', **p) for p in plans]
        clients = team(script, scanner_ok(), analysis_ok())
        self.clients = clients
        result = run_agentic_round(client_factory=clients.__getitem__, collect=self.case.collect_with(),
                                   log_store=self.case.log, target_id='ubuntu:fixture',
                                   titles={c: x.title for c, x in _controls().items()},
                                   rank=lambda r, e: None, eligible=ELIGIBLE)
        return result, self.case.events(result['orchestrator_run_id'])

    def test_separate_lists_store_the_same_plan_as_before(self):
        result, _ = self.round_with({'fixes': [{'control_id': '1.5.1', 'action_id': ELIGIBLE['1.5.1'],
                                                'reason_code': 'high_risk'}],
                                     'defers': [{'control_id': '5.1.20', 'reason_code': 'no_registered_action'}]})
        plan = result['plan']
        self.assertEqual(plan['fixes'], [{'control_id': '1.5.1', 'decision': 'fix', 'action_id': ELIGIBLE['1.5.1'],
                                          'reason_code': 'high_risk'}])
        self.assertEqual(plan['decisions'], [{'control_id': '5.1.20', 'decision': 'defer',
                                              'reason_code': 'no_registered_action'}])
        self.assertEqual(plan['outcome'], 'fix_proposed')

    def test_either_list_may_be_omitted(self):
        result, _ = self.round_with({'fixes': [{'control_id': '1.5.1', 'action_id': ELIGIBLE['1.5.1'],
                                                'reason_code': 'high_risk'}]})
        self.assertEqual(result['plan']['deferred_by_code'], [{'control_id': '5.1.20', 'reason_code': 'not_decided'}])

    def test_each_list_offers_only_its_own_reasons(self):
        from backends.ubuntu.agents import DEFER_REASONS, FIX_REASONS
        self.round_with({})
        schema = [t for t in self.tools_offered() if t['function']['name'] == 'submit_plan'][0]['function']['parameters']
        props = schema['properties']
        self.assertNotIn('decisions', props)
        fix_codes = set(props['fixes']['items']['properties']['reason_code']['enum'])
        defer_codes = set(props['defers']['items']['properties']['reason_code']['enum'])
        self.assertTrue(fix_codes)
        self.assertTrue(defer_codes)
        self.assertLessEqual(fix_codes, set(FIX_REASONS))
        self.assertLessEqual(defer_codes, set(DEFER_REASONS))
        self.assertEqual(props['fixes']['items']['properties']['action_id']['enum'], [ELIGIBLE['1.5.1']])

    def test_the_live_mistake_is_refused_with_the_valid_fix_reasons_named(self):
        _, events = self.round_with({'fixes': [{'control_id': '1.5.1', 'action_id': ELIGIBLE['1.5.1'],
                                                'reason_code': 'no_registered_action'}]})
        rejected = [e['data']['error'] for e in events if e['kind'] == 'tool_rejected']
        self.assertTrue(rejected)
        self.assertIn('high_risk', rejected[0])

    def test_a_control_in_both_lists_is_refused(self):
        result, _ = self.round_with({'fixes': [{'control_id': '1.5.1', 'action_id': ELIGIBLE['1.5.1'],
                                                'reason_code': 'high_risk'}],
                                     'defers': [{'control_id': '1.5.1', 'reason_code': 'needs_manual_review'}]})
        self.assertIsNone(result['plan'])

    def tools_offered(self):
        """The tool schemas the orchestrator was sent at its last request (recorded by the scripted client)."""
        from backends.ubuntu.agents import ORCHESTRATOR
        return self.clients[ORCHESTRATOR].tools_seen[-1]


class UbuntuGoalDisabledTests(unittest.TestCase):
    def test_backend_refuses_a_round_goal(self):
        from tests.integration.test_ubuntu_proposals import BackendRemediationTests
        from tests.integration.test_ubuntu_live_path import open_gate
        case = BackendRemediationTests('setUp'); case.setUp()
        self.addCleanup(case.doCleanups)
        backend = case.backend(case.FIX)
        with open_gate(), self.assertRaises(ValueError):
            backend.start_round('c', None, 'Only SSH settings', 'agentic', 'op-goal')


if __name__ == '__main__':
    unittest.main()
