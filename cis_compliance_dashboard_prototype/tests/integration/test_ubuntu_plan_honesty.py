"""Live 2026-11-07: qwen3:8b deferred 20 controls as "no_registered_action" although every one had a registered,
offered action, and the plan was accepted. A deferral reason must be true, and the orchestrator is told which
failures have actions. Proposal previews are shown as readable lines. Scripted models; no VM is contacted."""
import unittest

ELIGIBLE = {'1.5.1': 'fixture.file_value.v1'}


class PlanHonestyTests(unittest.TestCase):
    def setUp(self):
        from tests.integration.test_ubuntu_agents import AgentRoundTests
        self.case = AgentRoundTests('test_complete_round_delegates_in_order_and_defers_every_finding')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def round_with(self, *plans):
        from backends.ubuntu.agents import run_agentic_round
        from backends.ubuntu.adapter import _controls
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, analysis_ok
        script = [call('delegate_scanner'), call('delegate_analysis')] + [plan_call(d) for d in plans]
        clients = team(script, scanner_ok(), analysis_ok())
        result = run_agentic_round(client_factory=clients.__getitem__, collect=self.case.collect_with(),
                                   log_store=self.case.log, target_id='ubuntu:fixture',
                                   titles={c: x.title for c, x in _controls().items()},
                                   rank=lambda r, e: None, eligible=ELIGIBLE)
        return result, self.case.events(result['orchestrator_run_id'])

    def test_no_registered_action_is_refused_for_a_control_that_has_one(self):
        other = {'control_id': '5.1.20', 'decision': 'defer', 'reason_code': 'no_registered_action'}
        false = [{'control_id': '1.5.1', 'decision': 'defer', 'reason_code': 'no_registered_action'}, other]
        manual = [{'control_id': '1.5.1', 'decision': 'defer', 'reason_code': 'needs_manual_review'}, other]
        result, events = self.round_with(false, manual)
        rejected = [e['data'] for e in events if e['kind'] == 'tool_rejected']
        self.assertEqual(len(rejected), 1)
        self.assertIn('1.5.1', rejected[0]['error'])
        self.assertEqual(result['plan']['decisions'], manual)

    def test_no_registered_action_stays_valid_for_a_control_without_one(self):
        true = [{'control_id': '5.1.20', 'decision': 'defer', 'reason_code': 'no_registered_action'}]
        fix = [{'control_id': '1.5.1', 'decision': 'fix', 'action_id': ELIGIBLE['1.5.1'], 'reason_code': 'highest_risk'}]
        result, _ = self.round_with(fix + true)
        self.assertEqual(result['plan']['decisions'], true)

    def test_the_orchestrator_is_told_which_failures_have_a_registered_action(self):
        _, events = self.round_with([])
        analysis = [e['data'] for e in events if e['kind'] == 'tool' and e['data']['name'] == 'delegate_analysis'][0]
        self.assertEqual(analysis['result']['registered_actions'], ELIGIBLE)


class PreviewTextTests(unittest.TestCase):
    def test_preview_is_readable_lines_with_every_value(self):
        from backends.ubuntu.adapter import preview_text
        text = preview_text({'commands': ['ufw allow in on lo', 'ufw deny in from ::1'], 'confirm_window_seconds': 600,
                             'current_effective': {'permitrootlogin': 'without-password'}, 'order': 'appended'})
        self.assertNotIn('{"', text)
        self.assertEqual(text.splitlines(), [
            'Commands:', '  - ufw allow in on lo', '  - ufw deny in from ::1',
            'Confirm window seconds: 600',
            'Current effective:', '  - permitrootlogin = without-password',
            'Order: appended'])

    def test_proposal_rows_use_the_readable_preview(self):
        from tests.integration.test_ubuntu_proposals import BackendRemediationTests
        from backends.ubuntu.adapter import preview_text
        case = BackendRemediationTests('setUp'); case.setUp()
        try:
            backend = case.backend(case.FIX)
            handle, snap = case.round(backend)
            row = snap.proposals[0]
            stored = backend._store().proposals(handle.binding, snap.current_round_reference.record_id)[0]
            self.assertEqual(row.exact_preview, preview_text(stored.payload['preview']))
            self.assertNotIn('{"', row.exact_preview)
        finally:
            case.doCleanups()


class PlanTableTests(unittest.TestCase):
    """The Fixes tab accounts for every Non-Compliant control: the planner's decision, its reason and any flag."""

    def snapshot(self, decisions):
        from tests.integration.test_ubuntu_proposals import BackendRemediationTests
        case = BackendRemediationTests('setUp'); case.setUp()
        self.addCleanup(case.doCleanups)
        return case.round(case.backend(decisions))[1]

    def test_every_non_compliant_control_has_a_plan_row(self):
        from tests.integration.test_ubuntu_proposals import BackendRemediationTests
        snap = self.snapshot(BackendRemediationTests.FIX)
        failing = sorted(c.control_id for c in snap.controls if c.status.value == 'Non-Compliant')
        self.assertEqual(sorted(r.control_id for r in snap.plan), failing)
        row = next(r for r in snap.plan if r.control_id == '1.5.1')
        self.assertEqual((row.decision, row.reason), ('Fix proposed', 'Among the highest deterministic risk'))
        self.assertTrue(row.title)

    def test_a_deferral_shows_its_reason_in_words(self):
        snap = self.snapshot([{'control_id': '1.5.1', 'decision': 'defer', 'reason_code': 'needs_manual_review'}])
        row = next(r for r in snap.plan if r.control_id == '1.5.1')
        self.assertEqual((row.decision, row.reason), ('Deferred', 'Needs human review before any change'))

    def test_an_empty_plan_proposes_every_registered_fix_it_did_not_defer(self):
        snap = self.snapshot([])  # since 2026-11-07 06:57 the orchestrator decides by deferring
        row = next(r for r in snap.plan if r.control_id == '1.5.1')
        self.assertEqual((row.decision, row.reason),
                         ('Fix proposed', 'Confirmed CIS failure with a registered fix; the planner did not defer it'))

    def test_a_round_without_a_valid_plan_still_lists_every_failure(self):
        from backends.ubuntu.adapter import _plan_rows, _controls
        from types import SimpleNamespace as N
        from system.contracts import ComplianceStatus
        evidence = N(assessments=[N(control_id='1.5.1', status=ComplianceStatus.NON_COMPLIANT)])
        self.assertEqual(_plan_rows({'plan': None}, evidence, _controls())[0].decision, 'No plan')

    def test_rounds_stored_with_the_old_risk_reason_still_read_in_words(self):
        from backends.ubuntu.adapter import _plan_rows, _controls
        from types import SimpleNamespace as N
        from system.contracts import ComplianceStatus
        evidence = N(assessments=[N(control_id='5.1.20', status=ComplianceStatus.NON_COMPLIANT)])
        details = {'plan': {'fixes': [{'control_id': '5.1.20', 'decision': 'fix', 'action_id': 'ubuntu.5.1.20.v1',
                                       'reason_code': 'high_risk'}], 'decisions': [], 'deferred_by_code': []}}
        self.assertEqual(_plan_rows(details, evidence, _controls())[0].reason, 'High-priority confirmed failure')

    def test_a_deferral_recorded_by_code_says_so(self):
        from backends.ubuntu.adapter import _plan_rows, _controls
        from types import SimpleNamespace as N
        from system.contracts import ComplianceStatus
        evidence = N(assessments=[N(control_id='6.3.1.2', status=ComplianceStatus.NON_COMPLIANT)])
        details = {'plan': {'fixes': [], 'decisions': [],
                            'deferred_by_code': [{'control_id': '6.3.1.2', 'reason_code': 'no_registered_action'}]}}
        row = _plan_rows(details, evidence, _controls())[0]
        self.assertEqual(row.decision, 'Deferred (by the app)')
        self.assertEqual(row.reason, 'No registered fix applies in the current state')

    def test_the_fixes_tab_has_one_card_per_plan_row_with_its_proposal(self):
        from tests.integration.test_ubuntu_proposals import BackendRemediationTests
        from system.ui.components import plan_cards
        snap = self.snapshot(BackendRemediationTests.FIX)
        cards = plan_cards(snap)
        self.assertEqual([c['control_id'] for c in cards], [r.control_id for r in snap.plan])
        card = next(c for c in cards if c['control_id'] == '1.5.1')
        self.assertEqual([p.reference for p in card['proposals']], [snap.proposals[0].reference])


if __name__ == '__main__':
    unittest.main()
