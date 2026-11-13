"""Planned fixes the VM will not preview. Live 2026-11-07 05:08, 06:36 and 07:19: 1.2.2.1, 2.1.2, 6.3.3.4, 6.3.3.6 and
6.3.3.8 were in every plan but never got a stored fix plan, because the read-only VM preview was refused and the card
just said "Fix proposed" with nothing to approve. The audit-rule fixes need auditd (6.3.1.1) first: the scan records
loaded_audit_rules as missing, so the host now sees that, as it already did for 6.3.1.2. No VM is contacted."""
import json
import unittest

from tests.integration.test_ubuntu_fix_cards import proposal, snapshot

AUDIT_RULES = {'6.3.3.4': {'ruleset': 'time-change'}, '6.3.3.8': {'ruleset': 'identity'},
               '6.3.3.6': {'paths': ['/usr/bin/passwd'], 'uid_min': 1000}}


def audit_evidence(loaded):
    from tests.integration.test_ubuntu_risk import evidence
    from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
    ev, obs = evidence(list(AUDIT_RULES)), cases()
    for cid in AUDIT_RULES:
        key, value = FAILURES[cid]
        obs[cid][key] = observation(value)
        if loaded is not None:
            obs[cid]['loaded_audit_rules'] = loaded
    ev.raw = json.dumps({'observations': obs}).encode()
    return ev


class AuditPrerequisiteTests(unittest.TestCase):
    def test_audit_rule_fixes_wait_while_auditd_is_not_installed(self):
        from backends.ubuntu.actions import FAMILIES
        ev = audit_evidence({'state': 'missing', 'value': None})  # the live 07:18 scan: auditctl absent
        for cid in AUDIT_RULES:
            with self.subTest(control=cid):
                self.assertIsNone(FAMILIES['ubuntu.%s.v1' % cid].propose(cid, ev))

    def test_audit_rule_fixes_are_offered_once_auditd_reports_its_loaded_rules(self):
        from backends.ubuntu.actions import FAMILIES
        ev = audit_evidence(None)  # the fixture's loaded rules, state ok
        for cid, params in AUDIT_RULES.items():
            with self.subTest(control=cid):
                self.assertEqual(FAMILIES['ubuntu.%s.v1' % cid].propose(cid, ev), params)


class AuditdOrderTextTests(unittest.TestCase):
    """Task 4 (administrator's choice, 12 November): the controls that need auditd say they are planned after 6.3.1.1
    installs it, instead of the generic "No registered fix applies"; the next round plans them (the Orchestrator's
    review already recommends it: next_round / unblocked_findings)."""
    NEEDS_AUDITD = ('6.3.1.2', '6.3.3.4', '6.3.3.6', '6.3.3.8')

    def rows(self, failing):
        from backends.ubuntu.adapter import _controls, _plan_rows
        from tests.integration.test_ubuntu_risk import evidence
        plan = {'fixes': [{'control_id': '6.3.1.1', 'decision': 'fix', 'reason_code': 'highest_risk'}]
                if '6.3.1.1' in failing else [], 'decisions': [],
                'deferred_by_code': [{'control_id': c, 'reason_code': 'no_registered_action'}
                                     for c in failing if c != '6.3.1.1']}
        return {r.control_id: r for r in _plan_rows({'plan': plan}, evidence(list(failing)), _controls())}

    def test_while_auditd_is_missing_they_say_they_follow_6_3_1_1(self):
        rows = self.rows(('6.3.1.1',) + self.NEEDS_AUDITD)
        for cid in self.NEEDS_AUDITD:
            with self.subTest(control=cid):
                self.assertEqual(rows[cid].decision, 'Deferred (by the app)')
                self.assertIn('Planned after 6.3.1.1 installs auditd', rows[cid].reason)
                self.assertIn('next round', rows[cid].reason)
        self.assertEqual(rows['6.3.1.1'].decision, 'Fix proposed')

    def test_with_auditd_installed_the_usual_reason_stays(self):
        rows = self.rows(self.NEEDS_AUDITD)  # 6.3.1.1 is compliant: auditd is there, so something else blocks them
        for cid in self.NEEDS_AUDITD:
            with self.subTest(control=cid):
                self.assertEqual(rows[cid].reason, 'No registered fix applies in the current state')


class MissingFixPlanCardTests(unittest.TestCase):
    def test_a_planned_fix_without_a_stored_plan_says_the_preview_failed(self):
        from system.ui.components import plan_cards
        card = {c['control_id']: c for c in plan_cards(snapshot())}['3.3.2']
        self.assertEqual(card['state'], 'No fix plan: the read-only preview failed')
        self.assertIn('nothing to approve', card['note'])
        self.assertEqual(card['icon'], ':material/report:')

    def test_the_summary_counts_planned_fixes_without_a_fix_plan(self):
        from system.ui.components import plan_summary
        self.assertEqual(plan_summary(snapshot()),
                         '2 Non-Compliant controls · 1 fix proposed · 0 approved · 0 fixed (re-scan Compliant)'
                         ' · 1 without a fix plan')

    def test_a_planned_fix_with_its_plan_has_no_note(self):
        from system.ui.components import plan_cards
        card = {c['control_id']: c for c in plan_cards(snapshot((proposal('p', '3.3.2'),)))}['3.3.2']
        self.assertEqual((card['state'], card['note']), ('Awaiting your decision', ''))


if __name__ == '__main__':
    unittest.main()
