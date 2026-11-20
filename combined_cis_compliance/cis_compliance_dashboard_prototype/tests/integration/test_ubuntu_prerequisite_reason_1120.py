"""Not proposed this round: a control whose fix waits for another control says which one, and why (administrator,
20 November 2026: "Deferred: No registered fix applies in the current state" for 4.1.4, 4.1.7, 6.3.1.2, 6.3.3.4,
6.3.3.6 and 6.3.3.8 explained nothing). The stored round of 17 November (bd436d89) had the Orchestrator itself defer
them with no_registered_action, so the reason is read from the server's facts, whoever deferred the control.
Synthetic facts shaped like that round's evidence (UFW installed but inactive, auditd absent); not data from the VM."""
import json
from types import SimpleNamespace
import unittest

from tests.integration.ubuntu_fixtures import cases, observation

UFW_OFF = {'4.1.3': {'ufw.active': False},
           '4.1.4': {'ufw.active': False, 'ufw.ipv4.loopback_in': 'none'},
           '4.1.7': {'ufw.active': False}}
AUDITD_ABSENT = {'6.3.1.1': {'package.auditd': 'absent', 'package.audispd-plugins': 'absent'},
                 '6.3.1.2': {'auditd.enabled': 'not-found', 'auditd.active': 'inactive'}}
WAITING = ('4.1.4', '4.1.7', '6.3.1.2', '6.3.3.4', '6.3.3.6', '6.3.3.8')


def evidence(changes):
    """Evidence with the server's raw facts, as the store returns it (raw is the collector's JSON document)."""
    from backends.ubuntu.predicates import evaluate
    facts = cases()
    for cid, values in changes.items():
        for key, value in values.items():
            facts[cid][key] = value if isinstance(value, dict) and set(value) == {'state', 'value'} else observation(value)
    return SimpleNamespace(raw=json.dumps({'observations': facts}),
                           assessments=tuple(evaluate(cid, facts[cid]) for cid in sorted(facts)))


def audit_rules_missing(changes):
    for cid in ('6.3.3.4', '6.3.3.6', '6.3.3.8'):
        changes[cid] = {'loaded_audit_rules': {'state': 'missing', 'value': None}, 'persistent_audit_rules': []}
    return changes


def rows(changes, *, fixes=('4.1.3', '6.3.1.1'), by='decisions', code='no_registered_action'):
    from backends.ubuntu.adapter import _controls, _plan_rows
    ev = evidence(changes)
    failing = {a.control_id for a in ev.assessments if a.status.name == 'NON_COMPLIANT'}
    plan = {'fixes': [{'control_id': c, 'decision': 'fix', 'reason_code': 'not_deferred'} for c in fixes],
            'decisions': [], 'deferred_by_code': []}
    plan[by] = [{'control_id': c, 'reason_code': code} for c in WAITING if c in failing]
    return {r.control_id: r for r in _plan_rows({'plan': plan}, ev, _controls())}, failing


class PrerequisiteReasonTests(unittest.TestCase):
    def setUp(self):
        self.rows, self.failing = rows(audit_rules_missing({**UFW_OFF, **AUDITD_ABSENT}))

    def test_the_fixture_fails_every_control_of_the_stored_round(self):
        self.assertLessEqual(set(WAITING) | {'4.1.3', '6.3.1.1'}, self.failing)

    def test_the_ufw_rules_name_4_1_3_and_say_ufw_is_inactive(self):
        for cid, what in (('4.1.4', 'loopback rules'), ('4.1.7', 'default deny policy')):
            with self.subTest(control=cid):
                reason = self.rows[cid].reason
                self.assertTrue(reason.startswith('Requires 4.1.3 (Ensure ufw service is enabled) first: '), reason)
                self.assertIn(what, reason)
                self.assertIn('UFW is inactive on this server', reason)
                self.assertIn('4.1.3 is proposed in this round', reason)
                self.assertIn('the next round proposes this fix', reason)

    def test_the_auditd_service_names_6_3_1_1(self):
        reason = self.rows['6.3.1.2'].reason
        self.assertTrue(reason.startswith('Requires 6.3.1.1 (Ensure auditd packages are installed) first: '), reason)
        self.assertIn('auditd package is not installed on this server', reason)
        self.assertIn('6.3.1.1 is proposed in this round', reason)

    def test_the_audit_rules_name_6_3_1_1_while_auditd_is_absent(self):
        for cid in ('6.3.3.4', '6.3.3.6', '6.3.3.8'):
            with self.subTest(control=cid):
                reason = self.rows[cid].reason
                self.assertTrue(reason.startswith('Requires 6.3.1.1 (Ensure auditd packages are installed) first: '),
                                reason)
                self.assertIn('audit rules can only be loaded', reason)

    def test_the_orchestrator_deferral_keeps_its_decision_label(self):
        for cid in WAITING:
            with self.subTest(control=cid):
                self.assertEqual(self.rows[cid].decision, 'Deferred')

    def test_a_deferral_by_the_app_gets_the_same_reason(self):
        by_code, _ = rows(audit_rules_missing({**UFW_OFF, **AUDITD_ABSENT}), by='deferred_by_code')
        for cid in WAITING:
            with self.subTest(control=cid):
                self.assertEqual(by_code[cid].decision, 'Deferred (by the app)')
                self.assertEqual(by_code[cid].reason, self.rows[cid].reason)


class PrerequisiteStateTests(unittest.TestCase):
    def test_a_prerequisite_not_proposed_this_round_says_so(self):
        found, _ = rows(audit_rules_missing({**UFW_OFF, **AUDITD_ABSENT}), fixes=())
        self.assertIn('4.1.3 is not proposed in this round', found['4.1.4'].reason)
        self.assertIn('6.3.1.1 is not proposed in this round', found['6.3.3.4'].reason)

    def test_audit_rules_name_6_3_1_2_when_auditd_is_installed_but_not_running(self):
        stopped = audit_rules_missing({'6.3.1.2': {'auditd.enabled': 'disabled', 'auditd.active': 'inactive'}})
        found, failing = rows(stopped, fixes=('6.3.1.2',))
        self.assertNotIn('6.3.1.1', failing)
        reason = found['6.3.3.4'].reason
        self.assertTrue(reason.startswith('Requires 6.3.1.2 (Ensure auditd service is enabled and active) first: '),
                        reason)
        self.assertIn('auditd service is not running on this server', reason)
        self.assertIn('6.3.1.2 is proposed in this round', reason)

    def test_without_a_missing_prerequisite_the_general_reason_stays(self):
        # UFW is active, so 4.1.4 waits for something else (here: its rules could not be fully resolved).
        found, failing = rows({'4.1.4': {'ufw.ipv4.loopback_in': 'none', 'ufw_rule_resolution': 'incomplete'}},
                              fixes=())
        self.assertIn('4.1.4', failing)
        self.assertEqual(found['4.1.4'].reason, 'No registered fix applies in the current state')

    def test_other_deferral_reasons_are_kept(self):
        found, _ = rows(audit_rules_missing({**UFW_OFF, **AUDITD_ABSENT}), code='outside_goal')
        self.assertEqual(found['4.1.4'].reason, 'Outside the administrator goal')

    def test_auditd_controls_claim_no_prerequisite_when_the_package_facts_are_not_reported(self):
        from backends.ubuntu.adapter import _controls, _plan_rows
        ev = evidence(audit_rules_missing({**UFW_OFF, **AUDITD_ABSENT}))
        facts = json.loads(ev.raw)['observations']
        del facts['6.3.1.1']  # 6.3.1.2 says not-found and the loaded rules are missing, but auditd's package is unknown
        partial = SimpleNamespace(assessments=ev.assessments, raw=json.dumps({'observations': facts}))
        plan = {'fixes': [], 'decisions': [{'control_id': c, 'reason_code': 'no_registered_action'} for c in WAITING]}
        found = {r.control_id: r for r in _plan_rows({'plan': plan}, partial, _controls())}
        for cid in ('6.3.1.2', '6.3.3.4', '6.3.3.6', '6.3.3.8'):
            with self.subTest(control=cid):
                self.assertEqual(found[cid].reason, 'No registered fix applies in the current state')
        self.assertTrue(found['4.1.4'].reason.startswith('Requires 4.1.3'))

    def test_evidence_without_raw_facts_keeps_the_general_reason(self):
        from backends.ubuntu.adapter import _controls, _plan_rows
        ev = evidence(audit_rules_missing({**UFW_OFF, **AUDITD_ABSENT}))
        for bare in (SimpleNamespace(assessments=ev.assessments),
                     SimpleNamespace(assessments=ev.assessments, raw=json.dumps({'observations': {}}))):
            plan = {'fixes': [], 'decisions': [{'control_id': c, 'reason_code': 'no_registered_action'}
                                               for c in WAITING]}
            found = {r.control_id: r for r in _plan_rows({'plan': plan}, bare, _controls())}
            for cid in WAITING:
                with self.subTest(control=cid, raw=hasattr(bare, 'raw')):
                    self.assertEqual(found[cid].reason, 'No registered fix applies in the current state')


if __name__ == '__main__':
    unittest.main()
