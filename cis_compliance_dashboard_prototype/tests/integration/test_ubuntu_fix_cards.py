"""Fixes tab as one expandable card per Non-Compliant control (administrator request, 2026-11-07). Live 05:08-05:12:
3.3.2 was applied and the fresh scan read Compliant, but nothing on the Fixes tab said so; each card now shows the
latest outcome of its fix, including a restore. Synthetic snapshots; no VM is contacted."""
import unittest
from system.contracts import ComplianceStatus, PlanRow, ProposalRow, RecordRef, ResultRow, WorkspaceSnapshot

TARGET = 'ubuntu:fixture'


def ref(record):
    return RecordRef('ubuntu', TARGET, record)


def proposal(record, control, *, kind='control_remediation', decision=None, commands=('approve', 'reject')):
    return ProposalRow(ref(record), kind, control, 'ubuntu.%s.v1' % control, 'Fix ' + control, 'v1',
                       'Settings:\n  - key = 0', (), 'restore_backup: /etc/x', (), decision, None, 'plan', commands)


def result(record, state, status=None, detail='detail'):
    return ResultRow(ref(record), state, status, ref('r-' + record), None, 'not_requested', detail)


def snapshot(proposals=(), results=(), plan=None):
    rows = plan or (PlanRow('3.3.2', 'Ensure packet redirect sending is disabled', 'Fix proposed',
                            'Confirmed CIS failure with a registered fix', ''),
                    PlanRow('6.3.1.2', 'Ensure auditd service is enabled and active', 'Deferred (by the app)',
                            'No registered fix applies in the current state', ''))
    return _snap(proposals, results, rows)


def _snap(proposals, results, rows):
    from system.contracts import TargetSummary
    target = TargetSummary(ref('target'), 'host', 'Ubuntu 22.04', 'SSH', 'Live (SSH)', 'connected')
    return WorkspaceSnapshot(target, proposals=tuple(proposals), results=tuple(results), plan=tuple(rows))


class FixCardTests(unittest.TestCase):
    def cards(self, *args, **kwargs):
        from system.ui.components import plan_cards
        return {c['control_id']: c for c in plan_cards(snapshot(*args, **kwargs))}

    def test_one_card_per_non_compliant_control_in_plan_order(self):
        from system.ui.components import plan_cards
        self.assertEqual([c['control_id'] for c in plan_cards(snapshot())], ['3.3.2', '6.3.1.2'])

    def test_states_follow_the_life_of_a_fix(self):
        cases = [
            ((), (), 'No fix plan: the read-only preview failed'),  # plan row without a stored proposal
            ((proposal('p', '3.3.2'),), (), 'Awaiting your decision'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),), (), 'Approved, ready to execute'),
            ((proposal('p', '3.3.2', decision='rejected', commands=()),), (), 'Rejected'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),), (result('p', 'running'),), 'Running'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),), (result('p', 'applied'),),
             'Applied, re-scan pending'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),),
             (result('p', 'applied', ComplianceStatus.COMPLIANT),), 'Fixed, re-scan: Compliant'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),),
             (result('p', 'applied', ComplianceStatus.NON_COMPLIANT),), 'Applied, re-scan: Non-Compliant'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),), (result('p', 'rolled_back'),), 'Not applied'),
            ((proposal('p', '3.3.2', decision='approved', commands=()),), (result('p', 'unresolved'),), 'Outcome unknown'),
        ]
        for proposals, results, state in cases:
            with self.subTest(state=state):
                self.assertEqual(self.cards(proposals, results)['3.3.2']['state'], state)

    def test_an_applied_restore_says_the_fix_was_undone(self):
        fix = proposal('p', '3.3.2', decision='approved', commands=())
        undo = proposal('u', '3.3.2', kind='recovery', decision='approved', commands=())
        card = self.cards((fix, undo), (result('p', 'applied', ComplianceStatus.NON_COMPLIANT), result('u', 'applied')))['3.3.2']
        self.assertEqual(card['state'], 'Restored to the before-state')
        self.assertEqual([p.reference.record_id for p in card['proposals']], ['p', 'u'])

    def test_deferred_cards_keep_the_planner_reason(self):
        card = self.cards()['6.3.1.2']
        self.assertEqual(card['state'], 'Deferred (by the app)')
        self.assertEqual(card['reason'], 'No registered fix applies in the current state')
        self.assertEqual(card['proposals'], [])

    def test_summary_counts_proposed_approved_and_fixed(self):
        from system.ui.components import plan_summary
        fix = proposal('p', '3.3.2', decision='approved', commands=())
        text = plan_summary(snapshot((fix,), (result('p', 'applied', ComplianceStatus.COMPLIANT),)))
        self.assertEqual(text, '2 Non-Compliant controls · 1 fix proposed · 1 approved · 1 fixed (re-scan Compliant)')


if __name__ == '__main__':
    unittest.main()
