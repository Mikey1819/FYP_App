"""The live-validation register is derived from stored records, never typed in (task 17: "mark any family lacking
live evidence as unvalidated"). A control counts as validated live only when an approved fix was applied and the
verification scan read it Compliant (a restore, no longer offered since 12 November, never changes that). A control
this program has no fix for is "Manual on the server", in the same words on both systems (14 November 2026).
Module 3 (12 November 2026): the same register is shown on the Ubuntu page and in the round report, with the evidence
of each row (time, approver, request, round). Synthetic records shaped like the 2026-11-07 live ones; no store or VM
is opened."""
import unittest


def decision(request, control, action, approver='Kai', round_id='round-1', workflow='wf-1'):
    return {'request_id': request, 'control_id': control, 'action_id': action, 'approver': approver,
            'round_id': round_id, 'workflow': workflow}


def receipt(request, outcome, code='expected_after_state', at='2026-11-07T05:08:58+00:00'):
    return {'request_id': request, 'outcome': outcome, 'code': code, 'completed_at': at}


CONTROLS = ['3.3.2', '5.1.20', '1.5.1']
LIVE = dict(
    decisions=[decision('f236', '3.3.2', 'ubuntu.3.3.2.v1'), decision('9767', '3.3.2', 'recovery.restore.v1'),
               decision('2e2e', '5.1.20', 'ubuntu.5.1.20.v1'), decision('cadb', 'maintenance', 'maintenance.apt_refresh.v1')],
    receipts=[receipt('f236', 'applied'), receipt('9767', 'applied', at='2026-11-07T05:12:20+00:00'),
              receipt('2e2e', 'running', 'job_started'), receipt('2e2e', 'rolled_back', 'nothing_to_restore'),
              receipt('cadb', 'applied')],
    verifications={'f236': 'Compliant', '9767': 'Non-Compliant'})


class RegisterTests(unittest.TestCase):
    def rows(self, **records):
        from tools.live_validation_register import register
        return {r['control_id']: r for r in register(CONTROLS, **{**LIVE, **records})}

    def test_a_restore_from_before_12_november_never_changes_the_status(self):
        # No restore on either system since 12 November 2026 (administrator, 14 November: no "restored" status). The
        # command-line tool still lists the old restore beside the fix.
        row = self.rows()['3.3.2']
        self.assertEqual(row['status'], 'Validated live')
        self.assertEqual(row['fix'], 'applied 2026-11-07T05:08:58+00:00 (request f236), verification: Compliant')
        self.assertEqual(row['restore'], 'applied 2026-11-07T05:12:20+00:00 (request 9767), verification: Non-Compliant')
        self.assertEqual(row['evidence'], {'time': '2026-11-07T05:08:58+00:00', 'approver': 'Kai', 'request_id': 'f236',
                                           'round_id': 'round-1', 'workflow': 'wf-1'})

    def test_a_validated_fix_without_a_restore_is_validated_live(self):
        records = dict(decisions=[d for d in LIVE['decisions'] if d['request_id'] != '9767'])
        self.assertEqual(self.rows(**records)['3.3.2']['status'], 'Validated live')

    def test_an_attempt_that_rolled_back_is_refused_and_not_validated(self):
        row = self.rows()['5.1.20']
        self.assertEqual(row['status'], 'Refused')
        self.assertIn('rolled_back (nothing_to_restore)', row['fix'])
        self.assertEqual(row['evidence']['request_id'], '2e2e')

    def test_a_control_without_records_is_fixture_tested_only(self):
        row = self.rows()['1.5.1']
        self.assertEqual((row['status'], row['fix'], row['evidence']), ('Fixture-tested only', '', None))

    def test_approved_but_never_executed_is_still_fixture_tested_only(self):
        records = dict(decisions=LIVE['decisions'] + [decision('aa11', '1.5.1', 'ubuntu.1.5.1.v1')])
        self.assertEqual(self.rows(**records)['1.5.1']['status'], 'Fixture-tested only')

    def test_applied_without_a_compliant_verification_is_applied_not_verified(self):
        self.assertEqual(self.rows(verifications={})['3.3.2']['status'], 'Applied, not verified')

    def test_a_later_fix_after_a_restore_is_the_one_reported(self):
        records = dict(decisions=LIVE['decisions'] + [decision('d4d4', '3.3.2', 'ubuntu.3.3.2.v1', round_id='round-2')],
                       receipts=LIVE['receipts'] + [receipt('d4d4', 'applied', at='2026-11-07T06:38:07+00:00')],
                       verifications={**LIVE['verifications'], 'd4d4': 'Compliant'})
        row = self.rows(**records)['3.3.2']
        self.assertEqual((row['status'], row['attempts']), ('Validated live', 2))
        self.assertEqual((row['evidence']['request_id'], row['evidence']['round_id']), ('d4d4', 'round-2'))

    def test_a_later_failed_attempt_never_hides_the_earlier_proof(self):
        records = dict(decisions=[d for d in LIVE['decisions'] if d['request_id'] != '9767']
                       + [decision('e5e5', '3.3.2', 'ubuntu.3.3.2.v1')],
                       receipts=LIVE['receipts'] + [receipt('e5e5', 'refused', 'stale_read_set', at='2026-11-08T01:00:00+00:00')])
        row = self.rows(**records)['3.3.2']
        self.assertEqual((row['status'], row['evidence']['request_id'], row['attempts']), ('Validated live', 'f236', 2))

    def test_maintenance_operations_never_count_as_a_control(self):
        from tools.live_validation_register import register
        self.assertNotIn('maintenance', [r['control_id'] for r in register(CONTROLS, **LIVE)])

    def test_the_summary_counts_the_validated_controls(self):
        from tools.live_validation_register import register, summary
        self.assertEqual(summary(register(CONTROLS, **LIVE)), '1 of 3 validated live')

    def test_a_control_without_a_program_fix_is_manual_on_the_server(self):
        # Administrator, 14 November 2026: the same words on both systems. Only a control this program never changes
        # (Windows 9.2.1, 9.2.2, 9.3.1, 9.3.2) reads so; one with a fix that never ran stays fixture-tested only.
        rows = {r['control_id']: r for r in self.register_with(automated={'3.3.2', '5.1.20'})}
        self.assertEqual((rows['1.5.1']['status'], rows['1.5.1']['evidence']), ('Manual on the server', None))
        self.assertEqual(rows['3.3.2']['status'], 'Validated live')
        without = {r['control_id']: r for r in self.register_with(automated=None)}
        self.assertEqual(without['1.5.1']['status'], 'Fixture-tested only')

    def register_with(self, automated):
        from tools.live_validation_register import register
        return register(CONTROLS, **LIVE, automated=automated)

    def test_no_status_says_restored_any_more(self):
        from tools.live_validation_register import STATUSES
        self.assertFalse([s for s in STATUSES if 'restored' in s.lower()])


class ReportSectionTests(unittest.TestCase):
    def test_the_round_report_carries_the_register_with_its_evidence(self):
        from types import SimpleNamespace as N
        from system.ui.round_report import ubuntu_round_report
        from tools.live_validation_register import register
        snapshot = N(summary=None, current_round_reference=None, plan=(), findings=(), controls=(), proposals=(),
                     results=(), events=(), target=N(hostname='UBUNTU-FIXTURE'))
        html = ubuntu_round_report(snapshot, (), None, None, register=register(CONTROLS, **LIVE))
        self.assertIn('7. Live validation register', html)
        self.assertIn('1 of 3 validated live', html)
        self.assertNotIn('restored', html)
        self.assertIn('f236', html)
        self.assertIn('Fixture-tested only', html)
        without = ubuntu_round_report(snapshot, (), None, None)
        self.assertNotIn('Live validation register', without)


if __name__ == '__main__':
    unittest.main()
