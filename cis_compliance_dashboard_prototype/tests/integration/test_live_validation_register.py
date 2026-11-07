"""The live-validation register is derived from stored records, never typed in (task 17: "mark any family lacking
live evidence as unvalidated"). A control counts as validated live only when an approved fix was applied and the
verification scan read it Compliant; a restore counts only when it was applied and the verification read the
before-state again. Synthetic records shaped like the 2026-11-07 live ones; no store or VM is opened."""
import unittest


def decision(request, control, action):
    return {'request_id': request, 'control_id': control, 'action_id': action}


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

    def test_an_applied_fix_verified_compliant_is_validated_live(self):
        row = self.rows()['3.3.2']
        self.assertEqual(row['status'], 'Validated live')
        self.assertEqual(row['fix'], 'applied 2026-11-07T05:08:58+00:00 (request f236), verification: Compliant')
        self.assertEqual(row['restore'], 'applied 2026-11-07T05:12:20+00:00 (request 9767), verification: Non-Compliant')

    def test_an_attempt_that_rolled_back_is_recorded_but_not_validated(self):
        row = self.rows()['5.1.20']
        self.assertEqual(row['status'], 'Attempted, not applied')
        self.assertIn('rolled_back (nothing_to_restore)', row['fix'])

    def test_a_control_without_records_is_unvalidated(self):
        self.assertEqual((self.rows()['1.5.1']['status'], self.rows()['1.5.1']['fix']), ('Not run live', ''))

    def test_applied_without_a_compliant_verification_is_not_validated(self):
        row = self.rows(verifications={})['3.3.2']
        self.assertEqual(row['status'], 'Applied, not verified Compliant')

    def test_a_later_fix_after_a_restore_is_the_one_reported(self):
        records = dict(decisions=LIVE['decisions'] + [decision('d4d4', '3.3.2', 'ubuntu.3.3.2.v1')],
                       receipts=LIVE['receipts'] + [receipt('d4d4', 'applied', at='2026-11-07T06:38:07+00:00')],
                       verifications={**LIVE['verifications'], 'd4d4': 'Compliant'})
        row = self.rows(**records)['3.3.2']
        self.assertEqual((row['status'], row['attempts']), ('Validated live', 2))
        self.assertIn('request d4d4', row['fix'])

    def test_maintenance_operations_never_count_as_a_control(self):
        from tools.live_validation_register import register
        self.assertNotIn('maintenance', [r['control_id'] for r in register(CONTROLS, **LIVE)])


if __name__ == '__main__':
    unittest.main()
