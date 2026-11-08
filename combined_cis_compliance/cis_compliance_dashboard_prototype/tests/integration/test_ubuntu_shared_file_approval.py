"""Fixes that restore a common file cannot be approved together (administrator request 2026-11-08). Live 13:44: 1.5.1,
1.5.3, 3.3.1 and 3.3.8 were approved and executed together; after 1.5.1 changed the shared sysctl file the others were
refused stale. While one fix of such a group is approved and not executed, the others cannot be approved: the page
disables Approve and says why, and the backend refuses it. Synthetic proposals; no VM."""
import unittest
from types import SimpleNamespace as N

SYSCTL = '/etc/sysctl.d/60-fyp-hardening-cis.conf'


def proposal(pid, control, scope, *, decision=None, receipts=(), action=None):
    return N(proposal_id=pid, decision=decision, receipts=receipts,
             payload={'proposal_id': pid, 'action': {'action_id': action or 'ubuntu.%s.v1' % control},
                      'fields': {'control_id': control, 'recovery': {'kind': 'restore_backup', 'scope': scope}}})


ASLR = proposal('p151', '1.5.1', [SYSCTL, 'runtime:kernel.randomize_va_space'], decision='approved')
CORE = proposal('p153', '1.5.3', ['/etc/security/limits.d/60-fyp-hardening-cis.conf', SYSCTL, 'runtime:fs.suid_dumpable'])
SUDO = proposal('p523', '5.2.3', ['/etc/sudoers.d/60-fyp-hardening-cis'])


class SharedFileApprovalTests(unittest.TestCase):
    def conflict(self, candidate, proposals):
        from backends.ubuntu.adapter import shared_file_conflict
        return shared_file_conflict(candidate.payload, proposals)

    def test_a_fix_sharing_a_file_with_an_approved_unexecuted_fix_is_blocked(self):
        self.assertEqual(self.conflict(CORE, [ASLR, CORE, SUDO]), '1.5.1')

    def test_an_independent_fix_is_not_blocked(self):
        self.assertIsNone(self.conflict(SUDO, [ASLR, CORE, SUDO]))

    def test_once_the_approved_fix_has_run_the_group_is_free_again_in_a_new_round(self):
        ran = proposal('p151', '1.5.1', ASLR.payload['fields']['recovery']['scope'], decision='approved',
                       receipts=({'outcome': 'applied', 'code': 'expected_after_state'},))
        self.assertIsNone(self.conflict(CORE, [ran, CORE]))

    def test_runtime_keys_alone_never_conflict_and_restores_are_not_counted(self):
        restore = proposal('r1', '1.5.1', [SYSCTL], decision='approved', action='recovery.restore.v1')
        self.assertIsNone(self.conflict(CORE, [restore, CORE]))
        other = proposal('x', '3.3.1', ['runtime:fs.suid_dumpable'], decision='approved')
        self.assertIsNone(self.conflict(proposal('y', '1.5.4', ['runtime:fs.suid_dumpable']), [other]))

    def test_the_message_names_both_controls_and_what_to_do(self):
        from backends.ubuntu.adapter import shared_file_message
        text = shared_file_message('1.5.3', '1.5.1')
        for part in ('1.5.3', '1.5.1', 'same file', 'execute', 'new round'):
            self.assertIn(part, text)


if __name__ == '__main__':
    unittest.main()
