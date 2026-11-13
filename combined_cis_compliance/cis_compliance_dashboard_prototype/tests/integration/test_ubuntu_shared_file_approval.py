"""Fixes that share a file. Live 2026-11-07 13:44: 1.5.1, 1.5.3, 3.3.1 and 3.3.8 were approved and executed together;
after 1.5.1 changed the shared sysctl file the others were refused stale, so such fixes could not be approved together
(administrator request 2026-11-08). Since 2026-11-11 (administrator request) every fix on the sysctl, sshd, sudoers,
login.defs and shadow files checks and restores only its own keys, lines or account fields, so those no longer block
each other and can be approved and executed together. UFW fixes still block each other: enabling the firewall
depends on the allow rules. Synthetic proposals; no VM."""
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
UFW_FILES = ['/etc/default/ufw', '/etc/ufw/user.rules', '/etc/ufw/user6.rules']
UFW_LOOPBACK = proposal('p414', '4.1.4', UFW_FILES, decision='approved')
UFW_ENABLE = proposal('p413', '4.1.3', UFW_FILES)


class SharedFileApprovalTests(unittest.TestCase):
    def conflict(self, candidate, proposals):
        from backends.ubuntu.adapter import shared_file_conflict
        return shared_file_conflict(candidate.payload, proposals)

    def test_ufw_fixes_sharing_a_file_still_block_each_other(self):
        self.assertEqual(self.conflict(UFW_ENABLE, [UFW_LOOPBACK, UFW_ENABLE, SUDO]), '4.1.4')

    def test_fixes_scoped_to_their_own_part_of_a_shared_file_are_not_blocked(self):
        self.assertIsNone(self.conflict(CORE, [ASLR, CORE, SUDO]))  # sysctl drop-in: own keys only
        sshd = '/etc/ssh/sshd_config.d/00-fyp-hardening-cis.conf'
        self.assertIsNone(self.conflict(proposal('a', '5.1.16', [sshd]),
                                        [proposal('b', '5.1.20', [sshd], decision='approved')]))
        self.assertIsNone(self.conflict(proposal('c', '5.2.2', SUDO.payload['fields']['recovery']['scope']),
                                        [proposal('d', '5.2.3', SUDO.payload['fields']['recovery']['scope'],
                                                  decision='approved')]))
        self.assertIsNone(self.conflict(proposal('e', '5.4.1.3', ['/etc/login.defs', '/etc/shadow']),
                                        [proposal('f', '5.4.1.1', ['/etc/login.defs', '/etc/shadow'],
                                                  decision='approved')]))
        self.assertIsNone(self.conflict(proposal('g', '5.4.1.5', ['/etc/default/useradd', '/etc/shadow']),
                                        [proposal('h', '5.4.1.1', ['/etc/login.defs', '/etc/shadow'],
                                                  decision='approved')]))

    def test_the_registered_ufw_fixes_are_the_only_shared_file_group_left(self):
        from backends.ubuntu.actions import FAMILIES
        from backends.ubuntu.adapter import _files, shared_file_conflict
        plans = [proposal(aid, spec.control_ids[0], (spec.recovery or {}).get('scope', []), decision='approved')
                 for aid, spec in FAMILIES.items()]
        blocked = {p.payload['fields']['control_id'] for p in plans if shared_file_conflict(p.payload, plans)}
        self.assertEqual(blocked, {'4.1.3', '4.1.4', '4.1.7'})

    def test_an_independent_fix_is_not_blocked(self):
        self.assertIsNone(self.conflict(SUDO, [ASLR, CORE, SUDO]))

    def test_once_the_approved_fix_has_run_the_group_is_free_again_in_a_new_round(self):
        ran = proposal('p414', '4.1.4', UFW_FILES, decision='approved',
                       receipts=({'outcome': 'applied', 'code': 'expected_after_state'},))
        self.assertIsNone(self.conflict(UFW_ENABLE, [ran, UFW_ENABLE]))

    def test_runtime_keys_alone_never_conflict_and_restores_are_not_counted(self):
        restore = proposal('r1', '4.1.4', UFW_FILES, decision='approved', action='recovery.restore.v1')
        self.assertIsNone(self.conflict(UFW_ENABLE, [restore, UFW_ENABLE]))
        other = proposal('x', '3.3.1', ['runtime:fs.suid_dumpable'], decision='approved')
        self.assertIsNone(self.conflict(proposal('y', '1.5.4', ['runtime:fs.suid_dumpable']), [other]))

    def test_the_message_names_both_controls_and_what_to_do(self):
        from backends.ubuntu.adapter import shared_file_message
        text = shared_file_message('1.5.3', '1.5.1')
        for part in ('1.5.3', '1.5.1', 'same file', 'execute', 'new round'):
            self.assertIn(part, text)


if __name__ == '__main__':
    unittest.main()
