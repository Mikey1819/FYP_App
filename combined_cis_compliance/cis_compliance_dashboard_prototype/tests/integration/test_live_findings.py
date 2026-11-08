"""Regressions found by the first live collection on FYP-Ubuntu2204 (2026-11-06). Fixture-shaped inputs."""
from types import SimpleNamespace
import unittest


class LiveFindingTests(unittest.TestCase):
    def test_sshd_alias_without_password_is_prohibit_password(self):
        # OpenSSH's sshd -T prints the legacy alias for Ubuntu's default "PermitRootLogin prohibit-password".
        from vm.ubuntu.probes import ssh_context
        context = ssh_context('permitrootlogin without-password\n', 'global', ('permitrootlogin',))
        self.assertEqual(context['permitrootlogin'], 'prohibit-password')
        from backends.ubuntu.predicates import evaluate
        facts = {'ssh_context_resolution': {'state': 'ok', 'value': 'complete'},
                 'ssh_contexts': {'state': 'ok', 'value': [context]}}
        self.assertEqual(evaluate('5.1.20', facts).status.value, 'Non-Compliant')  # CIS requires "no"

    def test_uninstalled_service_is_not_found_not_an_error(self):
        from tests.integration.test_collection import FakeIO
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io = FakeIO(); original = io.command
        def command(key):
            if key == 'unit.auditd.service':  # what systemctl show reports for a unit that is not installed
                return SimpleNamespace(returncode=0, stdout='LoadState=not-found\nActiveState=inactive\nUnitFileState=\n')
            return original(key)
        io.command = command
        facts = collect_observations(io)
        self.assertEqual(facts['6.3.1.2']['auditd.enabled'], {'state': 'ok', 'value': 'not-found'})
        self.assertEqual(evaluate('6.3.1.2', facts['6.3.1.2']).status.value, 'Non-Compliant')

    def test_unit_query_requests_load_state(self):
        from vm.ubuntu.collector import COMMANDS
        self.assertIn('--property=LoadState,ActiveState,UnitFileState', COMMANDS['unit.auditd.service'])


UBUNTU_50_DEFAULT = ('# /usr/lib/sysctl.d/50-default.conf\n'
                     'net.ipv4.conf.default.accept_source_route = 0\n'
                     'net.ipv4.conf.*.accept_source_route = 0\n'
                     '-net.ipv4.conf.all.accept_source_route\n'
                     'net.ipv4.conf.default.rp_filter = 2\n'
                     'net.ipv4.conf.*.rp_filter = 2\n'
                     '-net.ipv4.conf.all.rp_filter\n')


class LiveSysctlFindingTests(unittest.TestCase):
    """Second live diagnostic: most keys are set in no file; Ubuntu's 50-default.conf uses globs and exclusions."""

    def test_key_set_in_no_file_is_unset_and_fails_like_the_cis_audit(self):
        from vm.ubuntu.probes import resolve_sysctl
        self.assertEqual(resolve_sysctl(UBUNTU_50_DEFAULT, 'kernel.randomize_va_space'), 'unset')
        from backends.ubuntu.predicates import evaluate
        facts = {'runtime.kernel.randomize_va_space': {'state': 'ok', 'value': 2},
                 'persistent.kernel.randomize_va_space': {'state': 'ok', 'value': 'unset'},
                 'sysctl_resolution': {'state': 'ok', 'value': 'complete'}}
        self.assertEqual(evaluate('1.5.1', facts).status.value, 'Non-Compliant')

    def test_exact_names_resolve_and_excluded_globs_do_not_apply(self):
        from vm.ubuntu.probes import resolve_sysctl
        self.assertEqual(resolve_sysctl(UBUNTU_50_DEFAULT, 'net.ipv4.conf.default.accept_source_route'), 0)
        self.assertEqual(resolve_sysctl(UBUNTU_50_DEFAULT, 'net.ipv4.conf.all.accept_source_route'), 'unset')

    def test_a_glob_with_a_different_value_is_a_conflict_not_a_guess(self):
        from vm.ubuntu.probes import resolve_sysctl
        text = 'net.ipv4.conf.default.send_redirects = 0\nnet.ipv4.conf.*.send_redirects = 1\n'
        with self.assertRaises(ValueError):resolve_sysctl(text, 'net.ipv4.conf.default.send_redirects')

    def test_remediation_family_accepts_ubuntu_defaults_and_still_refuses_conflicting_globs(self):
        from vm.ubuntu.family_sysctl import SysctlFamily
        from tests.integration.test_ubuntu_sysctl_family import FakeSystem
        params = {'keys': {'net.ipv4.conf.all.accept_source_route': 0, 'net.ipv4.conf.default.accept_source_route': 0,
                           'net.ipv6.conf.all.accept_source_route': 0, 'net.ipv6.conf.default.accept_source_route': 0}}
        ubuntu = FakeSystem(files={'/usr/lib/sysctl.d/50-default.conf': UBUNTU_50_DEFAULT.split('\n', 1)[1].encode()})
        SysctlFamily('3.3.8', ubuntu).check_eligible(params)
        later = FakeSystem(files={'/etc/sysctl.d/99-zz.conf': b'net.ipv4.conf.*.accept_source_route = 1\n'})
        with self.assertRaises(ValueError):SysctlFamily('3.3.8', later).check_eligible(params)


class LiveTrustAndInventoryFindingTests(unittest.TestCase):
    def test_root_group_writable_is_trusted_world_or_other_group_is_not(self):
        from types import SimpleNamespace as S
        from vm.ubuntu.collector import trusted_owner
        self.assertTrue(trusted_owner(S(st_uid=0, st_gid=0, st_mode=0o100664)))   # grub.cfg on the target
        self.assertTrue(trusted_owner(S(st_uid=0, st_gid=42, st_mode=0o100640)))
        self.assertFalse(trusted_owner(S(st_uid=0, st_gid=1000, st_mode=0o100664)))
        self.assertFalse(trusted_owner(S(st_uid=0, st_gid=0, st_mode=0o100666)))
        self.assertFalse(trusted_owner(S(st_uid=1000, st_gid=0, st_mode=0o100644)))

    def test_inventory_budget_fits_a_real_root_filesystem(self):
        import inspect
        from vm.ubuntu.inventory import discover_privileged
        defaults = inspect.signature(discover_privileged).parameters
        self.assertEqual(defaults['max_entries'].default, 2_000_000)
        with self.assertRaises(ValueError):discover_privileged(('/',), deadline_seconds=121)
