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
