"""Execution acceptance, target side: a harmless commit-confirm marker family and the read-only runner probe."""
import io
import json
import unittest
from tests.integration.test_ubuntu_supervision import FakeLauncher

NONCE = 'c' * 32


class FakeMarker:
    def __init__(self, content=None):
        self.content, self.writes = content, []

    def read_marker(self):
        return self.content

    def write_marker(self, content):
        self.writes.append(content)
        self.content = content


class MarkerFamilyTests(unittest.TestCase):
    def family(self, system):
        from vm.ubuntu.family_acceptance import AcceptanceMarkerFamily
        return AcceptanceMarkerFamily(system)

    def test_marker_cycle_restore_and_parameters(self):
        system = FakeMarker()
        family = self.family(system)
        params = {'scenario': 'confirm', 'nonce': NONCE}
        family.validate(params)
        before = family.read_state(params)
        expected = family.expected_after(params, before)
        family.apply(params)
        self.assertEqual(family.read_state(params), expected)
        self.assertEqual(system.content, 'confirm:' + NONCE)
        family.restore(params, before)
        self.assertEqual((family.read_state(params), system.content), (before, None))
        self.assertEqual((family.supervision, family.confirm_seconds, family.action_id),
                         ('confirm', 60, 'acceptance.marker.v1'))
        for bad in ({'scenario': 'other', 'nonce': NONCE}, {'scenario': 'confirm', 'nonce': 'x'}, {'scenario': 'confirm'},
                    {'scenario': 'rollback', 'nonce': NONCE, 'extra': 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_the_marker_lives_only_in_the_runner_state_directory(self):
        from vm.ubuntu.family_acceptance import MARKER
        self.assertEqual(MARKER, '/var/lib/fyp-hardening/acceptance/marker')

    def test_registered_in_the_target_registry(self):
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        self.assertIn('acceptance.marker.v1', build(FakeCoreSystem()))


class SchemaTests(unittest.TestCase):
    def test_acceptance_is_a_recognised_control_binding(self):
        from vm.ubuntu.remediation_schema import CONTROL_IDS
        self.assertIn('acceptance', CONTROL_IDS)
        self.assertIn('5.1.10', CONTROL_IDS)


class LauncherProbe(FakeLauncher):
    def available(self):
        return True

    def boot_rollback_state(self):
        return 'enabled'


class ProbeTests(unittest.TestCase):
    def runner(self, launcher):
        import tempfile
        from pathlib import Path
        from vm.ubuntu.runner import Runner
        from vm.ubuntu.family_acceptance import AcceptanceMarkerFamily
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        family = AcceptanceMarkerFamily(FakeMarker())
        return Runner(Path(folder.name), {family.action_id: family}, lambda: ('a' * 32, 'h'),
                      require_root_owned=False, launcher=launcher)

    def test_probe_reports_deployment_facts_only(self):
        from vm.ubuntu.provenance import collector_digest
        probe = self.runner(LauncherProbe()).probe()
        self.assertEqual(probe['collector_digest'], collector_digest())
        self.assertEqual(probe['families']['acceptance.marker.v1'][0], 1)
        self.assertIn('recovery.restore.v1', probe['families'])
        self.assertEqual((probe['launcher'], probe['boot_rollback']), (True, 'enabled'))
        self.assertEqual(self.runner(None).probe()['launcher'], False)

    def test_cli_probe_takes_no_payload(self):
        from vm.ubuntu.runner_cli import main
        runner = self.runner(LauncherProbe())
        out, err = io.BytesIO(), io.BytesIO()
        self.assertEqual(main(io.BytesIO(b'{"op":"probe"}\n'), out, err, runner_factory=lambda: runner), 0)
        self.assertEqual(json.loads(out.getvalue())['boot_rollback'], 'enabled')
        self.assertEqual(main(io.BytesIO(b'{"op":"probe"}\nextra'), io.BytesIO(), io.BytesIO(),
                              runner_factory=lambda: runner), 2)
