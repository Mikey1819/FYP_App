"""Core-dump family (CIS 1.5.3, printed pp.159-161) against an IN-MEMORY fake system. No VM, no real files."""
from datetime import timedelta
import json
import unittest
from tests.integration.test_ubuntu_sysctl_family import FakeSystem

LIMITS_MANAGED = '/etc/security/limits.d/60-fyp-hardening-cis.conf'
COREDUMP_MANAGED = '/etc/systemd/coredump.conf.d/60-fyp-hardening-cis.conf'
PARAMS = {'sysctl': {'keys': {'fs.suid_dumpable': 0}}, 'limits': True, 'coredump': True}


class FakeCoreSystem(FakeSystem):
    def __init__(self, limits=None, coredump=None, **kwargs):
        super().__init__(runtime={'fs.suid_dumpable': 2}, **kwargs)
        self.limits = dict(limits if limits is not None else {'/etc/security/limits.conf': b'# defaults\n'})
        self.coredump = dict(coredump if coredump is not None else {'/etc/systemd/coredump.conf': b'[Coredump]\n'})

    def limits_files(self):
        return sorted(self.limits.items(), key=lambda kv: (kv[0] != '/etc/security/limits.conf', kv[0]))

    def coredump_files(self):
        return sorted(self.coredump.items(), key=lambda kv: (kv[0] != '/etc/systemd/coredump.conf', kv[0]))

    def write_file(self, path, content):
        self.writes.append(('write', path))
        (self.limits if path == LIMITS_MANAGED else self.coredump)[path] = content

    def remove_file(self, path):
        self.writes.append(('remove', path))
        (self.limits if path == LIMITS_MANAGED else self.coredump).pop(path, None)


class CoreDumpFamilyTests(unittest.TestCase):
    def family(self, system):
        from vm.ubuntu.family_core import CoreDumpFamily
        return CoreDumpFamily(system)

    def test_parameters_are_exact(self):
        family = self.family(FakeCoreSystem())
        family.validate(PARAMS)
        family.validate(dict(PARAMS, coredump=False))
        for bad in (dict(PARAMS, limits=False), dict(PARAMS, sysctl={'keys': {'fs.suid_dumpable': 1}}),
                    dict(PARAMS, extra=1), dict(PARAMS, coredump='yes')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_apply_writes_only_managed_files_and_the_runtime_key(self):
        system = FakeCoreSystem()
        family = self.family(system)
        before = family.read_state(PARAMS)
        expected = family.expected_after(PARAMS, before)
        family.check_eligible(PARAMS)
        family.apply(PARAMS)
        self.assertEqual(family.read_state(PARAMS), expected)
        self.assertIn(b'*\thard\tcore\t0\n', system.limits[LIMITS_MANAGED])
        self.assertIn(b'[Coredump]\nStorage=none\nProcessSizeMax=0\n', system.coredump[COREDUMP_MANAGED])
        self.assertIn(b'fs.suid_dumpable = 0', system.files['/etc/sysctl.d/60-fyp-hardening-cis.conf'])
        self.assertEqual(system.runtime_values['fs.suid_dumpable'], 0)
        self.assertEqual(system.limits['/etc/security/limits.conf'], b'# defaults\n')  # never edited

    def test_without_systemd_coredump_no_coredump_file_is_written(self):
        system = FakeCoreSystem()
        family = self.family(system)
        params = dict(PARAMS, coredump=False)
        family.apply(params)
        self.assertNotIn(COREDUMP_MANAGED, system.coredump)

    def test_sources_that_would_keep_the_control_failing_are_not_eligible(self):
        later_star = FakeCoreSystem(limits={'/etc/security/limits.d/90-dev.conf': b'*  hard  core  unlimited\n'})
        other_domain = FakeCoreSystem(limits={'/etc/security/limits.conf': b'@dev hard core 100\n'})
        later_coredump = FakeCoreSystem(coredump={'/etc/systemd/coredump.conf.d/99-keep.conf': b'[Coredump]\nStorage=external\n'})
        later_sysctl = FakeCoreSystem(files={'/etc/sysctl.d/99-sysctl.conf': b'fs.suid_dumpable = 2\n'})
        for system in (later_star, other_domain, later_coredump, later_sysctl):
            with self.subTest(), self.assertRaises(ValueError):self.family(system).check_eligible(PARAMS)
        earlier = FakeCoreSystem(limits={'/etc/security/limits.conf': b'* hard core unlimited\n'})
        self.family(earlier).check_eligible(PARAMS)  # superseded by the later managed file for domain '*'

    def test_restore_returns_the_exact_before_state(self):
        system = FakeCoreSystem()
        family = self.family(system)
        before = family.read_state(PARAMS)
        family.apply(PARAMS)
        family.restore(PARAMS, before)
        self.assertEqual(family.read_state(PARAMS), before)
        self.assertNotIn(LIMITS_MANAGED, system.limits)
        self.assertNotIn(COREDUMP_MANAGED, system.coredump)
        self.assertEqual(system.runtime_values['fs.suid_dumpable'], 2)

    def test_collector_reads_the_managed_limits_line_as_compliant(self):
        from vm.ubuntu.family_core import LIMITS_CONTENT
        import shlex
        rows = [shlex.split(line, comments=True) for line in LIMITS_CONTENT.decode().splitlines()]
        self.assertIn(['*', 'hard', 'core', '0'], rows)

    def test_host_planner_and_registries(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases
        target = build(FakeCoreSystem())
        self.assertIn('ubuntu.1.5.3.v1', target)
        spec = FAMILIES['ubuntu.1.5.3.v1']
        self.assertEqual((spec.version, spec.implementation_sha256),
                         (target['ubuntu.1.5.3.v1'].version, target['ubuntu.1.5.3.v1'].implementation_sha256))
        ev = evidence(['1.5.3'])
        obs = cases(); ev.raw = json.dumps({'observations': obs}).encode()
        installed = obs['1.5.3']['systemd_coredump_installed']['value']
        self.assertEqual(spec.propose('1.5.3', ev), dict(PARAMS, coredump=installed))
        self.assertIsNone(spec.propose('1.5.3', evidence([])))  # compliant: nothing to plan
