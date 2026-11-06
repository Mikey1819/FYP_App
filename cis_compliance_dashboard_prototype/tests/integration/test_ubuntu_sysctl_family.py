"""Sysctl remediation family (1.5.1, 3.3.1, 3.3.2, 3.3.8) against an IN-MEMORY fake system. No VM, no real sysctl."""
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from tests.integration.test_ubuntu_runner import NOW, IDENTITY

MANAGED = '/etc/sysctl.d/60-fyp-hardening-cis.conf'


class FakeSystem:
    def __init__(self, files=None, runtime=None, ufw=None):
        self.files = dict(files or {'/usr/lib/sysctl.d/50-default.conf': b'kernel.core_uses_pid = 1\n',
                                    '/etc/sysctl.d/99-sysctl.conf': b'# defaults\n'})
        self.runtime_values = dict(runtime or {'kernel.randomize_va_space': 0})
        self.ufw, self.writes = ufw, []

    def config_paths(self):
        # systemd orders by file name across directories.
        return sorted(self.files, key=lambda p: p.rsplit('/', 1)[1])

    def read_config(self, path):
        if path == '/etc/ufw/sysctl.conf':
            return self.ufw
        return self.files.get(path)

    def ufw_sysctl_path(self):
        return '/etc/ufw/sysctl.conf' if self.ufw is not None else None

    def runtime(self, key):
        return self.runtime_values[key]

    def write_managed(self, content):
        self.writes.append(('file', content)); self.files[MANAGED] = content

    def remove_managed(self):
        self.writes.append(('remove',)); self.files.pop(MANAGED, None)

    def set_runtime(self, key, value):
        self.writes.append(('runtime', key, value)); self.runtime_values[key] = value


ASLR = {'keys': {'kernel.randomize_va_space': 2}}


class SysctlFamilyTests(unittest.TestCase):
    def family(self, system, control='1.5.1'):
        from vm.ubuntu.family_sysctl import SysctlFamily
        return SysctlFamily(control, system)

    def test_parameters_are_exactly_the_benchmark_keys_and_values(self):
        from vm.ubuntu.family_sysctl import validate_params
        validate_params('1.5.1', ASLR)
        validate_params('3.3.8', {'keys': {'net.ipv4.conf.all.accept_source_route': 0,
                                           'net.ipv4.conf.default.accept_source_route': 0}})  # IPv6 excluded by planner
        for bad in ({'keys': {'kernel.randomize_va_space': 1}}, {'keys': {}}, {'keys': {'kernel.modprobe': 0}},
                    {'keys': {'kernel.randomize_va_space': True}}, dict(ASLR, extra=1), {'keys': {'net.ipv4.ip_forward': 0}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):validate_params('1.5.1', bad)

    def test_apply_writes_only_the_managed_file_and_listed_runtime_keys(self):
        system = FakeSystem()
        family = self.family(system)
        before = family.read_state(ASLR)
        expected = family.expected_after(ASLR, before)
        family.check_eligible(ASLR)
        family.apply(ASLR)
        self.assertEqual(family.read_state(ASLR), expected)
        self.assertIn(b'kernel.randomize_va_space = 2\n', system.files[MANAGED])
        self.assertEqual([w[0] for w in system.writes], ['file', 'runtime'])
        self.assertEqual(system.runtime_values['kernel.randomize_va_space'], 2)
        self.assertEqual(system.files['/etc/sysctl.d/99-sysctl.conf'], b'# defaults\n')  # other files untouched
        self.assertEqual(family.summary(ASLR, before),
                         {'managed_file': MANAGED, 'keys': [{'key': 'kernel.randomize_va_space', 'runtime': 0, 'proposed': 2}]})

    def test_existing_managed_keys_of_other_controls_are_preserved(self):
        from vm.ubuntu.family_sysctl import HEADER
        system = FakeSystem(files={MANAGED: HEADER + b'net.ipv4.ip_forward = 0\n'}, runtime={'kernel.randomize_va_space': 0})
        self.family(system).apply(ASLR)
        self.assertEqual(system.files[MANAGED].splitlines()[1:], [b'kernel.randomize_va_space = 2', b'net.ipv4.ip_forward = 0'])

    def test_later_file_or_ufw_override_or_foreign_managed_content_is_not_eligible(self):
        later = FakeSystem(files={'/etc/sysctl.d/99-sysctl.conf': b'kernel.randomize_va_space=0\n'})
        same = FakeSystem(files={'/etc/sysctl.d/99-sysctl.conf': b'kernel.randomize_va_space = 2\n'})
        earlier = FakeSystem(files={'/etc/sysctl.d/10-old.conf': b'kernel.randomize_va_space = 0\n'})
        ufw = FakeSystem(ufw=b'kernel/randomize_va_space=1\n')
        foreign = FakeSystem(files={MANAGED: b'vm.swappiness = 10\n'})
        for system in (later, ufw, foreign):
            with self.subTest(), self.assertRaises(ValueError):self.family(system).check_eligible(ASLR)
        self.family(same).check_eligible(ASLR)     # a later file with the same value does not conflict
        self.family(earlier).check_eligible(ASLR)  # an earlier file is superseded by the managed file

    def test_runner_applies_once_keeps_before_state_and_refuses_ineligible_without_writes(self):
        from backends.ubuntu.actions import ActionPlan, ActionSpec
        from backends.ubuntu.approvals import approve
        from vm.ubuntu.runner import Runner
        from vm.ubuntu.family_sysctl import IMPLEMENTATION_SHA256, validate_params
        with tempfile.TemporaryDirectory() as folder:
            def request(system):
                family = self.family(system)
                runner = Runner(folder, {family.action_id: family}, lambda: IDENTITY, clock=lambda: NOW,
                                require_root_owned=False)
                preview = runner.preview(family.action_id, ASLR)
                spec = ActionSpec(family.action_id, 1, IMPLEMENTATION_SHA256, ('1.5.1',),
                                  lambda p: validate_params('1.5.1', p), 60)
                fields = dict(target_id='ubuntu:fixture', registration_epoch='epoch', hostname='UBUNTU-FIXTURE',
                              machine_id='a' * 32, workflow_session_id='1' * 32, round_id='2' * 32, evidence_sha256='e' * 64,
                              control_id='1.5.1', predicate_id='ubuntu.1.5.1.predicate.v1', parameters=ASLR,
                              before_state_sha256=preview['before_state_sha256'],
                              expected_after_sha256=preview['expected_after_sha256'],
                              before_state_collected_at=preview['collected_at'],
                              recovery={'kind': 'restore_backup', 'scope': [MANAGED]}, job_deadline_seconds=60)
                return runner, approve(ActionPlan(spec, 'f' * 32, fields), 'fixture-operator', NOW + timedelta(seconds=1))
            system = FakeSystem()
            runner, approved = request(system)
            self.assertEqual(system.writes, [])  # preview is read-only
            self.assertEqual(json.loads(runner.execute(approved.raw))['outcome'], 'applied')
            stored = Path(folder) / 'requests' / approved.request['request_id'] / 'before_state'
            self.assertIn(b'"kernel.randomize_va_space":0', stored.read_bytes())
            self.assertEqual(json.loads(runner.execute(approved.raw))['code'], 'already_claimed')
            self.assertEqual([w[0] for w in system.writes], ['file', 'runtime'])
            # A conflicting later file appearing after approval: refused before any write.
            racing = FakeSystem()
            runner, approved = request(racing)
            racing.files['/etc/sysctl.d/99-sysctl.conf'] = b'kernel.randomize_va_space = 0\n'
            self.assertIn(json.loads(runner.execute(approved.raw))['code'], ('stale_read_set', 'not_eligible'))
            self.assertEqual(racing.writes, [])

    def test_host_planner_proposes_only_complete_failing_sysctl_controls(self):
        from backends.ubuntu.actions import FAMILIES
        from tests.integration.test_ubuntu_risk import evidence
        ev = evidence(['1.5.1', '3.3.8'])
        ev.raw = json.dumps({'observations': self._observations(ev)}).encode()
        spec = FAMILIES['ubuntu.1.5.1.v1']
        self.assertEqual(spec.propose('1.5.1', ev), ASLR)
        self.assertIsNone(FAMILIES['ubuntu.3.3.1.v1'].propose('3.3.1', ev))  # compliant: nothing to propose
        self.assertEqual(set(FAMILIES), {'ubuntu.1.5.1.v1', 'ubuntu.1.5.3.v1', 'ubuntu.3.3.1.v1', 'ubuntu.3.3.2.v1',
                                         'ubuntu.3.3.8.v1', 'ubuntu.5.2.3.v1', 'ubuntu.5.3.3.2.2.v1',
                                         'ubuntu.5.4.1.1.v1', 'ubuntu.5.4.1.3.v1', 'ubuntu.5.4.1.5.v1',
                                         'ubuntu.1.3.1.1.v1', 'ubuntu.1.5.4.v1', 'ubuntu.2.1.2.v1', 'ubuntu.6.3.1.1.v1',
                                         'ubuntu.5.1.7.v1', 'ubuntu.5.1.10.v1', 'ubuntu.5.1.16.v1', 'ubuntu.5.1.19.v1',
                                         'ubuntu.5.1.20.v1', 'ubuntu.5.1.21.v1', 'ubuntu.4.1.7.v1',
                                         'ubuntu.5.2.2.v1', 'ubuntu.6.3.1.2.v1', 'ubuntu.6.3.3.4.v1',
                                         'ubuntu.6.3.3.6.v1', 'ubuntu.6.3.3.8.v1', 'ubuntu.6.3.1.3.v1',
                                         'ubuntu.4.1.3.v1', 'ubuntu.4.1.4.v1', 'ubuntu.1.2.2.1.v1'})
        incomplete = self._observations(ev); incomplete['1.5.1']['sysctl_resolution'] = {'state': 'ok', 'value': 'incomplete'}
        ev.raw = json.dumps({'observations': incomplete}).encode()
        self.assertIsNone(spec.propose('1.5.1', ev))

    def _observations(self, ev):
        from tests.integration.ubuntu_fixtures import cases
        return cases()

    def test_target_and_host_registries_agree_on_versions_and_hashes(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        target = build(FakeSystem())
        self.assertEqual(set(target), set(FAMILIES))
        for action_id, family in target.items():
            self.assertEqual((family.version, family.implementation_sha256),
                             (FAMILIES[action_id].version, FAMILIES[action_id].implementation_sha256))

    def test_conf_parser_handles_slashes_dashes_comments_and_last_value(self):
        from vm.ubuntu.family_sysctl import parse_conf
        text = b'# c\n; c\n-net/ipv4/ip_forward = 1\nkernel.randomize_va_space=1\nkernel.randomize_va_space = 2\n\n'
        self.assertEqual(parse_conf(text), {'net.ipv4.ip_forward': '1', 'kernel.randomize_va_space': '2'})
        with self.assertRaises(ValueError):parse_conf(b'not a setting\n')
