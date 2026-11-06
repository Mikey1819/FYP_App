"""Sudo logfile (CIS 5.2.3, p.562) and password minlen (CIS 5.3.3.2.2, pp.605-607) families. IN-MEMORY fakes only."""
import json
import unittest

SUDO_MANAGED = '/etc/sudoers.d/60-fyp-hardening-cis'
PWQ_MANAGED = '/etc/security/pwquality.conf.d/60-fyp-hardening-cis.conf'
UBUNTU_SUDOERS = b'Defaults env_reset\nDefaults use_pty\nroot ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n'
PAM = b'password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so obscure use_authtok\n'


class FakeAuthSystem:
    def __init__(self, sudoers=None, sudo_d=None, pwq_main=b'# minlen = 8\n', pwq_d=None, pam=PAM, visudo_ok=True):
        self.sudoers, self.sudo_d = sudoers if sudoers is not None else UBUNTU_SUDOERS, dict(sudo_d or {})
        self.pwq_main, self.pwq_d, self.pam, self.visudo_ok, self.writes = pwq_main, dict(pwq_d or {}), pam, visudo_ok, []

    def sudo_sources(self):
        return [('/etc/sudoers', self.sudoers)] + sorted(('/etc/sudoers.d/' + n, d) for n, d in self.sudo_d.items())

    def write_sudo_managed(self, content):
        if not self.visudo_ok:
            raise OSError('visudo -cf rejected the staged file')  # nothing installed
        self.writes.append('sudo'); self.sudo_d[SUDO_MANAGED.rsplit('/', 1)[1]] = content

    def remove_sudo_managed(self):
        self.writes.append('sudo-remove'); self.sudo_d.pop(SUDO_MANAGED.rsplit('/', 1)[1], None)

    def pwquality_sources(self):
        return self.pwq_main, sorted(self.pwq_d.items()), self.pam

    def write_pwquality_managed(self, content):
        self.writes.append('pwq'); self.pwq_d[PWQ_MANAGED.rsplit('/', 1)[1]] = content

    def remove_pwquality_managed(self):
        self.writes.append('pwq-remove'); self.pwq_d.pop(PWQ_MANAGED.rsplit('/', 1)[1], None)


class SudoLogfileTests(unittest.TestCase):
    PARAMS = {'logfile': '/var/log/sudo.log'}

    def family(self, system):
        from vm.ubuntu.family_auth import SudoLogfileFamily
        return SudoLogfileFamily(system)

    def test_parameters_are_the_approved_site_path_only(self):
        family = self.family(FakeAuthSystem())
        family.validate(self.PARAMS)
        for bad in ({'logfile': '/tmp/x'}, {'logfile': '/var/log/../etc/shadow'}, dict(self.PARAMS, extra=1), {}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_apply_writes_one_validated_managed_file_that_the_collector_reads(self):
        system = FakeAuthSystem()
        family = self.family(system)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.check_eligible(self.PARAMS)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        self.assertEqual(system.sudoers, UBUNTU_SUDOERS)  # never edited
        import shlex
        managed = system.sudo_d['60-fyp-hardening-cis'].decode()
        self.assertIn(['Defaults', 'logfile=/var/log/sudo.log'], [shlex.split(l, comments=True) for l in managed.splitlines()])
        self.assertNotIn('.', SUDO_MANAGED.rsplit('/', 1)[1])  # sudo skips names containing '.'

    def test_conflicts_and_unsupported_includes_are_not_eligible(self):
        for system in (FakeAuthSystem(sudo_d={'90-local': b'Defaults !logfile\n'}),
                       FakeAuthSystem(sudoers=UBUNTU_SUDOERS + b'@include /etc/sudoers.local\n'),
                       FakeAuthSystem(sudo_d={'60-fyp-hardening-cis': b'Defaults lecture=always\n'})):
            with self.subTest(), self.assertRaises(ValueError):self.family(system).check_eligible(self.PARAMS)

    def test_rejected_validation_installs_nothing_and_restore_removes_the_file(self):
        failing = FakeAuthSystem(visudo_ok=False)
        with self.assertRaises(OSError):self.family(failing).apply(self.PARAMS)
        self.assertEqual(failing.sudo_d, {})
        system = FakeAuthSystem()
        family = self.family(system)
        before = family.read_state(self.PARAMS)
        family.apply(self.PARAMS)
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)


class PasswordMinlenTests(unittest.TestCase):
    PARAMS = {'minlen': 14}

    def family(self, system):
        from vm.ubuntu.family_auth import PasswordMinlenFamily
        return PasswordMinlenFamily(system)

    def test_apply_makes_the_collector_resolver_report_14(self):
        from vm.ubuntu.probes import password_minlen
        system = FakeAuthSystem()
        family = self.family(system)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.check_eligible(self.PARAMS)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        main, dropins, pam = system.pwquality_sources()
        self.assertEqual(password_minlen([(n, d.decode()) for n, d in dropins], main.decode(), pam.decode()), 14)
        self.assertEqual(system.pwq_main, b'# minlen = 8\n')  # never edited

    def test_overrides_that_would_keep_it_below_14_or_missing_enforcement_are_not_eligible(self):
        for system in (FakeAuthSystem(pwq_main=b'minlen = 8\n'),
                       FakeAuthSystem(pwq_d={'90-short.conf': b'minlen = 10\n'}),
                       FakeAuthSystem(pam=b'password requisite pam_pwquality.so retry=3 minlen=8\n'),
                       FakeAuthSystem(pam=b'password [success=1 default=ignore] pam_unix.so obscure\n')):
            with self.subTest(), self.assertRaises(ValueError):self.family(system).check_eligible(self.PARAMS)
        self.family(FakeAuthSystem(pwq_d={'10-old.conf': b'minlen = 8\n'})).check_eligible(self.PARAMS)  # superseded

    def test_parameters_and_restore(self):
        family = self.family(FakeAuthSystem())
        for bad in ({'minlen': 13}, {'minlen': '14'}, {}, {'minlen': 14, 'x': 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)
        system = FakeAuthSystem()
        family = self.family(system)
        before = family.read_state(self.PARAMS)
        family.apply(self.PARAMS)
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)


class AuthRegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_planners_need_resolved_evidence(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        for action in ('ubuntu.5.2.3.v1', 'ubuntu.5.3.3.2.2.v1'):
            self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
        ev = evidence(['5.2.3', '5.3.3.2.2'])
        obs = cases(); ev.raw = json.dumps({'observations': obs}).encode()
        self.assertEqual(FAMILIES['ubuntu.5.2.3.v1'].propose('5.2.3', ev), {'logfile': '/var/log/sudo.log'})
        self.assertEqual(FAMILIES['ubuntu.5.3.3.2.2.v1'].propose('5.3.3.2.2', ev), {'minlen': 14})
        obs['5.3.3.2.2']['pam_resolution'] = {'state': 'ok', 'value': 'unsupported'}
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES['ubuntu.5.3.3.2.2.v1'].propose('5.3.3.2.2', ev))

    def test_catalogue_remediation_coverage_matches_the_registered_families(self):
        from pathlib import Path
        from backends.ubuntu.actions import FAMILIES
        catalogue = json.loads((Path(__file__).resolve().parents[2] / 'catalogues' / 'ubuntu2204.json').read_text('utf-8'))
        covered = {c['control_id'] for c in catalogue['controls'] if c['coverage']['remediation'] == 'fixture_tested'}
        self.assertEqual(covered, {cid for spec in FAMILIES.values() for cid in spec.control_ids})
