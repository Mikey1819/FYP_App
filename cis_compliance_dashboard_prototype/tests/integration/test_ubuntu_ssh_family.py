"""SSH drop-in family for CIS 5.1.7/5.1.10/5.1.16/5.1.19/5.1.20/5.1.21 (pp.502-553). IN-MEMORY sshd model only."""
import json
import unittest

MANAGED = '00-fyp-hardening-cis.conf'
UBUNTU_MAIN = b'# sshd_config\nInclude /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nUsePAM yes\n'
DEFAULTS = {'permitrootlogin': 'without-password', 'maxauthtries': '6', 'clientaliveinterval': '0',
            'clientalivecountmax': '3', 'hostbasedauthentication': 'no', 'permitemptypasswords': 'no',
            'permituserenvironment': 'no', 'usepam': 'yes'}


class FakeSsh:
    """sshd's rule: the first value obtained wins; the Include is expanded in place, drop-ins in lexical order."""
    def __init__(self, main=UBUNTU_MAIN, dropins=None, syntax_ok=True):
        self.main, self.dropins, self.syntax_ok, self.calls = main, dict(dropins or {}), syntax_ok, []

    def sshd_sources(self):
        return self.main, sorted(self.dropins.items())

    def effective(self):
        lines = []
        for line in self.main.decode().splitlines():
            if line.lower().startswith('include '):
                for _, data in sorted(self.dropins.items()):
                    lines += data.decode().splitlines()
            else:
                lines.append(line)
        values = dict(DEFAULTS)
        seen = set()
        for line in lines:
            parts = line.split('#')[0].split()
            if len(parts) == 2 and parts[0].lower() not in seen:
                seen.add(parts[0].lower())
                values[parts[0].lower()] = {'prohibit-password': 'without-password'}.get(parts[1], parts[1].lower())
        return values

    def write_managed(self, content):
        if not self.syntax_ok:
            raise OSError('sshd -t rejected the configuration; the previous file was put back')
        self.calls.append('write' if content is not None else 'remove')
        if content is None:
            self.dropins.pop(MANAGED, None)
        else:
            self.dropins[MANAGED] = content


class SshCase(unittest.TestCase):
    CONTROL, PARAMS = None, None

    def family(self, system, control=None):
        from vm.ubuntu.family_ssh import SshFamily
        return SshFamily(control or self.CONTROL, system)

    def cycle(self, system, control=None, params=None):
        family, params = self.family(system, control), params or self.PARAMS
        family.validate(params)
        family.check_eligible(params)
        before = family.read_state(params)
        expected = family.expected_after(params, before)
        family.apply(params)
        self.assertEqual(family.read_state(params), expected)
        return family, before

    def refused(self, system):
        with self.assertRaises(ValueError):self.family(system).check_eligible(self.PARAMS)


class RootLoginTests(SshCase):
    CONTROL, PARAMS = '5.1.20', {'settings': {'PermitRootLogin': 'no'}}

    def test_drop_in_wins_over_the_main_file_after_the_include_and_restore_is_exact(self):
        system = FakeSsh()
        self.assertEqual(system.effective()['permitrootlogin'], 'without-password')
        family, before = self.cycle(system)
        self.assertEqual(system.effective()['permitrootlogin'], 'no')
        self.assertEqual(system.main, UBUNTU_MAIN)  # sshd_config itself is never edited
        self.assertIn(b'PermitRootLogin no\n', system.dropins[MANAGED])
        family.restore(self.PARAMS, before)
        self.assertEqual((family.read_state(self.PARAMS), MANAGED in system.dropins), (before, False))

    def test_only_the_cis_value(self):
        family = self.family(FakeSsh())
        for bad in ({'settings': {'PermitRootLogin': 'yes'}}, {'settings': {'MaxAuthTries': '4'}},
                    {'settings': {'PermitRootLogin': 'no', 'X': 'y'}}, {}, {'settings': 'no'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_sources_sshd_would_read_first_or_cannot_be_modelled_are_refused(self):
        for system in (FakeSsh(main=b'PermitRootLogin yes\n' + UBUNTU_MAIN),        # before the Include
                       FakeSsh(dropins={'00-aaa.conf': b'PermitRootLogin yes\n'}),  # earlier drop-in
                       FakeSsh(main=UBUNTU_MAIN + b'Match User backup\n  PermitRootLogin yes\n'),
                       FakeSsh(main=UBUNTU_MAIN.replace(b'Include /etc/ssh/sshd_config.d/*.conf\n', b'')),
                       FakeSsh(main=UBUNTU_MAIN + b'Include /etc/ssh/other/*.conf\n'),
                       FakeSsh(dropins={MANAGED: b'PermitRootLogin no\n'})):         # not written by this family
            with self.subTest(main=system.main[:40], dropins=sorted(system.dropins)):
                self.refused(system)
        self.cycle(FakeSsh(dropins={'50-cloud-init.conf': b'PasswordAuthentication yes\nPermitRootLogin yes\n'}))

    def test_a_rejected_configuration_changes_nothing(self):
        system = FakeSsh(syntax_ok=False)
        with self.assertRaises(OSError):self.family(system).apply(self.PARAMS)
        self.assertEqual(system.dropins, {})


class SharedFileTests(SshCase):
    CONTROL, PARAMS = '5.1.16', {'settings': {'MaxAuthTries': '4'}}

    def test_each_control_owns_only_its_keys_in_the_shared_file(self):
        system = FakeSsh()
        root, root_before = self.cycle(system, '5.1.20', {'settings': {'PermitRootLogin': 'no'}})
        alive, alive_before = self.cycle(system, '5.1.7', {'settings': {'ClientAliveInterval': '15',
                                                                         'ClientAliveCountMax': '3'}})
        tries, tries_before = self.cycle(system)
        effective = system.effective()
        self.assertEqual((effective['permitrootlogin'], effective['clientaliveinterval'], effective['maxauthtries']),
                         ('no', '15', '4'))
        # Restoring one control leaves the others' keys in place.
        alive.restore({'settings': {'ClientAliveInterval': '15', 'ClientAliveCountMax': '3'}}, alive_before)
        effective = system.effective()
        self.assertEqual((effective['permitrootlogin'], effective['clientaliveinterval'], effective['maxauthtries']),
                         ('no', '0', '4'))
        text = system.dropins[MANAGED].decode()
        self.assertLess(text.index('MaxAuthTries'), text.index('PermitRootLogin'))  # one fixed key order

    def test_without_the_include_the_drop_in_would_never_be_read(self):
        self.refused(FakeSsh(main=b'# sshd_config\nUsePAM yes\n'))

    def test_the_family_is_a_commit_confirm_job(self):
        family = self.family(FakeSsh())
        self.assertEqual((family.supervision, family.confirm_seconds), ('confirm', 600))
        self.assertIn('confirm', json.dumps(family.summary(self.PARAMS, family.read_state(self.PARAMS))).lower())


class SshRegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_planners_need_a_resolved_context(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        expected = {'5.1.7': {'ClientAliveInterval': '15', 'ClientAliveCountMax': '3'},
                    '5.1.10': {'HostbasedAuthentication': 'no'}, '5.1.16': {'MaxAuthTries': '4'},
                    '5.1.19': {'PermitEmptyPasswords': 'no'}, '5.1.20': {'PermitRootLogin': 'no'},
                    '5.1.21': {'PermitUserEnvironment': 'no'}}
        ev = evidence(list(expected))
        obs = cases()
        for cid in expected:
            key, value = FAILURES[cid]
            obs[cid][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        for cid, settings in expected.items():
            action = 'ubuntu.%s.v1' % cid
            self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
            self.assertEqual(next(a for a in ev.assessments if a.control_id == cid).status.value, 'Non-Compliant', cid)
            self.assertEqual(FAMILIES[action].propose(cid, ev), {'settings': settings}, cid)
        obs['5.1.20']['ssh_context_resolution'] = observation('unsupported')
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES['ubuntu.5.1.20.v1'].propose('5.1.20', ev))
