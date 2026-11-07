"""Package families: 1.3.1.1 / 6.3.1.1 install, 1.5.4 purge (CIS pp.136, 160, 752). IN-MEMORY apt fake."""
import json
import unittest

REPO = {'auditd': ('1:3.0.7-1build1', ['libauparse0']), 'audispd-plugins': ('1:3.0.7-1build1', ['auditd']),
        'libauparse0': ('1:3.0.7-1build1', []), 'apparmor': ('3.0.4-2ubuntu2.3', []),
        'apparmor-utils': ('3.0.4-2ubuntu2.3', ['python3-apparmor']), 'python3-apparmor': ('3.0.4-2ubuntu2.3', []),
        'prelink': ('0.0.20131005-1', []), 'avahi-daemon': ('0.8-5ubuntu5.2', [])}


class FakeApt:
    """Just enough apt/dpkg: installs pull dependencies, purges report reverse dependencies."""
    def __init__(self, installed=None, rdepends=None, incomplete=(), newer=None):
        self.installed = dict(installed or {})
        self.rdepends, self.incomplete, self.newer, self.calls = dict(rdepends or {}), set(incomplete), dict(newer or {}), []

    def package_status(self, names):
        return {n: {'status': 'incomplete' if n in self.incomplete else 'installed' if n in self.installed else 'absent',
                    'version': self.installed.get(n)} for n in names}

    def _closure(self, names):
        out = []
        for name in names:
            for dep in REPO[name][1]:
                out += [d for d in self._closure([dep]) if d not in out]
            if name not in out:
                out.append(name)
        return out

    def simulate(self, mode, names):
        lines = []
        if mode == 'install':
            for name in self._closure(names):
                if name in self.newer and name in self.installed:
                    lines.append('Inst %s [%s] (%s Ubuntu:22.04/jammy-updates [amd64])' % (name, self.installed[name], self.newer[name]))
                elif name not in self.installed:
                    lines.append('Inst %s (%s Ubuntu:22.04/jammy [amd64])' % (name, REPO[name][0]))
        else:
            for name in names:
                for other in self.rdepends.get(name, []):
                    if other in self.installed:
                        lines.append('Purg %s [%s]' % (other, self.installed[other]))
                if name in self.installed:
                    lines.append('Purg %s [%s]' % (name, self.installed[name]))
        return '\n'.join(['Reading package lists...'] + lines + [l.replace('Inst', 'Conf', 1) for l in lines if l.startswith('Inst')]) + '\n'

    def install(self, names, versions=None):
        self.calls.append(('install', tuple(names)))
        for name in self._closure([n.split('=')[0] for n in names]):
            self.installed.setdefault(name, (versions or {}).get(name, REPO[name][0]))

    def purge(self, names):
        self.calls.append(('purge', tuple(names)))
        for name in names:
            self.installed.pop(name, None)

    def run_fixed(self, argv):
        self.calls.append(('run', tuple(argv)))


class SimulationParserTests(unittest.TestCase):
    def test_install_upgrade_remove_and_purge_lines(self):
        from vm.ubuntu.family_package import parse_simulation
        text = ('NOTE: This is only a simulation!\nInst libauparse0:amd64 (1:3.0.7-1build1 Ubuntu:22.04/jammy [amd64])\n'
                'Inst libc6 [2.35-0ubuntu3.1] (2.35-0ubuntu3.8 Ubuntu:22.04/jammy-updates [amd64])\n'
                'Remv foo [1.0]\nPurg avahi-daemon [0.8-5ubuntu5.2]\nConf libauparse0:amd64 (1:3.0.7-1build1 Ubuntu:22.04/jammy [amd64])\n')
        self.assertEqual(parse_simulation(text), [('Inst', 'libauparse0', '1:3.0.7-1build1', None),
                                                  ('Inst', 'libc6', '2.35-0ubuntu3.8', '2.35-0ubuntu3.1'),
                                                  ('Remv', 'foo', '1.0', None), ('Purg', 'avahi-daemon', '0.8-5ubuntu5.2', None)])
        with self.assertRaises(ValueError):
            parse_simulation('Inst bad;name (1 x)\n')


class PackageCase(unittest.TestCase):
    CONTROL, PARAMS = None, None

    def family(self, system):
        from vm.ubuntu.family_package import PackageFamily
        return PackageFamily(self.CONTROL, system)

    def cycle(self, system):
        family = self.family(system)
        family.validate(self.PARAMS)
        family.check_eligible(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        return family, before

    def refused(self, system):
        with self.assertRaises(ValueError):self.family(system).check_eligible(self.PARAMS)


class AuditdInstallTests(PackageCase):
    CONTROL, PARAMS = '6.3.1.1', {'packages': ['auditd', 'audispd-plugins']}

    def test_validate_only_the_cis_package_set(self):
        family = self.family(FakeApt())
        for bad in ({'packages': ['auditd']}, {'packages': ['audispd-plugins', 'auditd']}, {'packages': ['auditd', 'evil']},
                    {}, {'packages': ['auditd', 'audispd-plugins'], 'x': 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_install_adds_exactly_the_simulated_packages_and_restore_purges_only_those(self):
        system = FakeApt(installed={'openssh-server': '1:8.9p1'})
        family, before = self.cycle(system)
        self.assertEqual(set(system.installed), {'openssh-server', 'auditd', 'audispd-plugins', 'libauparse0'})
        summary = family.summary(self.PARAMS, before)
        self.assertEqual(summary['will_install'], ['libauparse0=1:3.0.7-1build1', 'auditd=1:3.0.7-1build1',
                                                   'audispd-plugins=1:3.0.7-1build1'])
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)
        self.assertEqual(set(system.installed), {'openssh-server'})
        self.assertIn(('purge', ('libauparse0', 'auditd', 'audispd-plugins')), system.calls)

    def test_upgrades_removals_or_broken_packages_are_refused(self):
        self.refused(FakeApt(installed={'libauparse0': '1:3.0.6'}, newer={'libauparse0': '1:3.0.7-1build1'}))
        self.refused(FakeApt(incomplete={'auditd'}))
        system = FakeApt()
        system.simulate = lambda mode, names: 'Inst auditd (1 x [amd64])\nRemv other [1]\n'
        self.refused(system)

    def test_already_installed_target_is_kept_and_only_the_missing_one_added(self):
        system = FakeApt(installed={'auditd': '1:3.0.7-1build1', 'libauparse0': '1:3.0.7-1build1'})
        family, before = self.cycle(system)
        family.restore(self.PARAMS, before)
        self.assertEqual(set(system.installed), {'auditd', 'libauparse0'})


class AppArmorInstallTests(PackageCase):
    CONTROL, PARAMS = '1.3.1.1', {'packages': ['apparmor', 'apparmor-utils']}

    def test_install_and_restore(self):
        system = FakeApt(installed={'apparmor': '3.0.4-2ubuntu2.3'})
        family, before = self.cycle(system)
        self.assertIn('python3-apparmor', system.installed)
        family.restore(self.PARAMS, before)
        self.assertEqual(set(system.installed), {'apparmor'})


# 2.1.2 no longer purges avahi-daemon: it keeps the package and masks its units (administrator decision
# 2026-11-08; test_ubuntu_avahi_mask.py).


class PrelinkPurgeTests(PackageCase):
    CONTROL, PARAMS = '1.5.4', {'packages': ['prelink']}

    def test_binaries_are_restored_before_the_purge(self):
        system = FakeApt(installed={'prelink': '0.0.20131005-1'})
        self.cycle(system)
        self.assertEqual(system.calls, [('run', ('/usr/sbin/prelink', '-ua')), ('purge', ('prelink',))])


class PackageRegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_jobs_are_supervised(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        expected = {'6.3.1.1': {'packages': ['auditd', 'audispd-plugins']}}
        for cid in ('1.3.1.1', '1.5.4', '6.3.1.1'):
            action = 'ubuntu.%s.v1' % cid
            self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
            self.assertEqual((target[action].supervision, target[action].max_seconds), ('job', 900))
        from tests.integration.ubuntu_fixtures import FAILURES
        units = {unit + '.' + field: value for unit in ('avahi-daemon.service', 'avahi-daemon.socket')
                 for field, value in (('active', 'active'), ('enabled', 'enabled'))}  # as found on the live VM
        ev = evidence(list(expected))
        obs = cases()
        for cid in expected:
            key, value = FAILURES[cid]
            obs[cid][key] = observation(value)
        obs['2.1.2'].update({k: observation(v) for k, v in units.items()})
        from backends.ubuntu.predicates import evaluate
        ev.assessments = tuple(evaluate(cid, obs[cid]) if cid in expected else a
                               for cid, a in ((a.control_id, a) for a in ev.assessments))
        ev.raw = json.dumps({'observations': obs}).encode()
        for cid, params in expected.items():
            self.assertEqual(next(a for a in ev.assessments if a.control_id == cid).status.value, 'Non-Compliant', cid)
            self.assertEqual(FAMILIES['ubuntu.%s.v1' % cid].propose(cid, ev), params, cid)
        obs['6.3.1.1']['package.auditd'] = {'state': 'error', 'value': None}
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES['ubuntu.6.3.1.1.v1'].propose('6.3.1.1', ev))
