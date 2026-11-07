"""2.1.2 mask-and-retain (administrator decision 2026-11-08: keep avahi-daemon installed, stop and mask its socket and
service). CIS v2.0.0 pp. 222-223: "IF the avahi-daemon package is required as a dependency: systemctl stop
avahi-daemon.socket avahi-daemon.service; systemctl mask avahi-daemon.socket avahi-daemon.service". The catalogue's
U-2.1.2 prefers this path; the live purge preview was refused because removing the package would remove dependants.
Recovery restores the recorded mask, enablement and activity. In-memory systemd fake; no VM."""
import json
import unittest

from tests.integration.ubuntu_fixtures import cases, observation

UNITS = ('avahi-daemon.socket', 'avahi-daemon.service')
PARAMS = {'units': list(UNITS), 'masked': True}
MACHINE = 'f1d16ae7e6bc4d2488f9410fcd858e36'


class FakeSystemd:
    """systemctl show semantics: a masked unit reads LoadState=masked, UnitFileState=masked; unmask brings back the
    enablement its symlinks still give it."""

    def __init__(self, enabled='enabled', active='active', installed=True):
        self.units = {u: {'load': 'loaded' if installed else 'not-found', 'enabled': enabled if installed else 'not-found',
                          'active': active if installed else 'inactive', 'links': enabled == 'enabled'} for u in UNITS}
        self.calls = []

    def unit_state(self, unit):
        u = self.units[unit]
        return {'load': u['load'], 'enabled': u['enabled'], 'active': u['active']}

    def systemctl(self, verb, unit):
        self.calls.append((verb, unit))
        u = self.units[unit]
        if verb == 'stop':
            u['active'] = 'inactive'
        elif verb == 'start':
            u['active'] = 'active'
        elif verb == 'mask':
            u.update(load='masked', enabled='masked', active='inactive' if u['active'] != 'active' else u['active'])
        elif verb == 'unmask':
            u.update(load='loaded', enabled='enabled' if u['links'] else 'disabled')
        elif verb == 'enable':
            u.update(enabled='enabled', links=True)
        elif verb == 'disable':
            u.update(enabled='disabled', links=False)


class AvahiMaskFamilyTests(unittest.TestCase):
    def family(self, system):
        from vm.ubuntu.family_service import AvahiMaskFamily
        return AvahiMaskFamily('2.1.2', system)

    def test_stop_then_mask_both_units_matches_the_planned_after_state_and_restore_is_exact(self):
        system = FakeSystemd()
        family = self.family(system)
        family.validate(PARAMS)
        family.check_eligible(PARAMS)
        before = family.read_state(PARAMS)
        expected = family.expected_after(PARAMS, before)
        family.apply(PARAMS)
        self.assertEqual(system.calls[:2], [('stop', 'avahi-daemon.socket'), ('stop', 'avahi-daemon.service')])
        self.assertEqual(set(system.calls[2:]), {('mask', u) for u in UNITS})
        self.assertEqual(family.read_state(PARAMS), expected)
        family.restore(PARAMS, before)
        self.assertEqual(family.read_state(PARAMS), before)

    def test_only_the_registered_units_and_mask_are_managed(self):
        family = self.family(FakeSystemd())
        for params in ({'units': ['avahi-daemon.service'], 'masked': True}, dict(PARAMS, masked=False),
                       {'units': ['ssh.service', 'avahi-daemon.socket'], 'masked': True}):
            with self.subTest(params=params), self.assertRaises(ValueError):
                family.validate(params)

    def test_a_missing_package_or_a_changing_unit_is_refused(self):
        for system in (FakeSystemd(installed=False), FakeSystemd(active='activating')):
            with self.subTest(state=system.units['avahi-daemon.service']), self.assertRaises(ValueError):
                self.family(system).check_eligible(PARAMS)

    def test_the_summary_lists_the_steps_and_says_the_package_stays(self):
        family = self.family(FakeSystemd())
        summary = family.summary(PARAMS, family.read_state(PARAMS))
        self.assertEqual(summary['steps'], ['stop avahi-daemon.socket', 'stop avahi-daemon.service',
                                            'mask avahi-daemon.socket', 'mask avahi-daemon.service'])
        self.assertIn('stays installed', summary['package'])


class AvahiHostSpecTests(unittest.TestCase):
    def evidence(self, machine=MACHINE, package='installed', active='active', enabled='enabled'):
        from types import SimpleNamespace as N
        from backends.ubuntu.predicates import evaluate
        obs = cases()
        obs['2.1.2'] = {'package.avahi-daemon': observation(package),
                        **{'%s.%s' % (u, f): observation(v) for u in UNITS for f, v in (('active', active), ('enabled', enabled))}}
        return N(raw=json.dumps({'observations': obs, 'machine_id': machine}).encode(),
                 assessments=[evaluate('2.1.2', obs['2.1.2'], reviewed_avahi_retention=True)])

    def test_the_mask_is_proposed_only_where_the_retention_decision_is_registered(self):
        from backends.ubuntu.actions import FAMILIES
        spec = FAMILIES['ubuntu.2.1.2.v1']
        self.assertEqual(spec.propose('2.1.2', self.evidence()), PARAMS)
        self.assertIsNone(spec.propose('2.1.2', self.evidence(machine='0' * 32)))
        self.assertIsNone(spec.propose('2.1.2', self.evidence(package='absent')))
        self.assertEqual(spec.recovery['scope'], ['systemd:avahi-daemon.socket', 'systemd:avahi-daemon.service'])

    def test_host_and_target_registries_agree(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())['ubuntu.2.1.2.v1']
        self.assertEqual((FAMILIES['ubuntu.2.1.2.v1'].version, FAMILIES['ubuntu.2.1.2.v1'].implementation_sha256),
                         (target.version, target.implementation_sha256))
        self.assertIsNone(getattr(target, 'supervision', None))  # direct: in the runner session


class AvahiRetentionDecisionTests(unittest.TestCase):
    def test_masked_units_read_compliant_only_on_the_registered_machine(self):
        from backends.ubuntu.predicates import evaluate
        from system.config import UBUNTU_AVAHI_RETENTION
        self.assertEqual(UBUNTU_AVAHI_RETENTION.get(MACHINE), 'mask')
        masked = {'package.avahi-daemon': observation('installed'),
                  **{'%s.%s' % (u, f): observation(v) for u in UNITS for f, v in (('active', 'inactive'), ('enabled', 'masked'))}}
        self.assertEqual(evaluate('2.1.2', masked, reviewed_avahi_retention=True).status.value, 'Compliant')
        self.assertEqual(evaluate('2.1.2', masked).status.value, 'Unknown')  # unreviewed retention stays Unknown

    def test_the_envelope_applies_the_registration_by_machine_id(self):
        from backends.ubuntu.envelope import _avahi_retention
        self.assertTrue(_avahi_retention({'machine_id': MACHINE}))
        self.assertFalse(_avahi_retention({'machine_id': '0' * 32}))


if __name__ == '__main__':
    unittest.main()
