"""auditd service family for CIS 6.3.1.2 (p.754): unmask, enable and start. IN-MEMORY systemd fake."""
import json
import unittest

PARAMS = {'unit': 'auditd.service', 'enabled': True, 'active': True}


class FakeSystemd:
    def __init__(self, load='loaded', enabled='disabled', active='inactive'):
        self.state, self.calls = {'load': load, 'enabled': enabled, 'active': active}, []

    def unit_state(self, unit):
        return dict(self.state)

    def systemctl(self, verb, unit):
        self.calls.append(verb)
        self.state.update({'unmask': {'enabled': 'disabled'}, 'enable': {'enabled': 'enabled'},
                           'start': {'active': 'active'}, 'stop': {'active': 'inactive'},
                           'disable': {'enabled': 'disabled'}, 'mask': {'enabled': 'masked'}}[verb])


class AuditdServiceTests(unittest.TestCase):
    def family(self, system):
        from vm.ubuntu.family_service import ServiceFamily
        return ServiceFamily('6.3.1.2', system)

    def cycle(self, system):
        family = self.family(system)
        family.validate(PARAMS)
        family.check_eligible(PARAMS)
        before = family.read_state(PARAMS)
        expected = family.expected_after(PARAMS, before)
        family.apply(PARAMS)
        self.assertEqual(family.read_state(PARAMS), expected)
        return family, before

    def test_masked_unit_is_unmasked_enabled_and_started_then_restored_exactly(self):
        system = FakeSystemd(enabled='masked')
        family, before = self.cycle(system)
        self.assertEqual(system.calls, ['unmask', 'enable', 'start'])
        family.restore(PARAMS, before)
        self.assertEqual(family.read_state(PARAMS), before)
        self.assertEqual(system.calls[3:], ['stop', 'mask'])

    def test_only_missing_steps_run(self):
        system = FakeSystemd(enabled='enabled', active='inactive')
        self.cycle(system)
        self.assertEqual(system.calls, ['start'])

    def test_not_installed_or_unmodelled_unit_states_are_refused(self):
        for system in (FakeSystemd(load='not-found'), FakeSystemd(enabled='static'), FakeSystemd(enabled='indirect')):
            with self.subTest(state=system.state), self.assertRaises(ValueError):
                self.family(system).check_eligible(PARAMS)
        with self.assertRaises(ValueError):self.family(FakeSystemd()).validate(dict(PARAMS, unit='ssh.service'))

    def test_registry_agrees_and_planner_needs_resolved_unit_facts(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())['ubuntu.6.3.1.2.v1']
        spec = FAMILIES['ubuntu.6.3.1.2.v1']
        self.assertEqual((spec.version, spec.implementation_sha256), (target.version, target.implementation_sha256))
        ev = evidence(['6.3.1.2'])
        obs = cases()
        key, value = FAILURES['6.3.1.2']
        obs['6.3.1.2'][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertEqual(spec.propose('6.3.1.2', ev), PARAMS)
        obs['6.3.1.2']['auditd.enabled'] = observation('not-found')  # package missing: 6.3.1.1 comes first
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(spec.propose('6.3.1.2', ev))
