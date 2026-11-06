"""CIS 1.2.2.1 (Manual): read-only update facts in the collector and a supervised apt upgrade job. IN-MEMORY only."""
import json
import unittest
from types import SimpleNamespace
from tests.integration.test_collection import FakeIO

SIM = ('NOTE: This is only a simulation!\nInst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates [amd64])\n'
       'Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates [amd64])\n'
       'Conf openssl (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates [amd64])\n')


class CollectorFactsTests(unittest.TestCase):
    def collect(self, *, sim=SIM, holds='', reboot=True, age=3600):
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io = FakeIO()
        command = io.command
        io.command = lambda key: (SimpleNamespace(returncode=0, stdout=sim) if key == 'apt_upgrade_sim' else
                                  SimpleNamespace(returncode=0, stdout=holds) if key == 'apt_holds' else command(key))
        read = io.read_file

        def read_file(path):
            if path == '/run/reboot-required':
                if not reboot:
                    raise FileNotFoundError(path)
                return '*** System restart required ***\n'
            return read(path)
        io.read_file = read_file
        io.apt_metadata_age = lambda: age
        facts = collect_observations(io, registered_firewall_manager='ufw')['1.2.2.1']
        return {k: v['value'] for k, v in facts.items()}, evaluate('1.2.2.1', facts).status.value

    def test_pending_updates_are_a_confirmed_failure_and_none_leave_the_manual_review(self):
        facts, status = self.collect(holds='linux-image-generic\n')
        self.assertEqual(facts, {'metadata_fresh': True, 'pending_updates': 2, 'held_packages': 1, 'reboot_required': True})
        self.assertEqual(status, 'Non-Compliant')
        facts, status = self.collect(sim='Reading package lists...\n', reboot=False)
        self.assertEqual((facts['pending_updates'], facts['reboot_required'], status), (0, False, 'Unknown'))
        facts, _ = self.collect(age=8 * 86400)
        self.assertFalse(facts['metadata_fresh'])

    def test_the_read_only_commands_never_take_the_apt_lock(self):
        from vm.ubuntu.collector import COMMANDS
        self.assertEqual(COMMANDS['apt_upgrade_sim'], ('/usr/bin/apt-get', '-s', '-q', '-o', 'Debug::NoLocking=1', 'upgrade'))
        self.assertEqual(COMMANDS['apt_holds'], ('/usr/bin/apt-mark', 'showhold'))


class FakePatchApt:
    def __init__(self, pending=('openssl', 'libssl3'), holds=(), broken=False, update_fails=False):
        self.pending, self.holds, self.broken, self.update_fails = list(pending), list(holds), broken, update_fails
        self.calls = []

    def upgrade_plan(self):
        return {'pending': sorted(self.pending), 'held': sorted(self.holds)}

    def dpkg_broken(self):
        return self.broken

    def apt_update(self):
        self.calls.append('update')
        if self.update_fails:
            raise OSError('apt-get update failed')
        self.pending.append('tzdata')  # fresh lists reveal one more update

    def apt_upgrade(self):
        self.calls.append('upgrade')
        self.pending = []


class PatchFamilyTests(unittest.TestCase):
    PARAMS = {'upgrade': 'apt-get upgrade'}

    def family(self, system):
        from vm.ubuntu.family_patch import PatchFamily
        return PatchFamily(system)

    def test_update_then_upgrade_leaves_nothing_pending_and_keeps_holds(self):
        system = FakePatchApt(holds=['linux-image-generic'])
        family = self.family(system)
        family.validate(self.PARAMS)
        family.check_eligible(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        self.assertEqual(system.calls, ['update', 'upgrade'])
        self.assertEqual((family.supervision, family.max_seconds), ('job', 1800))
        summary = json.dumps(family.summary(self.PARAMS, before)).lower()
        for word in ('snapshot', 'manual', 'reboot'):
            self.assertIn(word, summary)

    def test_restore_is_refused_honestly(self):
        with self.assertRaisesRegex(ValueError, 'snapshot'):
            self.family(FakePatchApt()).restore(self.PARAMS, b'{}')

    def test_broken_dpkg_state_or_other_parameters_are_refused(self):
        with self.assertRaises(ValueError):self.family(FakePatchApt(broken=True)).check_eligible(self.PARAMS)
        for bad in ({'upgrade': 'apt-get dist-upgrade'}, {}, {'upgrade': 'apt-get upgrade', 'x': 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):self.family(FakePatchApt()).validate(bad)
        with self.assertRaises(OSError):self.family(FakePatchApt(update_fails=True)).apply(self.PARAMS)

    def test_registry_agrees_and_planner_needs_pending_updates_with_fresh_metadata(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target, spec = build(FakeCoreSystem())['ubuntu.1.2.2.1.v1'], FAMILIES['ubuntu.1.2.2.1.v1']
        self.assertEqual((spec.version, spec.implementation_sha256), (target.version, target.implementation_sha256))
        self.assertEqual(spec.recovery['kind'], 'snapshot_restore')
        ev = evidence(['1.2.2.1'])
        obs = cases()
        key, value = FAILURES['1.2.2.1']
        obs['1.2.2.1'][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertEqual(spec.propose('1.2.2.1', ev), self.PARAMS)
        obs['1.2.2.1']['metadata_fresh'] = {'state': 'error', 'value': None}
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(spec.propose('1.2.2.1', ev))
