"""UFW enable (CIS 4.1.3, p.429) and loopback rules (CIS 4.1.4, p.433) families, commit-confirm. IN-MEMORY ufw."""
import json
import unittest
from tests.integration.test_ubuntu_ufw_loopback import CIS4, CIS6, LO_IN4, LO_OUT4, SPOOF4, SSH_FROM_HOST

TUPLES = {('allow', 'in', 'on', 'lo'): [('rules4', LO_IN4), ('rules6', 'allow any any ::/0 any ::/0 in_lo')],
          ('allow', 'out', 'on', 'lo'): [('rules4', LO_OUT4), ('rules6', 'allow any any ::/0 any ::/0 out_lo')],
          ('deny', 'in', 'from', '127.0.0.0/8'): [('rules4', SPOOF4)],
          ('deny', 'in', 'from', '::1'): [('rules6', 'deny any any ::/0 any ::1 in')]}


class FakeFirewall:
    def __init__(self, rules4=(SSH_FROM_HOST,), rules6=(), ipv6=True, kernel_ipv6=True, active=True,
                 unit=None):
        self.rules4, self.rules6, self.ipv6, self.kernel, self.active = list(rules4), list(rules6), ipv6, kernel_ipv6, active
        self.unit = dict(unit or {'load': 'loaded', 'enabled': 'enabled', 'active': 'active'})
        self.calls = []

    def ufw_state(self):
        return {'active': self.active, 'ipv6': self.ipv6, 'rules4': list(self.rules4), 'rules6': list(self.rules6),
                'defaults': {'incoming': 'deny', 'outgoing': 'allow', 'routed': 'disabled'} if self.active else None}

    def kernel_ipv6(self):
        return self.kernel

    def unit_state(self, unit):
        assert unit == 'ufw.service'
        return dict(self.unit)

    def systemctl(self, verb, unit):
        self.calls.append(('systemctl', verb))
        self.unit.update({'unmask': {'enabled': 'disabled'}, 'enable': {'enabled': 'enabled'}, 'start': {'active': 'active'},
                          'stop': {'active': 'inactive'}, 'disable': {'enabled': 'disabled'},
                          'mask': {'enabled': 'masked'}}[verb])

    def ufw(self, args):
        self.calls.append(tuple(args))
        if tuple(args) == ('--force', 'enable'):
            self.active = True
            return
        if tuple(args) == ('disable',):
            self.active = False
            return
        delete, prepend = args[0] == 'delete', args[0] == 'prepend'  # `ufw prepend`: to the top of each list
        for key, line in TUPLES[tuple(args[1:] if delete or prepend else args)]:
            rules = getattr(self, key)
            if key == 'rules6' and not self.ipv6:
                continue
            if delete:
                rules.remove(line)
            elif line not in rules:
                rules.insert(0, line) if prepend else rules.append(line)


class Case(unittest.TestCase):
    CLASS, PARAMS = None, None

    def family(self, system):
        import vm.ubuntu.family_ufw as module
        return getattr(module, self.CLASS)(system)

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


class LoopbackTests(Case):
    CLASS, PARAMS = 'UfwLoopbackFamily', {'rules': 'cis-loopback'}

    def test_cis_rules_are_appended_in_order_and_resolve_as_cis_audits_them(self):
        from vm.ubuntu.probes import ufw_loopback
        system = FakeFirewall()
        family, before = self.cycle(system)
        self.assertEqual(system.rules4, [SSH_FROM_HOST] + [LO_IN4, LO_OUT4, SPOOF4])
        expected = {'loopback_in': 'allow', 'loopback_out': 'allow', 'spoofed_in': 'deny'}
        self.assertEqual(ufw_loopback(system.rules4, system.rules6), {'ipv4': expected, 'ipv6': expected})
        self.assertEqual((family.supervision, family.confirm_seconds), ('confirm', 600))
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)

    def test_existing_rules_are_kept_and_not_deleted_on_restore(self):
        lo_in6 = 'allow any any ::/0 any ::/0 in_lo'
        system = FakeFirewall(rules4=[SSH_FROM_HOST, LO_IN4], rules6=[lo_in6])
        family, before = self.cycle(system)
        self.assertEqual(system.rules4.count(LO_IN4), 1)
        self.assertNotIn(('allow', 'in', 'on', 'lo'), system.calls)
        family.restore(self.PARAMS, before)
        self.assertEqual((system.rules4, system.rules6), ([SSH_FROM_HOST, LO_IN4], [lo_in6]))

    def test_a_half_present_rule_is_refused_because_ufw_delete_removes_both_twins(self):
        # Adding the missing IPv6 twin is possible, but restoring it would also delete the existing IPv4 rule.
        self.refused(FakeFirewall(rules4=[SSH_FROM_HOST, LO_IN4]))

    def test_refused_when_appending_cannot_make_it_comply(self):
        open_ssh = 'allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in'   # an earlier partial allow keeps spoofed traffic mixed
        for system in (FakeFirewall(rules4=[open_ssh]), FakeFirewall(rules4=[SPOOF4]),  # deny before the lo allow
                       FakeFirewall(active=False), FakeFirewall(ipv6=False, kernel_ipv6=True),
                       FakeFirewall(rules4=[SSH_FROM_HOST] + CIS4, rules6=CIS6)):    # nothing to do
            with self.subTest(rules=system.rules4, ipv6=system.ipv6), self.assertRaises(ValueError):
                self.family(system).check_eligible(self.PARAMS)
        system = FakeFirewall(ipv6=False, kernel_ipv6=False)  # IPv6 off everywhere: IPv4 rules only
        self.cycle(system)
        self.assertNotIn(('deny', 'in', 'from', '::1'), system.calls)


class EnableTests(Case):
    CLASS, PARAMS = 'UfwEnableFamily', {'enable': True}

    def test_enables_service_and_firewall_and_restores_exactly(self):
        system = FakeFirewall(active=False, unit={'load': 'loaded', 'enabled': 'masked', 'active': 'inactive'})
        family, before = self.cycle(system)
        self.assertEqual(system.calls, [('systemctl', 'unmask'), ('systemctl', 'enable'), ('systemctl', 'start'),
                                        ('--force', 'enable')])
        self.assertTrue(system.active)
        self.assertEqual((family.supervision, family.confirm_seconds), ('confirm', 600))
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)

    def test_never_enabled_when_not_installed_or_already_on(self):
        # Without an SSH allow rule it now adds `ufw allow 22/tcp` itself (test_ubuntu_auto_steps_1113, 2026-11-13).
        for system in (FakeFirewall(active=False, unit={'load': 'not-found', 'enabled': 'not-found', 'active': 'inactive'}),
                       FakeFirewall()):  # already enabled and active: nothing to do
            with self.subTest(unit=system.unit, rules=system.rules4), self.assertRaises(ValueError):
                self.family(system).check_eligible(self.PARAMS)
        with self.assertRaises(ValueError):self.family(FakeFirewall()).validate({'enable': 1})


class RegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_planners_need_their_facts(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        expected = {'4.1.3': {'enable': True}, '4.1.4': {'rules': 'cis-loopback'}}
        ev = evidence(list(expected))
        obs = cases()
        for cid in expected:
            key, value = FAILURES[cid]
            obs[cid][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        for cid, params in expected.items():
            action = 'ubuntu.%s.v1' % cid
            self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
            self.assertEqual(FAMILIES[action].propose(cid, ev), params, cid)
        obs['4.1.4']['ufw_rule_resolution'] = observation('unsupported')
        obs['4.1.3']['package.ufw'] = observation('absent')
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES['ubuntu.4.1.4.v1'].propose('4.1.4', ev))
        self.assertIsNone(FAMILIES['ubuntu.4.1.3.v1'].propose('4.1.3', ev))
