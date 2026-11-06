"""UFW default-deny family for CIS 4.1.7 (pp.440-441) with the CIS-listed outbound allowances. IN-MEMORY ufw model."""
import json
import unittest

SSH_IN = 'allow tcp 22 0.0.0.0/0 any 192.168.56.1 in'
PARAMS = {'defaults': 'deny', 'allow_out': ['53', '80/tcp', '123/udp', '443/tcp', '853']}


class FakeUfw:
    """ufw's own records: `### tuple ###` lines in user.rules/user6.rules; v6 twins only when IPV6=yes."""
    def __init__(self, defaults=None, rules4=(SSH_IN,), rules6=(), ipv6=True, active=True, fail_on=None):
        self.defaults = dict(defaults or {'incoming': 'deny', 'outgoing': 'allow', 'routed': 'disabled'})
        self.rules4, self.rules6, self.ipv6, self.active = list(rules4), list(rules6), ipv6, active
        self.fail_on, self.calls = fail_on, []

    def ufw_state(self):
        return {'active': self.active, 'ipv6': self.ipv6, 'defaults': dict(self.defaults),
                'rules4': list(self.rules4), 'rules6': list(self.rules6)}

    def ufw(self, args):
        self.calls.append(tuple(args))
        if self.fail_on and tuple(args) == self.fail_on:
            raise OSError('ufw refused')
        if args[0] == 'default':
            self.defaults[{'incoming': 'incoming', 'outgoing': 'outgoing', 'routed': 'routed'}[args[2]]] = args[1]
            return
        delete = args[0] == 'delete'
        rule = args[1:] if delete else args
        port = rule[2]
        proto = port.split('/')[1] if '/' in port else 'any'
        number = port.split('/')[0]
        for rules, net in ((self.rules4, '0.0.0.0/0'), (self.rules6, '::/0') if self.ipv6 else (None, None)):
            if rules is None:
                continue
            line = 'allow %s %s %s any %s out' % (proto, number, net, net)
            if delete:
                rules.remove(line)
            elif line not in rules:
                rules.append(line)


class UfwDefaultDenyTests(unittest.TestCase):
    def family(self, system):
        from vm.ubuntu.family_ufw import UfwDefaultDenyFamily
        return UfwDefaultDenyFamily(system)

    def cycle(self, system):
        family = self.family(system)
        family.validate(PARAMS)
        family.check_eligible(PARAMS)
        before = family.read_state(PARAMS)
        expected = family.expected_after(PARAMS, before)
        family.apply(PARAMS)
        self.assertEqual(family.read_state(PARAMS), expected)
        return family, before

    def test_only_the_approved_site_profile(self):
        family = self.family(FakeUfw())
        for bad in (dict(PARAMS, defaults='reject'), dict(PARAMS, allow_out=['53']), dict(PARAMS, allow_out=PARAMS['allow_out'] + ['22']),
                    {}, dict(PARAMS, extra=1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)

    def test_outbound_allowances_come_first_then_only_allow_defaults_become_deny(self):
        system = FakeUfw()
        family, before = self.cycle(system)
        self.assertEqual(system.defaults, {'incoming': 'deny', 'outgoing': 'deny', 'routed': 'disabled'})
        defaults_at = [i for i, call in enumerate(system.calls) if call[0] == 'default']
        rules_at = [i for i, call in enumerate(system.calls) if call[0] == 'allow']
        self.assertEqual(len(rules_at), 5)
        self.assertLess(max(rules_at), min(defaults_at))  # outbound is never fully blocked
        self.assertEqual(system.calls[defaults_at[0]], ('default', 'deny', 'outgoing'))
        self.assertEqual(len(defaults_at), 1)  # incoming already deny, routed disabled: untouched
        self.assertIn('allow udp 123 ::/0 any ::/0 out', system.rules6)
        self.assertEqual(system.rules4[0], SSH_IN)
        summary = family.summary(PARAMS, before)
        self.assertEqual(summary['defaults_changed'], {'outgoing': ['allow', 'deny']})
        self.assertIn('confirm', json.dumps(summary).lower())

    def test_restore_returns_policies_and_removes_only_what_was_added(self):
        existing = 'allow any 53 0.0.0.0/0 any 0.0.0.0/0 out'
        system = FakeUfw(rules4=(SSH_IN, existing), ipv6=False)
        family, before = self.cycle(system)
        self.assertEqual(system.rules4.count(existing), 1)  # an existing equal rule is not added twice
        family.restore(PARAMS, before)
        self.assertEqual(family.read_state(PARAMS), before)
        self.assertEqual(system.rules4, [SSH_IN, existing])  # the pre-existing DNS rule stays
        self.assertNotIn(('delete', 'allow', 'out', '53'), system.calls)

    def test_inactive_ufw_or_a_lockout_risk_is_refused(self):
        for system in (FakeUfw(active=False),
                       FakeUfw(defaults={'incoming': 'allow', 'outgoing': 'allow', 'routed': 'disabled'}, rules4=())):
            with self.subTest(), self.assertRaises(ValueError):self.family(system).check_eligible(PARAMS)
        # With an SSH allow rule, switching incoming to deny keeps the management channel.
        self.cycle(FakeUfw(defaults={'incoming': 'allow', 'outgoing': 'allow', 'routed': 'allow'}))

    def test_a_failed_ufw_command_is_raised_for_the_watchdog_to_roll_back(self):
        system = FakeUfw(fail_on=('default', 'deny', 'outgoing'))
        with self.assertRaises(OSError):self.family(system).apply(PARAMS)

    def test_the_family_is_a_commit_confirm_job(self):
        family = self.family(FakeUfw())
        self.assertEqual((family.supervision, family.confirm_seconds), ('confirm', 600))


class UfwParsingTests(unittest.TestCase):
    def test_user_rules_tuples_and_status_defaults(self):
        from vm.ubuntu.family_ufw import parse_defaults, parse_tuples
        text = '*filter\n### tuple ### allow tcp 22 0.0.0.0/0 any 192.168.56.1 in\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n'
        self.assertEqual(parse_tuples(text), ['allow tcp 22 0.0.0.0/0 any 192.168.56.1 in'])
        status = 'Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n'
        self.assertEqual(parse_defaults(status), (True, {'incoming': 'deny', 'outgoing': 'allow', 'routed': 'disabled'}))
        self.assertEqual(parse_defaults('Status: inactive\n'), (False, None))


class UfwRegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_planner_needs_registered_active_ufw(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        action = 'ubuntu.4.1.7.v1'
        self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                         (target[action].version, target[action].implementation_sha256))
        ev = evidence(['4.1.7'])
        obs = cases()
        key, value = FAILURES['4.1.7']
        obs['4.1.7'][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertEqual(FAMILIES[action].propose('4.1.7', ev), PARAMS)
        obs['4.1.7']['firewall_manager'] = {'state': 'missing', 'value': None}
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES[action].propose('4.1.7', ev))
