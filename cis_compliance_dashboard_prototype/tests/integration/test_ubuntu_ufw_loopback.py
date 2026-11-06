"""UFW loopback resolver (CIS 4.1.4, p.433) from ufw's ordered user-rule records, and its collector wiring."""
import unittest
from tests.integration.test_collection import FakeIO

LO_IN4, LO_OUT4 = 'allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo', 'allow any any 0.0.0.0/0 any 0.0.0.0/0 out_lo'
SPOOF4 = 'deny any any 0.0.0.0/0 any 127.0.0.0/8 in'
LO_IN6, LO_OUT6, SPOOF6 = 'allow any any ::/0 any ::/0 in_lo', 'allow any any ::/0 any ::/0 out_lo', 'deny any any ::/0 any ::1 in'
SSH_FROM_HOST = 'allow tcp 22 0.0.0.0/0 any 192.168.56.1 in'
CIS4, CIS6 = [LO_IN4, SPOOF4, LO_OUT4], [LO_IN6, SPOOF6, LO_OUT6]


class ResolverTests(unittest.TestCase):
    def resolve(self, rules4, rules6=()):
        from vm.ubuntu.probes import ufw_loopback
        return ufw_loopback(list(rules4), list(rules6))

    def test_cis_rules_resolve_to_the_expected_first_matching_actions(self):
        result = self.resolve([SSH_FROM_HOST] + CIS4, CIS6)
        expected = {'loopback_in': 'allow', 'loopback_out': 'allow', 'spoofed_in': 'deny'}
        self.assertEqual(result, {'ipv4': expected, 'ipv6': expected})

    def test_no_explicit_rule_is_none_and_order_matters(self):
        self.assertEqual(self.resolve([SSH_FROM_HOST])['ipv4'],
                         {'loopback_in': 'none', 'loopback_out': 'none', 'spoofed_in': 'none'})
        # The spoof deny first also catches loopback traffic: CIS lists the lo allow first for this reason.
        self.assertEqual(self.resolve([SPOOF4, LO_IN4, LO_OUT4])['ipv4']['loopback_in'], 'deny')

    def test_an_earlier_partial_rule_with_another_action_is_mixed(self):
        open_ssh = 'allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in'  # also admits spoofed 127.x to port 22 on eth0
        result = self.resolve([open_ssh] + CIS4)['ipv4']
        self.assertEqual((result['spoofed_in'], result['loopback_in']), ('mixed', 'allow'))
        self.assertEqual(self.resolve(['deny any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0'] + CIS4)['ipv4']['spoofed_in'], 'deny')

    def test_unparseable_records_are_refused(self):
        for bad in ('allow any', 'allow any any 0.0.0.0/0 any not-an-address in'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):self.resolve([bad])
        self.assertEqual(self.resolve([LO_IN4 + ' comment=\'loopback\'', 'route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in'] + CIS4)
                         ['ipv4']['loopback_in'], 'allow')


class CollectorWiringTests(unittest.TestCase):
    def collect(self, rules4, rules6):
        from vm.ubuntu.collection import collect_observations
        from backends.ubuntu.predicates import evaluate
        io = FakeIO()
        files = {'/etc/ufw/user.rules': ''.join('### tuple ### %s\n' % r for r in rules4),
                 '/etc/ufw/user6.rules': ''.join('### tuple ### %s\n' % r for r in rules6)}
        original = io.read_file
        io.read_file = lambda path: files[path] if path in files else original(path)
        facts = collect_observations(io, registered_firewall_manager='ufw')['4.1.4']
        return facts, evaluate('4.1.4', facts).status.value

    def test_resolved_rules_make_4_1_4_decidable(self):
        facts, status = self.collect([SSH_FROM_HOST] + CIS4, CIS6)
        self.assertEqual((facts['ufw_rule_resolution']['value'], status), ('complete', 'Compliant'))
        facts, status = self.collect([SSH_FROM_HOST], [])
        self.assertEqual((facts['ufw.ipv4.loopback_in']['value'], status), ('none', 'Non-Compliant'))

    def test_the_rule_files_are_on_the_collector_allowlist(self):
        from vm.ubuntu.collector import FILES
        self.assertLessEqual({'/etc/ufw/user.rules', '/etc/ufw/user6.rules'}, FILES)
