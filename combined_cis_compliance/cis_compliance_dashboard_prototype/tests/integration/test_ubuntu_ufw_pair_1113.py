"""4.1.4 and 4.1.7 approved and executed in one round (administrator, 13 November 2026).

Before: both fixes recorded the whole UFW configuration as their before-state, so whichever ran second was stale,
and the dashboard refused the second approval ("4.1.7 changes the same file as 4.1.4 ... execute 4.1.4 first, then
start a new round"). Now, as the sysctl, sshd, sudo and login.defs fixes since 11 November, each records only its own
part: 4.1.7 the default policies and its five outbound rules, 4.1.4 its four loopback rules and whether they go in
front. Neither changes the other's part, so both can be approved together, run in either order (the second stacked
on the first, confirmed over one login), and each restore takes back only its own rules.
IN-MEMORY ufw; the VM is never contacted.
"""
import json
import unittest
from datetime import timedelta
from types import SimpleNamespace as N

from tests.integration.test_ubuntu_ufw_family import FakeUfw, PARAMS as DENY
from tests.integration.test_ubuntu_ufw_enable_loopback import TUPLES

SSH4, SSH6 = 'allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in', 'allow tcp 22 ::/0 any ::/0 in'
LOOP = {'rules': 'cis-loopback'}


class PairUfw(FakeUfw):
    """One ufw model both families act on: outbound rules and defaults (4.1.7), loopback rules (4.1.4)."""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kernel = True

    def kernel_ipv6(self):
        return self.kernel

    def ufw(self, args):
        delete, prepend = args[0] == 'delete', args[0] == 'prepend'
        rule = tuple(args[1:] if delete or prepend else args)
        if rule not in TUPLES:
            return super().ufw(args)
        self.calls.append(tuple(args))
        for key, line in TUPLES[rule]:
            if key == 'rules6' and not self.ipv6:
                continue
            rules = getattr(self, key)
            if delete:
                rules.remove(line)
            elif line not in rules:
                rules.insert(0, line) if prepend else rules.append(line)


def families(system):
    from vm.ubuntu.family_ufw import UfwDefaultDenyFamily, UfwLoopbackFamily
    return UfwLoopbackFamily(system), UfwDefaultDenyFamily(system)


class PairTests(unittest.TestCase):
    def system(self):
        return PairUfw(rules4=(SSH4,), rules6=(SSH6,))  # after 4.1.3: an SSH allow rule from anywhere

    def test_either_order_leaves_the_other_fix_valid_and_both_comply(self):
        from vm.ubuntu.probes import ufw_loopback
        for first in ('4.1.4', '4.1.7'):
            with self.subTest(first=first):
                system = self.system()
                loop, deny = families(system)
                loop.check_eligible(LOOP)
                deny.check_eligible(DENY)
                before = {'4.1.4': loop.read_state(LOOP), '4.1.7': deny.read_state(DENY)}
                expected = {'4.1.4': loop.expected_after(LOOP, before['4.1.4']),
                            '4.1.7': deny.expected_after(DENY, before['4.1.7'])}
                order = [(loop, LOOP, '4.1.4'), (deny, DENY, '4.1.7')]
                if first == '4.1.7':
                    order.reverse()
                (one, one_params, one_id), (two, two_params, two_id) = order
                one.apply(one_params)
                self.assertEqual(one.read_state(one_params), expected[one_id])
                # The second fix's approved before-state still holds: before, it was stale here.
                self.assertEqual(two.read_state(two_params), before[two_id])
                two.check_eligible(two_params)
                two.apply(two_params)
                self.assertEqual(two.read_state(two_params), expected[two_id])
                self.assertEqual(one.read_state(one_params), expected[one_id])
                good = {'loopback_in': 'allow', 'loopback_out': 'allow', 'spoofed_in': 'deny'}
                self.assertEqual(ufw_loopback(system.rules4, system.rules6), {'ipv4': good, 'ipv6': good})
                self.assertEqual(system.defaults, {'incoming': 'deny', 'outgoing': 'deny', 'routed': 'disabled'})

    def test_each_restore_takes_back_only_its_own_part_in_any_order(self):
        for first in ('4.1.4', '4.1.7'):
            with self.subTest(first=first):
                system = self.system()
                original = json.dumps(system.ufw_state(), sort_keys=True)
                loop, deny = families(system)
                before = {'4.1.4': loop.read_state(LOOP), '4.1.7': deny.read_state(DENY)}
                loop.apply(LOOP)
                deny.apply(DENY)
                after = {'4.1.4': loop.read_state(LOOP), '4.1.7': deny.read_state(DENY)}
                pairs = [(loop, LOOP, '4.1.4', deny, DENY, '4.1.7'), (deny, DENY, '4.1.7', loop, LOOP, '4.1.4')]
                one, one_params, one_id, two, two_params, two_id = pairs[0 if first == '4.1.4' else 1]
                one.restore(one_params, before[one_id])
                self.assertEqual(one.read_state(one_params), before[one_id])
                self.assertEqual(two.read_state(two_params), after[two_id])  # untouched by the other's restore
                two.restore(two_params, before[two_id])
                self.assertEqual(json.dumps(system.ufw_state(), sort_keys=True), original)

    def test_rules_that_existed_before_survive_both_restores(self):
        lo4, lo6 = 'allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo', 'allow any any ::/0 any ::/0 in_lo'
        dns4, dns6 = 'allow any 53 0.0.0.0/0 any 0.0.0.0/0 out', 'allow any 53 ::/0 any ::/0 out'
        system = PairUfw(rules4=(SSH4, lo4, dns4), rules6=(SSH6, lo6, dns6))
        original = json.dumps(system.ufw_state(), sort_keys=True)
        loop, deny = families(system)
        before = {'4.1.4': loop.read_state(LOOP), '4.1.7': deny.read_state(DENY)}
        loop.apply(LOOP)
        deny.apply(DENY)
        self.assertNotIn(('delete', 'allow', 'in', 'on', 'lo'), system.calls)
        deny.restore(DENY, before['4.1.7'])
        loop.restore(LOOP, before['4.1.4'])
        self.assertEqual(json.dumps(system.ufw_state(), sort_keys=True), original)  # the administrator's rules stay

    def test_the_summaries_still_say_what_each_will_do(self):
        system = self.system()
        loop, deny = families(system)
        loop_summary = loop.summary(LOOP, loop.read_state(LOOP))
        self.assertEqual(loop_summary['commands'][0], 'ufw prepend allow in on lo')
        self.assertIn('in front', loop_summary['order'])
        deny_summary = deny.summary(DENY, deny.read_state(DENY))
        self.assertEqual(deny_summary['defaults_changed'], {'outgoing': ['allow', 'deny']})
        self.assertEqual(deny_summary['allow_out_added'], DENY['allow_out'])


class RunnerPairTests(unittest.TestCase):
    """The runner itself: 4.1.4 applied and waiting, 4.1.7 stacked on it (its fresh read-set check passes now)."""

    def test_the_second_fix_is_stacked_on_the_first_and_both_are_confirmed(self):
        import tempfile
        from pathlib import Path
        from backends.ubuntu.actions import ActionSpec, plan_action
        from backends.ubuntu.approvals import approve
        from vm.ubuntu.runner import Runner
        from tests.integration.test_ubuntu_runner import NOW, sha
        from tests.integration.test_ubuntu_supervision import FakeLauncher, outcome
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        system, launcher = PairUfw(rules4=(SSH4,), rules6=(SSH6,)), FakeLauncher()
        loop, deny = families(system)
        runner = Runner(Path(folder.name), {loop.action_id: loop, deny.action_id: deny},
                        lambda: ('a' * 32, 'ubuntu-fixture'), clock=lambda: NOW + timedelta(minutes=1),
                        require_root_owned=False, launcher=launcher)

        def approved(family, params, control):
            spec = ActionSpec(family.action_id, family.version, family.implementation_sha256, (control,),
                              family.validate, 120)
            current = family.read_state(params)
            plan = plan_action(spec, families={spec.action_id: spec}, target_id='ubuntu:fixture',
                               registration_epoch='epoch', hostname='UBUNTU-FIXTURE', machine_id='a' * 32,
                               workflow_session_id='1' * 32, round_id='2' * 32, evidence_sha256='e' * 64,
                               control_id=control, predicate_id='ubuntu.%s.predicate.v1' % control, parameters=params,
                               before_state_sha256=sha(current),
                               expected_after_sha256=sha(family.expected_after(params, current)),
                               before_state_collected_at=(NOW - timedelta(minutes=1)).isoformat(),
                               recovery={'kind': 'restore_backup', 'scope': ['/etc/ufw/user.rules']},
                               job_deadline_seconds=120)
            return approve(plan, 'fixture-operator', NOW)
        first, second = approved(loop, LOOP, '4.1.4'), approved(deny, DENY, '4.1.7')  # both approved at once
        r1, r2 = first.request['request_id'], second.request['request_id']
        runner.execute(first.raw)
        runner.run_job(r1)
        launcher.active.discard(r1)
        self.assertEqual(outcome(runner.reconcile(r1)), ('running', 'awaiting_confirmation'))
        self.assertEqual(outcome(runner.execute(second.raw)), ('running', 'job_started'))  # before: stale_read_set
        runner.run_job(r2)
        launcher.active.discard(r2)
        self.assertEqual(outcome(runner.confirm(r1)), ('applied', 'confirmed'))
        self.assertEqual(outcome(runner.confirm(r2)), ('applied', 'confirmed'))


class ApprovalPairTests(unittest.TestCase):
    def proposal(self, control, scope, pid):
        payload = {'proposal_id': pid, 'action': {'action_id': 'ubuntu.%s.v1' % control},
                   'fields': {'control_id': control, 'recovery': {'scope': scope}}}
        return N(payload=payload, decision='approved', receipts=())

    def test_the_pair_may_be_approved_together_but_not_with_enabling_ufw(self):
        from backends.ubuntu.adapter import shared_file_conflict
        files = ['/etc/default/ufw', '/etc/ufw/user.rules', '/etc/ufw/user6.rules']
        loop, deny = self.proposal('4.1.4', files, 'p4'), self.proposal('4.1.7', files, 'p7')
        enable = self.proposal('4.1.3', files + ['systemd:ufw.service'], 'p3')
        self.assertIsNone(shared_file_conflict(deny.payload, [loop]))  # before: '4.1.4'
        self.assertIsNone(shared_file_conflict(loop.payload, [deny]))
        self.assertEqual(shared_file_conflict(deny.payload, [enable]), '4.1.3')  # enabling still reads all rules


if __name__ == '__main__':
    unittest.main()
