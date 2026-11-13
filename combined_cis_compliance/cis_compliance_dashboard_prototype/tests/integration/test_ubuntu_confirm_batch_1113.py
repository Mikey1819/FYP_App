"""One fresh login confirms all the SSH/UFW changes of an execution (administrator, 13 November 2026).

Before: the runner and the host ledger allowed one open change per server, so each commit-confirm change (4.1.3,
5.1.7, 5.1.16, 5.1.20) was applied, confirmed over its own fresh login, and only then was the next one sent. Now a
commit-confirm change may be stacked on others that are applied and waiting for their confirmation: each keeps its
own rollback timer and its own before-state, and one fresh login made after the last one confirms them all. A change
is only stacked when its fresh read-set check passed after the others were applied (so their files are disjoint and
the rollbacks are independent), never on a change still running, and never a job or in-session write.
TEST-ONLY families, fake launcher and fake server; the VM is never contacted.
"""
import json
import unittest
from datetime import timedelta
from types import SimpleNamespace as N
from unittest import mock

from tests.integration import test_ubuntu_execution_continue_ui as continue_ui
from tests.integration.runner_fixture import FileValueFamily
from tests.integration.test_ubuntu_runner import NOW, sha
from tests.integration.test_ubuntu_supervision import ConfirmFamily, FakeLauncher, JobFamily, SupervisionCase, outcome


class SecondConfirmFamily(ConfirmFamily):
    action_id = 'fixture.confirm.v2'


class StackCase(SupervisionCase):
    FAMILY = ConfirmFamily

    def setUp(self):
        super().setUp()
        (self.work / 'beta').write_bytes(b'old')
        self.second = SecondConfirmFamily(self.work)

    def approved_for(self, family, name):
        from backends.ubuntu.actions import ActionSpec, plan_action
        from backends.ubuntu.approvals import approve
        spec = ActionSpec(family.action_id, 1, family.implementation_sha256, ('1.5.1',), family.validate, 60)
        params = {'name': name, 'value': 'new'}
        plan = plan_action(spec, families={spec.action_id: spec}, target_id='ubuntu:fixture', registration_epoch='epoch',
                           hostname='UBUNTU-FIXTURE', machine_id='a' * 32, workflow_session_id='1' * 32,
                           round_id='2' * 32, evidence_sha256='e' * 64, control_id='1.5.1',
                           predicate_id='ubuntu.1.5.1.predicate.v1', parameters=params,
                           before_state_sha256=sha(family.read_state(params)), expected_after_sha256=sha(b'new'),
                           before_state_collected_at=(NOW - timedelta(minutes=1)).isoformat(),
                           recovery={'kind': 'restore_backup', 'scope': ['fixture:' + name]}, job_deadline_seconds=60)
        return approve(plan, 'fixture-operator', NOW)

    def runner(self, *families):
        from vm.ubuntu.runner import Runner
        families = families or (self.family, self.second)
        return Runner(self.state, {f.action_id: f for f in families}, lambda: ('a' * 32, 'ubuntu-fixture'),
                      clock=lambda: NOW + timedelta(minutes=1), require_root_owned=False, launcher=self.launcher)

    def fence(self):
        path = self.state / 'active'
        return path.read_text(encoding='ascii') if path.exists() else None

    def waiting_pair(self):
        """A applied and waiting, then B stacked on it, applied and waiting too."""
        a, b = self.approved_for(self.family, 'alpha'), self.approved_for(self.second, 'beta')
        runner = self.runner()
        ra, rb = a.request['request_id'], b.request['request_id']
        runner.execute(a.raw)
        self.job(runner, ra)
        self.assertEqual(outcome(runner.reconcile(ra)), ('running', 'awaiting_confirmation'))
        self.assertEqual(outcome(runner.execute(b.raw)), ('running', 'job_started'))  # before: target_fenced
        self.assertEqual(self.fence(), rb)
        self.job(runner, rb)
        self.assertEqual(outcome(runner.reconcile(rb)), ('running', 'awaiting_confirmation'))
        self.assertEqual(outcome(runner.reconcile(ra)), ('running', 'awaiting_confirmation'))
        return runner, ra, rb


class RunnerStackTests(StackCase):
    def test_two_waiting_changes_are_confirmed_one_after_the_other(self):
        runner, ra, rb = self.waiting_pair()
        self.assertEqual(outcome(runner.confirm(ra)), ('applied', 'confirmed'))
        self.assertEqual(self.fence(), rb)  # the open one above keeps the lock
        self.assertEqual(outcome(runner.confirm(rb)), ('applied', 'confirmed'))
        self.assertIsNone(self.fence())
        self.assertEqual(((self.work / 'alpha').read_bytes(), (self.work / 'beta').read_bytes()), (b'new', b'new'))

    def test_confirming_the_top_first_hands_the_lock_back_down(self):
        runner, ra, rb = self.waiting_pair()
        self.assertEqual(outcome(runner.confirm(rb)), ('applied', 'confirmed'))
        self.assertEqual(self.fence(), ra)
        self.assertEqual(outcome(runner.confirm(ra)), ('applied', 'confirmed'))
        self.assertIsNone(self.fence())

    def test_without_a_confirmation_each_timer_restores_its_own_change_in_any_order(self):
        for first in ('a', 'b'):
            with self.subTest(first=first):
                for name in ('alpha', 'beta'):
                    (self.work / name).write_bytes(b'old')
                runner, ra, rb = self.waiting_pair()
                order = (ra, rb) if first == 'a' else (rb, ra)
                for rid in order:
                    self.assertEqual(outcome(runner.rollback(rid)), ('rolled_back', 'restored'))
                self.assertIsNone(self.fence())
                self.assertEqual(((self.work / 'alpha').read_bytes(), (self.work / 'beta').read_bytes()),
                                 (b'old', b'old'))
                import shutil
                shutil.rmtree(self.state / 'requests')

    def test_at_boot_every_unconfirmed_change_is_restored(self):
        runner, ra, rb = self.waiting_pair()
        self.assertEqual(sorted(runner.boot_rollback()), sorted([ra, rb]))
        self.assertIsNone(self.fence())
        self.assertEqual(((self.work / 'alpha').read_bytes(), (self.work / 'beta').read_bytes()), (b'old', b'old'))

    def test_never_stacked_on_a_change_still_running(self):
        a, b = self.approved_for(self.family, 'alpha'), self.approved_for(self.second, 'beta')
        runner = self.runner()
        runner.execute(a.raw)  # its job has not run yet: nothing is waiting for confirmation
        self.assertEqual(outcome(runner.execute(b.raw)), ('refused', 'target_fenced'))
        self.assertEqual(self.fence(), a.request['request_id'])

    def test_a_job_or_in_session_write_is_never_stacked(self):
        job = JobFamily(self.work)
        job.action_id = 'fixture.job.v9'
        a, b = self.approved_for(self.family, 'alpha'), self.approved_for(job, 'beta')
        runner = self.runner(self.family, job)
        ra = a.request['request_id']
        runner.execute(a.raw)
        self.job(runner, ra)
        self.assertEqual(outcome(runner.execute(b.raw)), ('refused', 'target_fenced'))
        self.assertEqual(self.fence(), ra)

    def test_a_stacked_change_refused_before_its_claim_gives_the_lock_back(self):
        a, b = self.approved_for(self.family, 'alpha'), self.approved_for(self.second, 'beta')
        runner = self.runner()
        ra = a.request['request_id']
        runner.execute(a.raw)
        self.job(runner, ra)
        (self.work / 'beta').write_bytes(b'changed meanwhile')  # its approved read-set no longer holds
        self.assertEqual(outcome(runner.execute(b.raw)), ('refused', 'stale_read_set'))
        self.assertEqual(self.fence(), ra)
        self.assertEqual(outcome(runner.confirm(ra)), ('applied', 'confirmed'))
        self.assertIsNone(self.fence())


class LedgerStackTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from system.contracts import WorkflowBinding
        from system.ledger import CoordinationLedger
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.ledger = CoordinationLedger(Path(folder.name) / 'ledger.sqlite3')
        self.binding = WorkflowBinding('w', 'ubuntu', 'ubuntu:fixture', 'epoch', 'b', '2026-11-05T00:00:00+00:00')
        self.ledger.add_binding(self.binding)

    def test_a_stacked_claim_needs_the_others_waiting_and_ownership_moves_on(self):
        first, _ = self.ledger.claim(self.binding, 'op-a', 'execution', {'request_sha256': 'a'}, mutation=True)
        self.assertTrue(first)
        with self.assertRaises(ValueError):  # running, not yet waiting for its confirmation
            self.ledger.claim(self.binding, 'op-b', 'execution', {'request_sha256': 'b'}, mutation=True, stack=True)
        self.ledger.note('op-a', 'awaiting_confirmation')
        with self.assertRaises(ValueError):  # without the stack flag: one open change, as before
            self.ledger.claim(self.binding, 'op-b', 'execution', {'request_sha256': 'b'}, mutation=True)
        second, _ = self.ledger.claim(self.binding, 'op-b', 'execution', {'request_sha256': 'b'}, mutation=True,
                                      stack=True)
        self.assertTrue(second)
        self.assertEqual(self.ledger.owner(self.binding.target_id, self.binding.registration_epoch)['operation_id'],
                         'op-a')
        self.ledger.reconcile('op-a', 'completed', detail='confirmed')
        self.assertEqual(self.ledger.owner(self.binding.target_id, self.binding.registration_epoch)['operation_id'],
                         'op-b')  # handed over: the target stays owned while op-b is open
        self.ledger.reconcile('op-b', 'completed', detail='confirmed')
        self.assertIsNone(self.ledger.owner(self.binding.target_id, self.binding.registration_epoch))


class OneLoginTests(continue_ui.ContinueUiTests):
    """Two commit-confirm fixes (1.5.1 and 3.3.1): both are sent in one execution, then one fresh login confirms
    both. The fake server runs a started job while the dashboard waits between its status checks."""

    def setUp(self):
        super().setUp()
        self.job_family = SecondConfirmFamily(self.work)  # the 3.3.1 fix now waits for a confirmation too

    def test_both_changes_are_sent_then_confirmed_over_one_fresh_login(self):
        from backends.ubuntu.adapter import UbuntuBackend
        from tests.integration.test_ubuntu_live_path import open_gate

        def server_runs_jobs(self_, seconds):
            for rid in list(self.launcher.active):
                self.job(rid)
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), \
                mock.patch.object(UbuntuBackend, '_pause', server_runs_jobs, create=True):
            app = self.page()
            for _ in range(2):
                self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
            self.model_up = False
            app.button(key='ubuntu_execute_review').click().run()
            logins = len(self._channels)
            app.button(key='ubuntu_execute').click().run()
            self.assertEqual(sorted(self.sent()), ['alpha', 'beta'])  # before: beta only after alpha's confirmation
            for _ in range(3):
                server_runs_jobs(None, 0)  # the server applies the last change meanwhile
                app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
        self.assertEqual(len(self._channels) - logins, 1)  # one fresh login for both
        from tests.integration.test_ubuntu_batched_execution_1113 import OneScanTests
        [covered] = OneScanTests.scans(self)  # one verification scan, after both confirmations
        self.assertEqual(len(covered), 2)
        self.assertEqual(len([c for c in self.runner_calls() if c.startswith(b'{"op":"confirm"')]), 2)
        self.assertEqual(((self.work / 'alpha').read_bytes(), (self.work / 'beta').read_bytes()), (b'new', b'new'))


for _name in [n for n in dir(continue_ui.ContinueUiTests) if n.startswith('test')]:
    setattr(OneLoginTests, _name, None)  # only the harness is inherited
for _name in [n for n in dir(SupervisionCase) if n.startswith('test')]:
    setattr(StackCase, _name, None)


if __name__ == '__main__':
    unittest.main()
