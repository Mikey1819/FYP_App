"""Problems 5 and 7 (Ubuntu): approve all and execute once.

Problem 5 (stored data of 10-11 November): every execution sent one fix, the first that waits (an SSH or UFW fix that
needs its confirmation after a fresh login), and the other approved fixes never ran. Now the fixes that wait run after
the others. Problem 7: once a fix that waited has settled (confirmed, or its supervised job finished), the remaining
approved, unexpired fixes of the same execution continue without a new click.

TEST-ONLY families (an in-session file value, a supervised job, a commit-confirm value) on a fake server whose 1.5.1 and
3.3.1 fail; the real runner and ledger. The VM is never contacted.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock
from tests.integration.runner_fixture import FileValueFamily
from tests.integration import test_ubuntu_supervised_backend as supervised
from tests.integration.test_ubuntu_supervision import ConfirmFamily, JobFamily


class InSessionFamily(FileValueFamily):
    action_id = 'fixture.in_session.v1'


class SecondJobFamily(JobFamily):
    action_id = 'fixture.job.v1'


def two_failures():
    """The fake server with a second failing control: net.ipv4.ip_forward=1 (3.3.1) next to ASLR 0 (1.5.1)."""
    import tests.integration.test_ubuntu_live_path as live
    original = live.fake_io_factory

    def factory(scap='pass'):
        inner = original(scap)

        def make():
            target = inner()
            command = target.command
            target.command = lambda key: (SimpleNamespace(returncode=0, stdout='1\n')
                                          if key == 'sysctl.net.ipv4.ip_forward' else command(key))
            return target
        return make
    return mock.patch.object(live, 'fake_io_factory', factory)


class ContinueCase(supervised.SupervisedBackendCase):
    # 1.5.1 first in the plan, as the agents put the highest-ranked fix first.
    FIRST, SECOND = ConfirmFamily, InSessionFamily

    def setUp(self):
        super().setUp()
        patch = two_failures()
        patch.start()
        self.addCleanup(patch.stop)
        self.first, self.second = self.FIRST(self.work), self.SECOND(self.work)
        self.FIX = [{'control_id': '1.5.1', 'decision': 'fix', 'action_id': self.first.action_id,
                     'reason_code': 'highest_risk'},
                    {'control_id': '3.3.1', 'decision': 'fix', 'action_id': self.second.action_id,
                     'reason_code': 'highest_risk'}]

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.runner import Runner
        families = {f.action_id: f for f in (self.first, self.second)}
        return Runner(self.state, families, lambda: identity or ('a' * 32, 'ubuntu-fixture'),
                      clock=clock or self.clock, require_root_owned=False, launcher=self.launcher)

    def backend(self, decisions):
        from backends.ubuntu.actions import ActionSpec
        backend = super().backend(decisions)
        backend.families = {
            self.first.action_id: ActionSpec(self.first.action_id, 1, self.first.implementation_sha256, ('1.5.1',),
                                             self.first.validate, 60, propose=lambda c, e: {'name': 'alpha', 'value': 'new'},
                                             title='TEST-ONLY first', recovery={'kind': 'restore_backup', 'scope': ['f:a']}),
            self.second.action_id: ActionSpec(self.second.action_id, 1, self.second.implementation_sha256, ('3.3.1',),
                                              self.second.validate, 60, propose=lambda c, e: {'name': 'beta', 'value': 'new'},
                                              title='TEST-ONLY second', recovery={'kind': 'restore_backup', 'scope': ['f:b']})}
        return backend

    def approve(self, backend, workflow, controls):
        snap = backend.snapshot('c', workflow)
        for p in snap.proposals:
            if p.control_id in controls:
                backend.decide('c', workflow, p.reference, True, 'fixture-operator', '', 'op-d-' + p.control_id)
        snap = backend.snapshot('c', workflow)
        return snap.current_round_reference, {p.control_id: p.approved_request_id for p in snap.proposals
                                              if p.approved_request_id}

    def started(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        self.assertEqual(sorted(p.control_id for p in snap.proposals), ['1.5.1', '3.3.1'])
        return backend, handle.binding.workflow_session_id

    def execute(self, backend, workflow, round_ref, request_ids):
        from tests.integration.test_ubuntu_live_path import open_gate
        # Since 2026-11-13 a commit-confirm fix with another behind it is waited for (to stack the next one); this
        # fake server runs a job only when the test says so, so the wait passes at once and nothing is stacked.
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate(),                 mock.patch.object(type(backend), '_pause', staticmethod(lambda seconds: None)):
            return backend.execute_approved('c', workflow, round_ref, tuple(request_ids), True, 'op-exec')

    def proceed(self, backend, workflow, round_ref, connection='c'):
        from tests.integration.test_ubuntu_live_path import open_gate
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            return backend.continue_execution(connection, workflow, round_ref, True, 'op-continue')

    def dispatched(self):
        import json
        return [json.loads(c.split(b'\n', 1)[1])['parameters']['name'] for c in self.executes()]


class WaitingFixesRunLastTests(ContinueCase):
    def test_the_fix_that_waits_for_confirmation_runs_after_the_one_that_does_not(self):
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('1.5.1', '3.3.1'))
        result = self.execute(backend, workflow, round_ref, ids.values())
        # Before: plan order sent the confirm fix (alpha) first and stopped; beta never ran.
        self.assertEqual(self.dispatched(), ['beta', 'alpha'])
        self.assertEqual(result.state, 'running')  # alpha now waits for its confirmation
        self.assertEqual((self.work / 'beta').read_bytes(), b'new')

    def test_an_execution_that_stopped_without_a_fix_waiting_is_not_continued(self):
        """The model went away before the agents sent anything: the administrator decides (Confirm again, or run
        without AI); nothing continues by itself."""
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('1.5.1', '3.3.1'))
        backend.model_probe = lambda: False
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            with self.assertRaisesRegex(ValueError, 'model became unavailable'):
                backend.execute_approved('c', workflow, round_ref, tuple(ids.values()), False, 'op-agents')
        self.assertEqual(backend.continuation('c', workflow), ())
        self.assertIsNone(self.proceed(backend, workflow, round_ref))
        self.assertEqual(self.dispatched(), [])


class ContinueAfterSettlingTests(ContinueCase):
    # Two fixes that wait: the job (3.3.1) runs first, the confirm fix (1.5.1) after it has settled.
    SECOND = SecondJobFamily

    def test_after_the_job_settles_the_rest_of_the_execution_continues_once(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('1.5.1', '3.3.1'))
        self.assertIsNone(self.proceed(backend, workflow, round_ref))  # nothing was executed yet: nothing continues
        self.execute(backend, workflow, round_ref, ids.values())
        self.assertEqual(self.dispatched(), ['beta'])  # the job runs; the confirm fix waits for it
        self.assertEqual(backend.continuation('c', workflow), ())  # still running: nothing continues yet
        self.assertIsNone(self.proceed(backend, workflow, round_ref))
        self.job(ids['3.3.1'])
        with open_gate():
            self.assertEqual(backend.refresh_execution('c', workflow, round_ref, 'op-r').state, 'completed')
        self.assertEqual(backend.continuation('c', workflow), (ids['1.5.1'],))
        self.assertEqual(self.proceed(backend, workflow, round_ref).state, 'running')
        self.assertEqual(self.dispatched(), ['beta', 'alpha'])  # continued without a new Execute
        self.assertEqual(backend.continuation('c', workflow), ())  # never twice
        self.assertIsNone(self.proceed(backend, workflow, round_ref))
        self.assertEqual(len(self.executes()), 2)

    def test_a_fix_approved_after_the_execution_started_waits_for_its_own_click(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('3.3.1',))
        self.execute(backend, workflow, round_ref, ids.values())
        self.job(ids['3.3.1'])
        with open_gate():
            backend.refresh_execution('c', workflow, round_ref, 'op-r')
        round_ref, ids = self.approve(backend, workflow, ('1.5.1',))
        self.assertEqual(backend.continuation('c', workflow), ())  # not part of the execution the administrator sent
        self.assertIsNone(self.proceed(backend, workflow, round_ref))
        self.assertEqual(self.dispatched(), ['beta'])

    def test_an_expired_approval_is_not_continued(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('1.5.1', '3.3.1'))
        self.execute(backend, workflow, round_ref, ids.values())
        self.job(ids['3.3.1'])
        with open_gate():
            backend.refresh_execution('c', workflow, round_ref, 'op-r')
        later = datetime.now(timezone.utc) + timedelta(hours=2)
        with mock.patch('backends.ubuntu.adapter._utcnow', return_value=later):
            self.assertEqual(backend.continuation('c', workflow), ())
            self.assertIsNone(self.proceed(backend, workflow, round_ref))
        self.assertEqual(self.dispatched(), ['beta'])


class SecondConfirmFamily(ConfirmFamily):
    action_id = 'fixture.confirm.v1'


class RolledBackTests(ContinueCase):
    SECOND = SecondConfirmFamily  # both fixes wait for a confirmation; 1.5.1 runs first (plan order)

    def test_a_change_the_server_rolled_back_stops_the_continuation(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('1.5.1', '3.3.1'))
        self.execute(backend, workflow, round_ref, ids.values())
        self.assertEqual(self.dispatched(), ['alpha'])
        self.job(ids['1.5.1'])
        backend.refresh_execution('c', workflow, round_ref, 'op-r1')
        self.runner().rollback(ids['1.5.1'])  # nobody confirmed: the server restored it
        with open_gate():
            self.assertEqual(backend.refresh_execution('c', workflow, round_ref, 'op-r2').state, 'refused')
        # Something went wrong with the SSH login or the change: a person looks before anything else runs.
        self.assertEqual(backend.continuation('c', workflow), ())
        self.assertIsNone(self.proceed(backend, workflow, round_ref))
        self.assertEqual(self.dispatched(), ['alpha'])


for _name in [n for n in dir(supervised.SupervisedBackendCase) if n.startswith('test')]:
    setattr(ContinueCase, _name, None)  # only the harness is inherited
