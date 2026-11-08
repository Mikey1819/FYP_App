"""Backend status refresh and reconnect-to-confirm for supervised fixes. TEST-ONLY families, fake launcher; no VM."""
from datetime import datetime, timedelta, timezone
import json
from unittest import mock
from tests.integration.test_ubuntu_proposals import BackendRemediationTests
from tests.integration.test_ubuntu_supervision import ConfirmFamily, FakeLauncher, JobFamily


class SupervisedBackendCase(BackendRemediationTests):
    FAMILY = ConfirmFamily

    def setUp(self):
        super().setUp()
        self.family, self.launcher = self.FAMILY(self.work), FakeLauncher()

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.runner import Runner
        family = family or self.family
        return Runner(self.state, {family.action_id: family}, lambda: identity or ('a' * 32, 'ubuntu-fixture'),
                      clock=clock or self.clock, require_root_owned=False, launcher=self.launcher)

    def approved_round(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow = handle.binding.workflow_session_id
        backend.decide('c', workflow, snap.proposals[0].reference, True, 'fixture-operator', '', 'op-d')
        snap = backend.snapshot('c', workflow)
        return backend, workflow, snap.current_round_reference, snap.proposals[0].approved_request_id

    def execute(self, backend, workflow, round_ref, request_id):
        from tests.integration.test_ubuntu_live_path import open_gate
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            return backend.execute_approved('c', workflow, round_ref, (request_id,), True, 'op-exec')

    def job(self, request_id):
        self.runner().run_job(request_id)
        self.launcher.active.discard(request_id)

    def reconnect(self, backend, *, at):
        """A fresh login: a new verified session on the same ledger and stores (credentials are never reused)."""
        from backends.ubuntu.adapter import UbuntuBackend
        from dataclasses import replace
        session = replace(backend.session, connection_session_id='c2', connected_at=at.isoformat())
        return UbuntuBackend(backend.database_path, session=session, ledger=self.ledger, families=backend.families,
                             model_client_factory=backend.model_client_factory, model_probe=lambda: True)

    def row(self, backend, workflow, connection='c'):
        [row] = backend.snapshot(connection, workflow).results
        return row


class ConfirmBackendTests(SupervisedBackendCase):
    def test_running_then_awaiting_then_a_fresh_login_confirms_and_verifies(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow, round_ref, rid = self.approved_round()
        first = self.execute(backend, workflow, round_ref, rid)
        self.assertEqual(first.state, 'running')
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.row(backend, workflow).execution_state, 'running')
        self.assertEqual(backend.refresh_execution('c', workflow, round_ref, 'op-r1').state, 'running')
        self.job(rid)
        self.assertEqual(backend.refresh_execution('c', workflow, round_ref, 'op-r2').state, 'awaiting_confirmation')
        row = self.row(backend, workflow)
        self.assertIn('reconnect', row.detail.lower())
        with self.assertRaisesRegex(ValueError, 'fresh login'):  # the dispatching connection proves nothing
            backend.confirm_change('c', workflow, round_ref, rid, 'op-c1')
        stale = self.reconnect(backend, at=datetime.now(timezone.utc) - timedelta(hours=1))
        with self.assertRaisesRegex(ValueError, 'fresh login'):  # a login from before the change was applied
            stale.confirm_change('c2', workflow, round_ref, rid, 'op-c2')
        fresh = self.reconnect(backend, at=datetime.now(timezone.utc) + timedelta(seconds=1))
        with open_gate():
            done = fresh.confirm_change('c2', workflow, round_ref, rid, 'op-c3')
        self.assertEqual(done.state, 'completed')
        row = self.row(fresh, workflow, 'c2')
        self.assertEqual(row.execution_state, 'applied')
        self.assertIsNotNone(row.verification_assessment_reference)  # fresh verification scan ran
        self.assertEqual(self.ledger.operation_state('ubuntu-execute:' + rid).state, 'completed')
        self.assertEqual(len(self.executes()), 1)

    def test_no_confirmation_is_rolled_back_by_the_target_and_settles_refused(self):
        backend, workflow, round_ref, rid = self.approved_round()
        self.execute(backend, workflow, round_ref, rid)
        self.job(rid)
        backend.refresh_execution('c', workflow, round_ref, 'op-r1')
        self.runner().rollback(rid)  # the timer fired: nobody confirmed
        self.assertEqual(backend.refresh_execution('c', workflow, round_ref, 'op-r2').state, 'refused')
        row = self.row(backend, workflow)
        self.assertEqual(row.execution_state, 'rolled_back')
        self.assertIn('restored', row.detail.lower())
        self.assertEqual((self.work / 'alpha').read_bytes(), b'old')
        self.assertEqual(self.ledger.operation_state('ubuntu-execute:' + rid).state, 'refused')
        fresh = self.reconnect(backend, at=datetime.now(timezone.utc) + timedelta(seconds=1))
        with self.assertRaises(ValueError):  # nothing is awaiting confirmation any more
            fresh.confirm_change('c2', workflow, round_ref, rid, 'op-c')

    def test_after_a_reconnect_waiting_changes_are_found_without_the_old_workflow_key(self):
        backend, workflow, round_ref, rid = self.approved_round()
        self.assertEqual(backend.pending_supervised('c'), ())
        self.execute(backend, workflow, round_ref, rid)
        [item] = backend.pending_supervised('c')
        self.assertEqual((item.workflow_session_id, item.request_id, item.control_id, item.code),
                         (workflow, rid, '1.5.1', 'job_started'))
        self.job(rid)
        backend.refresh_execution('c', workflow, round_ref, 'op-r')
        fresh = self.reconnect(backend, at=datetime.now(timezone.utc) + timedelta(seconds=1))
        [item] = fresh.pending_supervised('c2')
        self.assertEqual((item.round_reference, item.code), (round_ref, 'awaiting_confirmation'))
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            fresh.confirm_change('c2', item.workflow_session_id, item.round_reference, item.request_id, 'op-c')
        self.assertEqual(fresh.pending_supervised('c2'), ())

    def test_repeated_status_checks_store_only_changes(self):
        backend, workflow, round_ref, rid = self.approved_round()
        self.execute(backend, workflow, round_ref, rid)
        for n in range(3):
            backend.refresh_execution('c', workflow, round_ref, 'op-r%d' % n)
        stored = backend._store().proposals(backend.check('c', workflow), round_ref.record_id)[0]
        self.assertEqual([(r['outcome'], r['code']) for r in stored.receipts],
                         [('running', 'job_started'), ('running', 'job_running')])


class JobBackendTests(SupervisedBackendCase):
    FAMILY = JobFamily

    def test_a_supervised_job_settles_through_status_and_is_verified(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow, round_ref, rid = self.approved_round()
        self.assertEqual(self.execute(backend, workflow, round_ref, rid).state, 'running')
        self.job(rid)
        with open_gate():
            self.assertEqual(backend.refresh_execution('c', workflow, round_ref, 'op-r').state, 'completed')
        row = self.row(backend, workflow)
        self.assertEqual(row.execution_state, 'applied')
        self.assertIsNotNone(row.verification_assessment_reference)
        with self.assertRaises(ValueError):  # a plain job has nothing to confirm
            backend.confirm_change('c', workflow, round_ref, rid, 'op-c')


class LedgerEventTests(SupervisedBackendCase):
    def test_observation_is_recorded_once_with_the_host_clock(self):
        backend, workflow, round_ref, rid = self.approved_round()
        self.execute(backend, workflow, round_ref, rid)
        op = 'ubuntu-execute:' + rid
        self.assertIsNone(self.ledger.first_event(op, 'awaiting_confirmation'))
        first = self.ledger.note(op, 'awaiting_confirmation')
        self.ledger.note(op, 'awaiting_confirmation')
        self.assertEqual(self.ledger.first_event(op, 'awaiting_confirmation'), first)
        datetime.fromisoformat(first)
        with self.assertRaises(ValueError):
            self.ledger.note('unknown-op', 'awaiting_confirmation')


for _name in [n for n in dir(BackendRemediationTests) if n.startswith('test')]:
    setattr(SupervisedBackendCase, _name, None)  # only the harness is inherited; the base tests run in their module
del BackendRemediationTests
