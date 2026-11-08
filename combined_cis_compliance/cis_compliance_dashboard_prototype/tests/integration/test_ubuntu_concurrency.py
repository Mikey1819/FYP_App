"""Task 16 robustness for the Ubuntu backend: simultaneous clients, double clicks and stale commands.
TEST-ONLY file-value family and in-process runner; the VM is never contacted."""
import threading
from unittest import mock
from tests.integration.test_ubuntu_proposals import BackendRemediationTests


class RobustnessTests(BackendRemediationTests):
    def approved(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow = handle.binding.workflow_session_id
        backend.decide('c', workflow, snap.proposals[0].reference, True, 'fixture-operator', '', 'op-d')
        snap = backend.snapshot('c', workflow)
        return backend, workflow, snap, snap.proposals[0].approved_request_id

    def second_client(self, backend):
        """An independent client: its own backend object and ledger handle over the same durable files."""
        from backends.ubuntu.adapter import UbuntuBackend
        from system.ledger import CoordinationLedger
        return UbuntuBackend(backend.database_path, session=backend.session, ledger=CoordinationLedger(self.ledger.path),
                             families=backend.families, model_client_factory=backend.model_client_factory,
                             model_probe=lambda: True)

    def test_two_clients_executing_the_same_approved_set_at_once_dispatch_once(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow, snap, rid = self.approved()
        other = self.second_client(backend)
        barrier, results, errors = threading.Barrier(2), [], []

        def click(client, operation):
            try:
                barrier.wait(timeout=10)
                results.append(client.execute_approved('c', workflow, snap.current_round_reference, (rid,), True, operation))
            except Exception as failure:  # a refusal is an acceptable outcome for the losing click
                errors.append(failure)
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            threads = [threading.Thread(target=click, args=(client, op)) for client, op in ((backend, 'op-1'), (other, 'op-2'))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=60)
        self.assertEqual(len(self.executes()), 1)  # exactly one dispatch reached the target
        self.assertEqual(self.writes(), ['alpha'])
        self.assertEqual(len(results) + len(errors), 2)

    def test_a_double_click_on_approve_records_one_decision(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow, ref = handle.binding.workflow_session_id, snap.proposals[0].reference
        first = backend.decide('c', workflow, ref, True, 'fixture-operator', '', 'op-a')
        try:
            second = backend.decide('c', workflow, ref, True, 'fixture-operator', '', 'op-b')
            self.assertEqual(second.state, first.state)
        except ValueError:
            pass  # refusing the repeat is equally safe
        stored = backend._store().proposals(handle.binding, snap.current_round_reference.record_id)[0]
        self.assertEqual(stored.decision, 'approved')
        with self.assertRaises(ValueError):  # and it can never flip to rejected afterwards
            backend.decide('c', workflow, ref, False, 'fixture-operator', '', 'op-c')
        self.assertEqual(backend._store().proposals(handle.binding, snap.current_round_reference.record_id)[0].decision,
                         'approved')

    def test_commands_against_an_earlier_round_are_refused_after_a_newer_round(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow, snap, rid = self.approved()
        old_round = snap.current_round_reference
        with open_gate():
            backend.start_round('c', workflow, None, 'deterministic', 'op-newer')  # a newer round in the workflow
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            with self.assertRaises(ValueError):
                backend.execute_approved('c', workflow, old_round, (rid,), True, 'op-stale')
        with self.assertRaises(ValueError):
            backend.decide('c', workflow, snap.proposals[0].reference, False, 'fixture-operator', '', 'op-stale-d')
        self.assertEqual(self.executes(), [])

    def test_an_expired_connection_session_can_no_longer_command(self):
        backend, workflow, snap, rid = self.approved()
        backend.session.active = False
        for command in (lambda: backend.snapshot('c', workflow),
                        lambda: backend.decide('c', workflow, snap.proposals[0].reference, False, 'x', '', 'op'),
                        lambda: backend.refresh_execution('c', workflow, snap.current_round_reference, 'op')):
            with self.subTest(), self.assertRaises(ValueError):
                command()
        with self.assertRaises(ValueError):
            backend.snapshot('another-connection', workflow)


for _name in [n for n in vars(BackendRemediationTests) if n.startswith('test')]:
    setattr(RobustnessTests, _name, None)  # only the harness is inherited
del BackendRemediationTests
