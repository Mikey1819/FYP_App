"""An applied fix whose verification scan did not happen can be verified later (administrator request 2026-11-08: a card
stayed "Applied, re-scan pending" and a browser refresh ends the connection, because credentials live only in that
session). verify_applied runs the read-only scan for applied fixes that have none; it never re-dispatches a fix.
Fixture target and runner; no VM."""
from unittest import mock

from tests.integration import test_ubuntu_proposals as base  # module import: the base tests are not collected twice


class VerifyAppliedTests(base.BackendRemediationTests):
    def approve_and_execute(self, backend):
        import json
        from tests.integration.test_ubuntu_live_path import open_gate
        handle, snap = self.round(backend)
        workflow = handle.binding.workflow_session_id
        backend.decide('c', workflow, snap.proposals[0].reference, True, 'fixture-operator', '', 'op-decide')
        snap = backend.snapshot('c', workflow)
        stored = backend._store().proposals(handle.binding, snap.current_round_reference.record_id)[0]
        request_id = json.loads(stored.approved_raw)['request_id']
        real_collect = backend._collect
        failing = mock.patch.object(backend, '_collect', side_effect=OSError('connection lost during the scan'))
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate(), failing:
            result = backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True, 'op-x')
        return workflow, snap.current_round_reference, result, real_collect

    def test_an_applied_fix_without_its_scan_is_verified_later_without_a_second_dispatch(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend = self.backend(self.FIX)
        workflow, round_ref, result, _ = self.approve_and_execute(backend)
        self.assertEqual(result.state, 'verification_pending')
        [row] = backend.snapshot('c', workflow).results
        self.assertIsNone(row.verification_status)
        self.assertEqual(backend.unverified_applied('c', workflow), (row.receipt_reference.record_id,))
        writes = len(self.executes())
        with open_gate():
            handle = backend.verify_applied('c', workflow, round_ref, 'op-verify')
        self.assertEqual(handle.state, 'completed')
        self.assertEqual(len(self.executes()), writes)  # read-only: no fix dispatched again
        [row] = backend.snapshot('c', workflow).results
        self.assertIsNotNone(row.verification_status)
        self.assertEqual(backend.unverified_applied('c', workflow), ())

    def test_nothing_to_verify_runs_no_scan(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        with mock.patch.object(backend, '_collect') as collect:
            result = backend.verify_applied('c', handle.binding.workflow_session_id, snap.current_round_reference, 'op-v')
        self.assertEqual(result.state, 'nothing_to_verify')
        collect.assert_not_called()

