"""A VM restored from a snapshot while a fix was open (administrator, 13 November 2026).

Live: 1.3.1.1 (supervised apt job) was running; the app was closed and the VM restored from a snapshot, twice. The
restore wiped the runner's records, so for 1.3.1.1 it answered "never claimed" without the request's digest (it no
longer has the request), and the host rejected that as "Receipt belongs to another request": the change stayed open
for ever. A safety check started meanwhile was recorded, then refused by the open change before any dispatch, and its
run without an outcome blocked every later safety check ("An acceptance run is still open").
Now the runner's "no record of this request" settles the change as not applied, and nothing continues by itself; a
safety check never dispatched is settled as such; and no safety check is recorded while a change is open.
TEST-ONLY runner, fake launcher and fake server; the VM is never contacted.
"""
import shutil
import unittest
from unittest import mock

from tests.integration import test_ubuntu_execution_continue as cont
from tests.integration import test_ubuntu_acceptance_host as acceptance


class RestoredTests(cont.ContinueCase):
    SECOND = cont.SecondJobFamily  # 3.3.1 is a supervised job (as 1.3.1.1); 1.5.1 (commit-confirm) waits behind it

    def restore_snapshot(self):
        """What a snapshot restore does to the runner: its records of this request are gone."""
        shutil.rmtree(self.state / 'requests', ignore_errors=True)
        (self.state / 'active').unlink(missing_ok=True)

    def test_a_request_the_server_has_no_record_of_is_settled_not_applied(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow = self.started()
        round_ref, ids = self.approve(backend, workflow, ('1.5.1', '3.3.1'))
        self.execute(backend, workflow, round_ref, ids.values())
        self.assertEqual(self.dispatched(), ['beta'])  # the job; the commit-confirm fix waits behind it
        self.restore_snapshot()
        with open_gate():
            handle = backend.refresh_execution('c', workflow, round_ref, 'op-status')  # before: "Receipt belongs ..."
        self.assertEqual(handle.state, 'refused')
        session = backend.session
        self.assertIsNone(backend.ledger.owner(session.target_id, session.registration_epoch))  # the server is free
        card = next(r for r in backend.snapshot('c', workflow).results if r.execution_state == 'refused')
        self.assertIn('no record', card.detail)
        self.assertEqual(backend.continuation('c', workflow), ())  # restored server: nothing continues by itself
        self.assertEqual(backend.pending_supervised('c'), ())

    def test_a_receipt_for_another_request_is_still_refused(self):
        from backends.ubuntu.executor import _trusted
        from vm.ubuntu.remediation_schema import receipt
        approved = type('A', (), {'request': {'request_id': 'a' * 32}, 'sha256': 'b' * 64})()
        stamp = '2026-11-13T00:00:00+00:00'
        for doc in (receipt('c' * 32, '0' * 64, 'refused', 'not_claimed', None, None, stamp, stamp),  # other request
                    receipt('a' * 32, '0' * 64, 'applied', 'expected_after_state', None, None, stamp, stamp),
                    receipt('a' * 32, 'd' * 64, 'refused', 'not_claimed', None, None, stamp, stamp)):
            with self.subTest(doc=doc[:80]), self.assertRaises(ValueError):
                _trusted(doc, approved)
        self.assertEqual(_trusted(receipt('a' * 32, '0' * 64, 'refused', 'not_claimed', None, None, stamp, stamp),
                                  approved)['code'], 'not_claimed')


for _name in [n for n in dir(cont.ContinueCase) if n.startswith('test')]:
    setattr(RestoredTests, _name, None)


class AcceptanceAfterRestoreTests(acceptance.AcceptanceCase):
    def test_no_safety_check_is_recorded_while_a_change_is_open(self):
        backend = self.deployed()
        binding = backend.new_binding('c')
        backend.ledger.claim(binding, 'op-open', 'execution', {'request_sha256': 'x'}, mutation=True)
        with self.assertRaisesRegex(ValueError, 'still open'):
            backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')
        self.assertEqual(list(backend._acceptance_runs()), [])  # before: a run recorded that could never finish

    def test_a_safety_check_never_dispatched_is_settled_and_no_longer_blocks(self):
        backend = self.deployed()
        with mock.patch('backends.ubuntu.executor.execute', side_effect=ValueError('TEST-ONLY claim refused')):
            with self.assertRaises(ValueError):
                backend.start_acceptance('c', 'confirm', 'fixture-operator', 'op-a1')
        [orphan] = backend._acceptance_runs()
        self.assertIsNone(orphan['outcome'])
        backend.acceptance_status('c')  # before: open for ever, every later safety check refused
        self.assertEqual([r['outcome'] for r in backend._acceptance_runs()], ['failed:not_dispatched'])
        run, _, confirmed = self.run_confirm(backend)
        self.assertEqual(confirmed.outcome, 'confirmed')


for _name in [n for n in dir(acceptance.AcceptanceCase) if n.startswith('test')]:
    setattr(AcceptanceAfterRestoreTests, _name, None)


if __name__ == '__main__':
    unittest.main()
