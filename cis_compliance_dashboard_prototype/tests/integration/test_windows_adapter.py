import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from test_agentic import FakeVm
from test_winrm_channel import target
from hardening.winrm_channel import LiveScanner
from system.identity import VerifiedIdentity
from system.connection import VerifiedSession
from system.ledger import CoordinationLedger
from system.contracts import AssessmentMode, WorkspaceBackend, encode_record

class WindowsAdapterTests(unittest.TestCase):
    def test_deterministic_round_uses_existing_engine_without_model_or_proposals(self):
        self.assertIsNotNone(importlib.util.find_spec('backends.windows.adapter'))
        from backends.windows.adapter import WindowsBackend
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder); vm=FakeVm(); t=target()
            session=VerifiedSession('connection',VerifiedIdentity('windows',t.hostname,t.machine_uuid,'Server 2022','winrm'),
                                    'windows:'+t.machine_uuid,'epoch',t.username,t.host,t.port,None,t)
            ledger=CoordinationLedger(path/'integration.db')
            backend=WindowsBackend(path/'windows'/'imports.sqlite3',session=session,ledger=ledger,
                scanner_factory=lambda runtime,t:LiveScanner(runtime,t,session_factory=vm))
            self.assertIsInstance(backend,WorkspaceBackend)
            handle=backend.start_round('connection',None,None,AssessmentMode.DETERMINISTIC,'scan-intent')
            snapshot=backend.snapshot('connection',handle.binding.workflow_session_id)
            self.assertEqual(snapshot.summary.selected,32)
            fix={c.control_id:c.fix for c in snapshot.controls}
            self.assertEqual({c for c,f in fix.items() if f=='Manual: not automated'},{'9.2.1','9.2.2','9.3.1','9.3.2'})
            self.assertEqual(sum(f=='Program fix' for f in fix.values()),28)
            self.assertEqual(snapshot.proposals,())
            self.assertEqual(snapshot.events,())
            self.assertEqual(vm.writes,[])
            self.assertNotEqual(handle.binding.backend_session_id,'connection')
            self.assertNotIn(t.password,encode_record(snapshot))
            with self.assertRaises(ValueError):backend.snapshot('wrong',handle.binding.workflow_session_id)
            self.assertEqual(ledger.resume(handle.binding.workflow_session_id,'windows',session.target_id,'epoch'),handle.binding)
            self.assertFalse(backend.capabilities('connection').can_remediate)
            scripts_before = len(vm.scripts)
            replay = backend.start_round('connection', None, None, AssessmentMode.DETERMINISTIC, 'scan-intent')
            self.assertEqual(replay, handle)
            self.assertEqual(len(vm.scripts), scripts_before, 'A replay must not collect again')
            self.assertEqual(len(backend.store.rounds(handle.binding.backend_session_id)), 1)
            self.assertEqual(len(backend.history()), 1)
            from dataclasses import replace
            other_epoch = WindowsBackend(path/'windows'/'imports.sqlite3',session=replace(session,registration_epoch='new-epoch'),
                ledger=ledger, scanner_factory=lambda runtime,t:LiveScanner(runtime,t,session_factory=vm))
            self.assertEqual(other_epoch.history(), ())
            self.assertFalse(other_epoch.compare(snapshot.summary.reference,snapshot.summary.reference).comparable)

    def test_clock_sync_is_a_recorded_change_that_then_lets_a_scan_through(self):
        import json
        from datetime import timedelta
        from backends.windows.adapter import WindowsBackend
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder); vm=FakeVm(); t=target()
            vm.clock_ahead=timedelta(minutes=7)
            session=VerifiedSession('connection',VerifiedIdentity('windows',t.hostname,t.machine_uuid,'Server 2022','winrm'),
                                    'windows:'+t.machine_uuid,'epoch',t.username,t.host,t.port,None,t)
            ledger=CoordinationLedger(path/'integration.db')
            backend=WindowsBackend(path/'windows'/'imports.sqlite3',session=session,ledger=ledger,
                scanner_factory=lambda runtime,t:LiveScanner(runtime,t,session_factory=vm))
            self.assertAlmostEqual(backend.clock_offset('connection')['offset'],420,delta=2)
            with self.assertRaises(ValueError):backend.clock_offset('wrong')
            result=backend.sync_clock('connection',None,'sync-1')
            self.assertAlmostEqual((result['before']-result['after']).total_seconds(),420,delta=2)
            state=ledger.operation_state('sync-1')
            self.assertEqual(state.state,'completed')
            record=json.loads(state.detail)
            self.assertEqual(record['account'],t.username)
            self.assertEqual(set(record),{'account','server_before','server_after'})
            self.assertAlmostEqual(backend.clock_offset('connection')['offset'],0,delta=2)
            handle=backend.start_round('connection',None,None,AssessmentMode.DETERMINISTIC,'scan-after-sync')
            self.assertEqual(handle.state,'completed')  # The scan now passes the time check.
            self.assertEqual(vm.writes,[])

    def test_round_goal_is_refused_before_any_scan(self):
        from backends.windows.adapter import WindowsBackend
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder); vm=FakeVm(); t=target()
            session=VerifiedSession('connection',VerifiedIdentity('windows',t.hostname,t.machine_uuid,'Server 2022','winrm'),
                                    'windows:'+t.machine_uuid,'epoch',t.username,t.host,t.port,None,t)
            backend=WindowsBackend(path/'windows'/'imports.sqlite3',session=session,ledger=CoordinationLedger(path/'integration.db'),
                scanner_factory=lambda runtime,t:LiveScanner(runtime,t,session_factory=vm))
            for mode in (AssessmentMode.AGENTIC, AssessmentMode.DETERMINISTIC):
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'goals were removed'):
                    backend.start_round('connection', None, 'Keep RDP usable', mode, 'goal-' + mode.value)
            self.assertEqual(vm.scripts, [])
            self.assertEqual(backend.history(), ())


class UnattemptedFixTests(unittest.TestCase):
    """Live 9 Nov: the WinRM channel failed before the 11th of 15 approved fixes. The 5 never attempted had no verdict,
    were counted as uncertain, and the execute locked the server: Confirm and Execute without AI were both refused."""

    def setUp(self):
        from types import SimpleNamespace
        from backends.windows.adapter import WindowsBackend
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name); vm = FakeVm(); t = target()
        session = VerifiedSession('connection', VerifiedIdentity('windows', t.hostname, t.machine_uuid, 'Server 2022', 'winrm'),
                                  'windows:' + t.machine_uuid, 'epoch', t.username, t.host, t.port, None, t)
        self.ledger = CoordinationLedger(path / 'integration.db')
        self.backend = WindowsBackend(path / 'windows' / 'imports.sqlite3', session=session, ledger=self.ledger,
                                      allow_mutation=True,
                                      scanner_factory=lambda runtime, t: LiveScanner(runtime, t, session_factory=vm))
        handle = self.backend.start_round('connection', None, None, AssessmentMode.DETERMINISTIC, 'scan')
        self.workflow, self.round = handle.binding.workflow_session_id, handle.round_reference
        # Five approved fixes; the store and the engine are simulated, the ledger and the backend are real.
        self.records = {f'r{n}': dict(proposal=dict(request_id=f'r{n}'), decision='approved', verdict=None)
                        for n in range(5)}
        real = self.backend.store
        self.backend.store = SimpleNamespace(rounds=real.rounds, for_run=lambda run_id: list(self.records.values()),
                                             get=lambda identifier: self.records[identifier])
        self.outcomes = []
        self.backend.engine = SimpleNamespace(execute_approved=lambda session_id, deterministic=False:
                                              self.records.update(self.outcomes.pop(0)))

    def execute(self, ids, operation):
        return self.backend.execute_approved('connection', self.workflow, self.round, ids, False, operation)

    def test_fixes_never_attempted_stay_approved_and_can_be_executed_next(self):
        done = dict(self.records['r0'], verdict='Verified compliant')
        refused = dict(self.records['r1'], verdict='Refused before execution: value changed')
        self.outcomes = [{'r0': done, 'r1': refused}, {n: dict(self.records[n], verdict='Verified compliant')
                                                      for n in ('r2', 'r3', 'r4')}]
        self.assertEqual(self.execute(tuple(self.records), 'exec-1').state, 'completed')
        self.assertEqual(self.ledger.unsettled(self.workflow), [])  # nothing locks the server
        self.assertEqual(self.execute(('r2', 'r3', 'r4'), 'exec-2').state, 'completed')

    def test_an_uncertain_outcome_still_locks_until_reviewed(self):
        self.outcomes = [{'r0': dict(self.records['r0'], verdict='Unresolved: outcome uncertain (channel lost); rescan')}]
        self.assertEqual(self.execute(tuple(self.records), 'exec-1').state, 'unresolved')
        with self.assertRaisesRegex(ValueError, 'unresolved operation'):
            self.execute(('r1', 'r2', 'r3', 'r4'), 'exec-2')

    def test_an_execute_already_locked_by_unattempted_fixes_is_settled_from_the_records(self):
        # The state the live ledger was left in before this fix: unresolved with no detail, no uncertain verdict.
        binding = self.ledger.resume(self.workflow, 'windows', self.backend.session.target_id, 'epoch')
        self.ledger.claim(binding, 'old-exec', 'execute', {'round': self.round.record_id}, mutation=True)
        self.ledger.transition('old-exec', 'unresolved')
        self.records['r0'] = dict(self.records['r0'], verdict='Verified compliant')
        self.outcomes = [{n: dict(self.records[n], verdict='Verified compliant') for n in ('r1', 'r2', 'r3', 'r4')}]
        self.assertEqual(self.execute(('r1', 'r2', 'r3', 'r4'), 'exec-2').state, 'completed')
        self.assertEqual(self.ledger.operation_state('old-exec').state, 'completed')
        self.assertIn('Settled from stored receipts', self.ledger.operation_state('old-exec').detail)
