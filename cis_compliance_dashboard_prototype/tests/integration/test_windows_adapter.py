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
