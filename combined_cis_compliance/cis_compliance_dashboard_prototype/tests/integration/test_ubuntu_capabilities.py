import importlib.util
import tempfile
import unittest
from pathlib import Path
from system.contracts import WorkspaceBackend
from system.connection import VerifiedSession
from system.identity import VerifiedIdentity
from system.ledger import CoordinationLedger

class UbuntuCapabilityTests(unittest.TestCase):
    def test_missing_collector_is_setup_required_and_never_fake_assessment(self):
        self.assertIsNotNone(importlib.util.find_spec('backends.ubuntu.adapter'))
        from backends.ubuntu.adapter import UbuntuBackend
        from unittest import mock
        with tempfile.TemporaryDirectory() as folder, mock.patch('backends.ubuntu.adapter.assessment_gate', return_value=('Ubuntu assessment is not enabled (test-closed gate).',)):
            session=VerifiedSession('c',VerifiedIdentity('ubuntu','vm','a'*32,'22.04','ssh'),'ubuntu:fixture','epoch','user','vm',22,None)
            backend=UbuntuBackend(Path(folder)/'imports.db',session=session,ledger=CoordinationLedger(Path(folder)/'ledger.db'))
            self.assertIsInstance(backend,WorkspaceBackend)
            self.assertFalse(backend.capabilities('c').can_assess)
            self.assertFalse(backend.capabilities('c').can_remediate)
            self.assertIsNone(backend.snapshot('c',None).summary)
            with self.assertRaises(ValueError):backend.start_round('c',None,None,'deterministic','op')
            self.assertFalse((Path(folder)/'imports.db').exists())
