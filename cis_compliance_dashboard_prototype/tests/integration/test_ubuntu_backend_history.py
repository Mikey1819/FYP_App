"""UbuntuBackend serves stored, validated assessments read-only. Synthetic fixture evidence only."""
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from tests.integration.test_ubuntu_evidence import envelope
from backends.ubuntu.envelope import ExpectedEvidence
from system.connection import VerifiedSession
from system.contracts import RecordRef, WorkflowBinding
from system.identity import VerifiedIdentity
from system.ledger import CoordinationLedger

NOW = datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc)


def session(epoch='epoch', hostname='UBUNTU-FIXTURE', machine='a'*32):
    return VerifiedSession('c', VerifiedIdentity('ubuntu', hostname, machine, '22.04', 'ssh'),
                           'ubuntu:fixture', epoch, 'user', 'vm', 22, None)


class UbuntuBackendHistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)/'ubuntu.sqlite3'
        self.ledger = CoordinationLedger(Path(self.folder.name)/'ledger.sqlite3')
        self.binding = self.ledger.add_binding(WorkflowBinding('workflow', 'ubuntu', 'ubuntu:fixture', 'epoch',
                                                               'backend-session', '2026-11-06T00:00:00+00:00'))

    def store_round(self, request_id='fixture-request', change=None):
        from backends.ubuntu.storage import UbuntuStore
        doc = envelope(); doc['request_id'] = request_id
        if change:change(doc)
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        store = UbuntuStore(self.path)
        run = store.start_run(json.dumps(doc).encode(), expected, self.binding, now=NOW)
        return run, store.record_round(self.binding, run.run_id, mode='deterministic')

    def backend(self, **kwargs):
        from backends.ubuntu.adapter import UbuntuBackend
        return UbuntuBackend(self.path, session=session(**kwargs), ledger=self.ledger)

    def test_history_and_snapshot_show_stored_counts_and_fixture_label(self):
        run, round_id = self.store_round()
        backend = self.backend()
        rows = backend.history('ubuntu:fixture')
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.run_reference, RecordRef('ubuntu', 'ubuntu:fixture', run.run_id))
        self.assertEqual((row.counts.selected, row.counts.compliant, row.counts.unknown), (30, 29, 1))
        self.assertEqual(row.evidence_mode, 'Synthetic fixture')
        self.assertNotIn('Live', row.target.evidence_mode)
        snap = backend.snapshot('c', 'workflow')
        self.assertEqual(snap.current_round_reference.record_id, round_id)
        self.assertEqual(len(snap.controls), 30)
        self.assertEqual(snap.summary.selected, 30)
        self.assertEqual(snap.target.evidence_mode, 'Synthetic fixture')
        self.assertEqual(snap.findings, ())  # risk derivation (task 8) is not implemented
        manual = next(c for c in snap.controls if c.control_id == '1.2.2.1')
        self.assertEqual(manual.status.value, 'Unknown')
        self.assertTrue(manual.subchecks)
        from unittest import mock
        with mock.patch('backends.ubuntu.adapter.assessment_gate', return_value=('Ubuntu assessment is not enabled (test-closed gate).',)):
            self.assertFalse(backend.capabilities('c').can_assess)

    def test_scope_epoch_identity_and_corruption(self):
        run, _ = self.store_round()
        self.assertEqual(self.backend(epoch='other-epoch').history('ubuntu:fixture'), ())
        with self.assertRaises(ValueError):self.backend().history('ubuntu:other')
        with self.assertRaises(ValueError):self.backend(machine='e'*32).history('ubuntu:fixture')
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('DROP TRIGGER imported_assessments_no_UPDATE')
            db.execute('UPDATE imported_assessments SET raw=?', (b'corrupt',)); db.commit()
        with self.assertRaises(ValueError):self.backend().history('ubuntu:fixture')

    def test_unbound_workflow_runs_are_not_shown(self):
        from backends.ubuntu.storage import UbuntuStore
        doc = envelope()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        stranger = WorkflowBinding('unregistered', 'ubuntu', 'ubuntu:fixture', 'epoch', 'b', '2026-11-06T00:00:00+00:00')
        UbuntuStore(self.path).start_run(json.dumps(doc).encode(), expected, stranger, now=NOW)
        self.assertEqual(self.backend().history('ubuntu:fixture'), ())

    def test_no_store_file_means_no_history_and_nothing_created(self):
        self.assertEqual(self.backend().history('ubuntu:fixture'), ())
        self.assertIsNone(self.backend().snapshot('c', 'workflow').summary)
        self.assertFalse(self.path.exists())

    def test_compare_reports_status_changes_in_chronological_order_only(self):
        first, _ = self.store_round()
        def fail_aslr(doc):doc['observations']['1.5.1']['runtime.kernel.randomize_va_space']['value'] = 0
        second, _ = self.store_round('fixture-request-2', fail_aslr)
        backend = self.backend()
        before, after = (RecordRef('ubuntu', 'ubuntu:fixture', r.run_id) for r in (first, second))
        result = backend.compare(before, after)
        self.assertTrue(result.comparable)
        self.assertEqual(result.changes, (('1.5.1', 'Compliant', 'Non-Compliant'),))
        self.assertFalse(backend.compare(after, before).comparable)
        self.assertFalse(backend.compare(before, RecordRef('ubuntu', 'ubuntu:fixture', 'missing')).comparable)
        self.assertFalse(backend.compare(before, RecordRef('windows', 'windows:x', first.run_id)).comparable)

    def test_controls_tab_renders_stored_snapshot_with_evidence_label(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_shared_ui import snapshot_panels
        self.store_round()
        app = AppTest.from_function(snapshot_panels, default_timeout=30)
        app.session_state['snapshot'] = self.backend().snapshot('c', 'workflow')
        app.run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any('Evidence: Synthetic fixture' in c.value for c in app.caption))
        self.assertFalse(any('Live (SSH)' in c.value for c in app.caption))
        self.assertEqual(len(app.dataframe[0].value), 30)
