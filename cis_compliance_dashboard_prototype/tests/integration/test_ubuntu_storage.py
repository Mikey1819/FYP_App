from contextlib import closing
from datetime import datetime,timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from tests.integration.test_ubuntu_evidence import envelope
from backends.ubuntu.envelope import ExpectedEvidence
from system.contracts import WorkflowBinding


class UbuntuStorageTests(unittest.TestCase):
    def fixture(self):
        doc=envelope()
        expected=ExpectedEvidence(doc['target_id'],doc['registration_epoch'],doc['hostname'],doc['machine_id'],
            doc['request_id'],doc['benchmark_sha256'],doc['source_lock_sha256'],doc['collector_sha256'],doc['evidence_mode'])
        binding=WorkflowBinding('workflow','ubuntu','ubuntu:fixture','epoch','backend-session','2026-11-06T00:00:00+00:00')
        return json.dumps(doc).encode(),expected,binding

    def test_three_isolated_files_eleven_tables_reopen_and_idempotent_request(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'ubuntu.sqlite3';store=UbuntuStore(path)
            raw,expected,binding=self.fixture()
            now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc)
            run=store.start_run(raw,expected,binding,now=now)
            self.assertEqual(store.start_run(raw,expected,binding,now=now),run)
            round_id=store.record_round(binding,run.run_id,mode='deterministic')
            self.assertEqual(store.record_round(binding,run.run_id,mode='deterministic'),round_id)
            reopened=UbuntuStore(path)
            self.assertEqual(len(reopened.history('ubuntu:fixture','epoch')),1)
            self.assertEqual(len(reopened.rounds(binding)),1)
            self.assertEqual(len(reopened.get_evidence(run.digest,'ubuntu:fixture','epoch').assessments),30)
            self.assertEqual(reopened.history('ubuntu:fixture','other-epoch'),())
            with self.assertRaises(ValueError):reopened.get_evidence(run.digest,'ubuntu:other','epoch')
            count=0
            for db_path in reopened.paths:
                with closing(sqlite3.connect(db_path)) as db:
                    count+=db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
            self.assertEqual(count,11)
            self.assertEqual(reopened.consistency_errors(),())

    def test_append_only_conflicting_request_and_no_windows_database_adoption(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            store=UbuntuStore(Path(folder)/'ubuntu.sqlite3')
            raw,expected,binding=self.fixture();now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc)
            run=store.start_run(raw,expected,binding,now=now)
            altered=json.loads(raw);altered['observations']['1.5.1']['runtime.kernel.randomize_va_space']['value']=0
            with self.assertRaises(ValueError):store.start_run(json.dumps(altered).encode(),expected,binding,now=now)
            with closing(sqlite3.connect(store.paths[0])) as db:
                with self.assertRaises(sqlite3.IntegrityError):db.execute('DELETE FROM imported_assessments')
                with self.assertRaises(sqlite3.IntegrityError):db.execute('UPDATE imported_assessments SET raw=?',(b'corrupt',))
                with self.assertRaises(sqlite3.IntegrityError):db.execute('INSERT OR REPLACE INTO imported_assessments SELECT * FROM imported_assessments')
            foreign=Path(folder)/'windows.sqlite3'
            with closing(sqlite3.connect(foreign)) as db:db.execute('CREATE TABLE imported_assessments(digest TEXT)');db.commit()
            before=foreign.read_bytes()
            with self.assertRaises(ValueError):UbuntuStore(foreign)
            self.assertEqual(foreign.read_bytes(),before)

    def test_corrupt_raw_is_detected_on_read_and_orphan_is_reported(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            store=UbuntuStore(Path(folder)/'ubuntu.sqlite3')
            raw,expected,binding=self.fixture();now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc)
            digest=store.save_evidence(raw,expected,now=now).raw_sha256
            self.assertTrue(any('orphan evidence' in error for error in store.consistency_errors()))
            with closing(sqlite3.connect(store.paths[0])) as db:
                db.execute('DROP TRIGGER imported_assessments_no_UPDATE')
                db.execute('UPDATE imported_assessments SET raw=?',(b'corrupt',));db.commit()
            with self.assertRaises(ValueError):store.get_evidence(digest,'ubuntu:fixture','epoch')


class UbuntuStorageRecoveryTests(unittest.TestCase):
    """Added after the first green run: partial-write recovery and link refusals (synthetic fixture only)."""
    fixture = UbuntuStorageTests.fixture

    def test_crash_after_evidence_recovers_idempotently_without_fresh_claim_or_invented_round(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            store=UbuntuStore(Path(folder)/'ubuntu.sqlite3')
            raw,expected,binding=self.fixture();now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc)
            saved=store.save_evidence(raw,expected,now=now)
            self.assertEqual(store.history('ubuntu:fixture','epoch'),())
            self.assertEqual(store.rounds(binding),())
            # Retried an hour later: stored bytes are reused and stay anchored to their receipt time.
            later=datetime(2026,11,6,1,0,0,tzinfo=timezone.utc)
            run=store.start_run(raw,expected,binding,now=later)
            self.assertEqual(store.get_evidence(run.digest,'ubuntu:fixture','epoch').received_at,saved.received_at)
            self.assertEqual(store.rounds(binding),())
            self.assertEqual(store.consistency_errors(),())
            # A fresh, never-stored envelope is still refused as too old for a new scan.
            altered=json.loads(raw);altered['observations']['1.5.1']['runtime.kernel.randomize_va_space']['value']=0
            altered['request_id']='other-request'
            other=ExpectedEvidence(*[altered[f] for f in ExpectedEvidence.__dataclass_fields__])
            with self.assertRaises(ValueError):store.save_evidence(json.dumps(altered).encode(),other,now=later)

    def test_round_requires_linked_run_in_same_workflow(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            store=UbuntuStore(Path(folder)/'ubuntu.sqlite3')
            raw,expected,binding=self.fixture();now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc)
            run=store.start_run(raw,expected,binding,now=now)
            stranger=WorkflowBinding('workflow-2','ubuntu','ubuntu:fixture','epoch','backend-2','2026-11-06T00:00:00+00:00')
            with self.assertRaises(ValueError):store.record_round(binding,'missing-run',mode='deterministic')
            with self.assertRaises(ValueError):store.record_round(stranger,run.run_id,mode='deterministic')
            with self.assertRaises(ValueError):store.start_run(raw,expected,stranger,now=now)
            with self.assertRaises(ValueError):store.record_round(binding,run.run_id,mode='invented')
            store.record_round(binding,run.run_id,mode='deterministic')
            with self.assertRaises(ValueError):store.record_round(binding,run.run_id,mode='agentic')
            self.assertEqual(len(store.rounds(binding)),1)
            self.assertEqual(store.rounds(stranger),())

    def test_changed_assessment_snapshot_and_removed_guard_are_refused(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'ubuntu.sqlite3';store=UbuntuStore(path)
            raw,expected,binding=self.fixture();now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc)
            run=store.start_run(raw,expected,binding,now=now)
            with closing(sqlite3.connect(store.paths[0])) as db:
                db.execute('DROP TRIGGER imported_assessments_no_UPDATE')
                db.execute("UPDATE imported_assessments SET snapshot='[]'");db.commit()
            with self.assertRaises(ValueError):store.get_evidence(run.digest,'ubuntu:fixture','epoch')
            self.assertTrue(store.consistency_errors())
            with self.assertRaises(ValueError):UbuntuStore(path)

    def test_foreign_derived_file_is_refused_before_any_file_is_created(self):
        from backends.ubuntu.storage import UbuntuStore
        with tempfile.TemporaryDirectory() as folder:
            foreign=Path(folder)/'ubuntu_agentic.sqlite3'
            with closing(sqlite3.connect(foreign)) as db:db.execute('CREATE TABLE agentic_rounds(id TEXT)');db.commit()
            before=foreign.read_bytes()
            with self.assertRaises(ValueError):UbuntuStore(Path(folder)/'ubuntu.sqlite3')
            self.assertEqual(foreign.read_bytes(),before)
            self.assertFalse((Path(folder)/'ubuntu.sqlite3').exists())
            self.assertFalse((Path(folder)/'ubuntu_framework.sqlite3').exists())
