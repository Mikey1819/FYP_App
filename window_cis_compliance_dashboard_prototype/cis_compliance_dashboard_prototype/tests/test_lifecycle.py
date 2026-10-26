"""Offline lifecycle tests; all evidence and receipts are fixtures."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.investigation import Coordinator
from hardening.lifecycle import RemediationLifecycle
from hardening.vm_bridge import BridgeStore, encode
from test_evidence_import import export_fixture, MACHINE_UUID, NOW
from test_investigation import MockClient
import test_vm_bridge


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.imports = ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3')
        self.runtime = AssessmentOrchestrator(self.imports)
        self.bridge = BridgeStore(Path(folder.name) / 'bridge.sqlite3', self.imports)
        self.service = RemediationLifecycle(self.runtime, self.bridge)
        self.run = self.new_run()

    def new_run(self, value=0, complete=True):
        payload = export_fixture()
        payload['observations'][0]['value'] = value
        run = self.runtime.start(encode(payload), expected_hostname='FIXTURE-SERVER',
                                 expected_machine_uuid=MACHINE_UUID)
        if complete:
            run = self.runtime.complete_assessment(run.run_id)
            self.service.save_context(run.run_id, compatibility='compatible', operator='fixture',
                                      note='Fixture provisioning supports 14 characters.')
        return run

    def approve(self, run=None):
        run = run or self.run
        identifier = self.service.prepare(run.run_id)
        raw = self.service.decide(run.run_id, identifier, approve=True, operator='fixture-admin', now=NOW)
        return identifier, raw

    def receipt(self, identifier, request, value=14, status='applied'):
        return test_vm_bridge.BridgeTests.receipt(self, identifier, request, value, status)

    def test_proposal_creation_is_atomic_idempotent_and_concurrent(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            identifiers = list(pool.map(lambda _: self.service.prepare(self.run.run_id), range(4)))
        self.assertEqual(len(set(identifiers)), 1)
        self.assertEqual(self.service.get(self.run.run_id)['outcome'], 'awaiting_approval')
        another = self.new_run()
        with self.bridge._connection() as db:
            db.execute("""CREATE TRIGGER fail_link BEFORE INSERT ON framework_proposals
                BEGIN SELECT RAISE(ABORT, 'fixture failure'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.service.prepare(another.run_id)
        with self.bridge._connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM proposals').fetchone()[0], 1)
        self.assertEqual(self.service.get(another.run_id)['attempts'], [])

    def test_incomplete_compliant_and_unknown_cannot_create_proposal(self):
        for run in (self.new_run(complete=False), self.new_run(value=14)):
            with self.assertRaises(ValueError):
                self.service.prepare(run.run_id)
        payload = export_fixture()
        payload['observations'][0].update(state='missing', value=None)
        run = self.runtime.start(encode(payload), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        self.runtime.complete_assessment(run.run_id)
        with self.assertRaises(ValueError):
            self.service.prepare(run.run_id)
        with self.bridge._connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM proposals').fetchone()[0], 0)

    def test_same_evidence_other_run_and_unlinked_proposal_cannot_be_decided_or_imported(self):
        other = self.new_run()
        identifier, request = self.approve()
        raw = encode(self.receipt(identifier, request))
        with self.assertRaisesRegex(ValueError, 'different test request'):
            self.service.accept_receipt(other.run_id, identifier, raw, now=NOW + timedelta(hours=1))
        unlinked = self.bridge.propose(self.run.evidence_sha256)
        with self.assertRaises(ValueError):
            self.service.decide(self.run.run_id, unlinked, approve=True, operator='fixture')
        self.assertIsNone(self.bridge.get(unlinked)['decision'])
        self.assertIsNone(self.bridge.get(identifier)['verdict'])

    def test_rejection_retained_and_fresh_proposal_requires_exact_previous_id(self):
        first = self.service.prepare(self.run.run_id)
        self.service.decide(self.run.run_id, first, approve=False, operator='fixture-admin')
        self.assertEqual(self.service.get(self.run.run_id)['outcome'], 'rejected')
        self.assertIsNone(self.bridge.get(first)['request'])
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.service.prepare(self.run.run_id)
        second = self.service.prepare(self.run.run_id, expected_previous_id=first)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.service.prepare(self.run.run_id, expected_previous_id=first)
        state = self.service.get(self.run.run_id)
        self.assertEqual([a['outcome'] for a in state['attempts']], ['rejected', 'awaiting_approval'])
        self.assertNotEqual(first, second)
        self.assertEqual(state['attempts'][0]['decision_record']['operator'], 'fixture-admin')

    def test_success_survives_process_restart_and_preserves_all_input_references(self):
        identifier, request = self.approve()
        self.assertEqual(self.service.get(self.run.run_id)['outcome'], 'awaiting_receipt')
        raw = encode(self.receipt(identifier, request))
        state = self.service.accept_receipt(self.run.run_id, identifier, raw, now=NOW + timedelta(hours=1))
        self.assertEqual(state['outcome'], 'verified')
        self.assertEqual(self.service.accept_receipt(self.run.run_id, identifier, raw, now=NOW + timedelta(hours=1)), state)
        self.assertEqual(self.imports.get(self.run.evidence_sha256).assessment.results[0].evidence.value, 0)
        after = state['attempts'][0]['verification_evidence_sha256']
        self.assertEqual(self.imports.get(after).assessment.results[0].evidence.value, 14)
        code = """import sys,json
sys.modules['streamlit']=None
sys.modules['hardening.ollama_client']=None
from hardening.import_storage import ImportedEvidenceStore
from hardening.framework import AssessmentOrchestrator
from hardening.vm_bridge import BridgeStore
from hardening.lifecycle import RemediationLifecycle
imports=ImportedEvidenceStore(sys.argv[1])
service=RemediationLifecycle(AssessmentOrchestrator(imports),BridgeStore(sys.argv[2],imports))
print(json.dumps(service.get(sys.argv[3])))
"""
        result = subprocess.run([sys.executable, '-B', '-c', code, str(self.imports.path),
            str(self.bridge.path), self.run.run_id], text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), state)

    def test_failed_and_unavailable_verification_stop_without_another_proposal(self):
        for status, value in (('applied', 0), ('execution_failed', 14), ('verification_unavailable', None)):
            run = self.new_run()
            identifier, request = self.approve(run)
            receipt = self.receipt(identifier, request, value=0 if value is None else value, status=status)
            if value is None:
                receipt['after_evidence'] = None
            state = self.service.accept_receipt(run.run_id, identifier, encode(receipt), now=NOW + timedelta(hours=1))
            self.assertEqual(state['outcome'], 'unresolved')
            if value is None:
                self.assertIsNone(state['attempts'][0]['verification_evidence_sha256'])
            with self.assertRaises(ValueError):
                self.service.prepare(run.run_id, expected_previous_id=identifier)
            self.assertEqual(len(self.service.get(run.run_id)['attempts']), 1)

    def test_interrupted_snapshot_import_repaired_by_identical_receipt(self):
        identifier, request = self.approve()
        raw = encode(self.receipt(identifier, request))
        with patch.object(self.imports, 'save', side_effect=OSError('fixture interruption')):
            with self.assertRaises(OSError):
                self.service.accept_receipt(self.run.run_id, identifier, raw, now=NOW + timedelta(hours=1))
        self.assertEqual(self.service.get(self.run.run_id)['outcome'], 'receipt_import_incomplete')
        repaired = self.service.accept_receipt(self.run.run_id, identifier, raw, now=NOW + timedelta(hours=1))
        self.assertEqual(repaired['outcome'], 'verified')
        self.assertEqual(len(repaired['attempts']), 1)

    def test_model_proposal_is_linked_and_cannot_approve(self):
        tools = self.service.investigation_tools(self.run.run_id)
        args = dict(target_id=tools.target_id, control_id='1.1.4')
        responses = [{'tool_calls': [{'function': {'name': name, 'arguments': {
            **args, **({'reason': 'Fixture investigation'} if name == 'submit_remediation_proposal' else {})}}}]}
            for name in ('get_finding_evidence', 'get_operational_context', 'get_supported_remediation',
                         'submit_remediation_proposal')]
        run = Coordinator(MockClient(responses + [{'content': 'Review required.'}]), tools).run()
        self.assertEqual(run['framework_run_id'], self.run.run_id)
        self.assertEqual(self.service.get(self.run.run_id)['outcome'], 'awaiting_approval')
        self.assertIsNone(self.bridge.get(tools.proposal_id)['request'])

    def test_audit_links_and_bridge_records_refuse_replacement(self):
        identifier, _ = self.approve()
        for table in ('framework_proposals', 'proposals', 'decisions'):
            for statement in (f'DELETE FROM {table}', f'INSERT OR REPLACE INTO {table} SELECT * FROM {table}'):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    with self.bridge._connection() as db:
                        db.execute(statement)
        self.assertEqual(self.service.get(self.run.run_id)['attempts'][0]['proposal_id'], identifier)

    def test_existing_bridge_proposals_are_not_auto_attached(self):
        legacy = self.bridge.propose(self.run.evidence_sha256)
        reopened = RemediationLifecycle(self.runtime, BridgeStore(self.bridge.path, self.imports))
        self.assertEqual(reopened.get(self.run.run_id)['attempts'], [])
        self.assertEqual(self.bridge.get(legacy)['proposal']['evidence_sha256'], self.run.evidence_sha256)


if __name__ == '__main__':
    unittest.main()
