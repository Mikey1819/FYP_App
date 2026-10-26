"""Synthetic collection transport tests. The real worker/collector are never run."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import base64
import hashlib
import json
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.scan_exchange import ScanExchange
from hardening.vm_bridge import encode
from test_evidence_import import MACHINE_UUID, NOW
from test_full_controls import full_fixture


def response_fixture(request_raw):
    request = json.loads(request_raw)
    from datetime import datetime
    start = datetime.fromisoformat(request['created_at'])
    doc = full_fixture()
    doc['started_at'] = start.isoformat()
    doc['completed_at'] = start.isoformat()
    for row in doc['observations'] + doc['effective_context']:
        row['collected_at'] = start.isoformat()
    return dict(schema_version=1, request_id=request['request_id'], request_sha256=hashlib.sha256(request_raw).hexdigest(),
                status='collected', evidence=base64.b64encode(encode(doc)).decode(), error=None)


class ScanExchangeTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.runtime = AssessmentOrchestrator(ImportedEvidenceStore(self.folder / 'imports.sqlite3'))
        self.exchange = ScanExchange(self.runtime, self.folder / 'queue')

    def request(self):
        return self.exchange.request('FIXTURE-SERVER', MACHINE_UUID, now=NOW)['request_id']

    def test_request_is_fixed_idempotent_and_concurrent(self):
        with ThreadPoolExecutor(max_workers=3) as pool:
            ids = list(pool.map(lambda _: self.request(), range(3)))
        self.assertEqual(len(set(ids)), 1)
        raw = self.exchange.get(ids[0])
        self.assertEqual(json.loads(raw)['operation'], 'collect_server2022_evidence')
        self.assertNotIn('command', json.loads(raw))
        self.assertEqual(len(list(self.exchange.directory.glob('*-request.json'))), 1)
        self.assertEqual(self.exchange.poll(ids[0], now=NOW)['state'], 'awaiting_worker')

    def test_success_survives_restart_and_repeated_import_is_one_new_run(self):
        identifier = self.request(); raw = encode(response_fixture(self.exchange.get(identifier)))
        first = self.exchange.accept(identifier, raw, now=NOW)
        second = ScanExchange(self.runtime, self.exchange.directory).poll(identifier, now=NOW)
        self.assertEqual(first, second)
        self.assertEqual(first['state'], 'assessment_ready')
        self.assertEqual(len(self.runtime.get(first['framework_run_id']).tasks), 3)
        self.assertEqual(len(self.runtime.imports.recent()), 1)

    def test_interrupted_assessment_can_resume_from_saved_response(self):
        identifier = self.request(); raw = encode(response_fixture(self.exchange.get(identifier)))
        with patch.object(self.runtime, 'complete_assessment', side_effect=OSError('fixture interruption')):
            with self.assertRaises(OSError): self.exchange.accept(identifier, raw, now=NOW)
        result = self.exchange.poll(identifier, now=NOW)
        self.assertEqual(result['state'], 'assessment_ready')
        with self.runtime._connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM framework_runs').fetchone()[0], 1)

    def test_wrong_bindings_contract_and_old_evidence_rejected(self):
        identifier = self.request(); original = response_fixture(self.exchange.get(identifier))
        cases = []
        for key, value in [('schema_version', True), ('request_id', '0'*32), ('request_sha256', '0'*64),
                           ('status', 'applied'), ('evidence', 'invalid'), ('command', 'ignored?')]:
            data = dict(original); data[key] = value; cases.append(data)
        for mode in ('target', 'time', 'catalogue'):
            data = dict(original); evidence = json.loads(base64.b64decode(data['evidence']))
            if mode == 'target': evidence['target']['hostname'] = 'OTHER'
            elif mode == 'time':
                old = (NOW-timedelta(seconds=1)).isoformat()
                evidence['started_at'] = old; evidence['completed_at'] = old
                for row in evidence['observations']+evidence['effective_context']: row['collected_at'] = old
            else: evidence['schema_version'] = 3
            data['evidence'] = base64.b64encode(encode(evidence)).decode(); cases.append(data)
        for data in cases:
            with self.assertRaises(ValueError): self.exchange.accept(identifier, encode(data), now=NOW)
        self.assertEqual(len(self.runtime.imports.recent()), 0)

    def test_failure_expiry_and_path_rejection(self):
        identifier = self.request()
        self.assertEqual(self.exchange.poll(identifier, now=NOW+timedelta(minutes=11))['state'], 'expired')
        failed = response_fixture(self.exchange.get(identifier))
        failed.update(status='collection_failed', evidence=None, error='timeout')
        self.assertEqual(self.exchange.accept(identifier, encode(failed), now=NOW)['state'], 'collection_failed')
        self.assertEqual(len(self.runtime.imports.recent()), 0)
        for bad in ('../other', '', 'a'*33):
            with self.assertRaises(ValueError): self.exchange.get(bad)

    def test_replacement_response_and_database_mutation_rejected(self):
        identifier = self.request(); raw = encode(response_fixture(self.exchange.get(identifier)))
        self.exchange.accept(identifier, raw, now=NOW)
        with self.assertRaises(ValueError): self.exchange.accept(identifier, raw+b' ', now=NOW)
        with self.exchange._connection() as db:
            for sql in ('DELETE FROM scan_requests', 'UPDATE scan_responses SET payload="x"',
                        'INSERT OR REPLACE INTO scan_requests SELECT * FROM scan_requests'):
                with self.assertRaises(sqlite3.IntegrityError): db.execute(sql)

    def test_model_origin_must_match_target(self):
        data = full_fixture()
        run = self.runtime.start(encode(data), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        with self.assertRaises(ValueError):
            self.exchange.request('OTHER', MACHINE_UUID, origin_run_id=run.run_id, now=NOW)

    def test_powershell_helper_roundtrip_and_durable_claim(self):
        identifier = self.request()
        evidence = self.folder / 'evidence.json'
        evidence.write_bytes(base64.b64decode(response_fixture(self.exchange.get(identifier))['evidence']))
        script = Path(__file__).resolve().parents[2] / 'scripts' / 'fixture_scan_exchange.ps1'
        response = self.exchange._file(identifier, 'response')
        command = ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script),
                   '-RequestPath', str(self.exchange._file(identifier, 'request')), '-EvidencePath', str(evidence), '-OutputPath', str(response)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.exchange.poll(identifier, now=NOW)['state'], 'assessment_ready')
        original = response.read_bytes()
        repeat = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertNotEqual(repeat.returncode, 0)
        self.assertEqual(response.read_bytes(), original)

    def test_worker_rejects_extra_operation_fields_before_claim(self):
        identifier = self.request()
        request = json.loads(self.exchange.get(identifier)); request['command'] = 'do-not-run'
        path = self.folder / 'bad.json'; path.write_bytes(encode(request))
        output = self.folder / 'bad-response.json'
        script = Path(__file__).resolve().parents[2] / 'scripts' / 'fixture_scan_exchange.ps1'
        result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', str(script), '-RequestPath', str(path), '-EvidencePath', 'missing', '-OutputPath', str(output)],
            capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(str(output)+'.claimed').exists())
