from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from hardening.framework import LEGACY_STATES, AssessmentRuns, describe
from hardening.import_storage import ImportedEvidenceStore
from test_evidence_import import export_fixture, MACHINE_UUID


class FrameworkTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.imports = ImportedEvidenceStore(self.folder / "imports.sqlite3")
        self.runtime = AssessmentRuns(self.imports)

    def start(self, payload=None, **options):
        return self.runtime.start(json.dumps(payload or export_fixture()).encode(),
            expected_hostname="FIXTURE-SERVER", expected_machine_uuid=MACHINE_UUID, **options)

    def test_a_run_is_assessed_when_created_and_survives_restart(self):
        run = self.start()
        self.assertEqual(run.state, 'assessed')
        reopened = AssessmentRuns(ImportedEvidenceStore(self.imports.path))
        self.assertEqual(reopened.get(run.run_id), run)
        self.assertEqual(reopened.record(run.run_id).assessment.source_sha256, run.evidence_sha256)
        with reopened._connection() as db:  # No retired stage output is written for new runs.
            self.assertEqual(db.execute('SELECT count(*) FROM framework_tasks').fetchone()[0], 0)

    def test_same_evidence_creates_distinct_runs_without_duplicate_snapshot(self):
        first, second = self.start(), self.start()
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(first.evidence_sha256, second.evidence_sha256)
        self.assertEqual(len(self.imports.recent()), 1)

    def test_collection_request_id_is_idempotent_and_bound_to_its_evidence(self):
        request = 'a' * 32
        self.assertEqual(self.start(collection_request_id=request), self.start(collection_request_id=request))
        other = export_fixture(); other['observations'][0]['value'] = 3
        with self.assertRaisesRegex(ValueError, 'different evidence'):
            self.start(other, collection_request_id=request)
        with self.assertRaisesRegex(ValueError, 'collection request'):
            self.start(collection_request_id='not-hex')

    def test_wrong_target_cannot_create_run(self):
        payload = export_fixture()
        payload['target']['hostname'] = 'OTHER-SERVER'
        with self.assertRaisesRegex(ValueError, 'selected target'):
            self.start(payload)
        with self.runtime._connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM framework_runs').fetchone()[0], 0)

    def test_concurrent_starts_of_one_collection_record_one_run(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            runs = list(pool.map(lambda _: self.start(collection_request_id='b' * 32), range(4)))
        self.assertEqual(len(set(runs)), 1)
        with self.runtime._connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM framework_runs').fetchone()[0], 1)

    def test_unknown_or_corrupt_runs_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unknown framework run'):
            self.runtime.get('unknown')
        run = self.start()
        with self.runtime._connection() as db:
            db.execute('DROP TRIGGER runs_fixed_state')
            db.execute("UPDATE framework_runs SET state='execute' WHERE run_id=?", (run.run_id,))
        with self.assertRaisesRegex(ValueError, 'run state'):
            self.runtime.get(run.run_id)

    def test_runs_written_by_the_retired_staged_runtime_still_open(self):
        with self.runtime._connection() as db:
            for state in LEGACY_STATES:
                db.execute('INSERT INTO framework_runs VALUES (?,?,?,?,?)',
                           ('legacy-' + state, '0' * 64, 'windows:x', state, '2026-10-20T00:00:00+00:00'))
        self.assertEqual({self.runtime.get('legacy-' + s).state for s in LEGACY_STATES}, set(LEGACY_STATES))

    def test_run_bindings_cannot_be_replaced_or_changed(self):
        run = self.start()
        statements = [
            ('UPDATE framework_runs SET digest=? WHERE run_id=?', ('changed', run.run_id)),
            ('UPDATE framework_runs SET target_id=? WHERE run_id=?', ('other', run.run_id)),
            ('UPDATE framework_runs SET state=? WHERE run_id=?', ('needs_review', run.run_id)),
            ('DELETE FROM framework_runs WHERE run_id=?', (run.run_id,)),
            ('INSERT OR REPLACE INTO framework_runs SELECT * FROM framework_runs WHERE run_id=?', (run.run_id,)),
        ]
        for sql, args in statements:
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                with self.runtime._connection() as db:
                    db.execute(sql, args)
            self.assertEqual(self.runtime.get(run.run_id), run)

    def test_retired_task_history_stays_immutable(self):
        with self.runtime._connection() as db:
            db.execute("INSERT INTO framework_tasks VALUES ('r', 0, 't', 'Scanner Agent', 'old', 'now', '{}')")
        for sql in ("UPDATE framework_tasks SET output='{}'", 'DELETE FROM framework_tasks',
                    'INSERT OR REPLACE INTO framework_tasks SELECT * FROM framework_tasks'):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                with self.runtime._connection() as db:
                    db.execute(sql)

    def test_describe_gives_results_and_the_deterministic_ranking(self):
        payload = export_fixture(); payload['observations'][0]['value'] = 0  # Password length 0.
        view = describe(self.runtime, self.start(payload).run_id)
        self.assertEqual(view['summary']['selected'], len(payload['observations']))
        self.assertEqual(view['ranking'][0]['control_id'], '1.1.4')
        self.assertEqual(view['ranking'][0]['score'], 69)

    def test_non_ui_client_and_separate_process_reopen(self):
        evidence = self.folder / 'evidence.json'
        evidence.write_text(json.dumps(export_fixture()), encoding='utf-8')
        base = [sys.executable, '-B', '-m', 'hardening.framework', '--database', str(self.imports.path)]
        result = subprocess.run(base + ['--evidence', str(evidence), '--hostname', 'FIXTURE-SERVER',
            '--machine-uuid', MACHINE_UUID], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        run = json.loads(result.stdout)
        self.assertEqual(run['evidence'], 'Imported')
        reopened = subprocess.run(base + ['--run', run['run_id']], capture_output=True, text=True, timeout=30)
        self.assertEqual(reopened.returncode, 0, reopened.stderr)
        self.assertEqual(json.loads(reopened.stdout), run)
        # The register remains importable in a process that refuses the UI/model modules.
        probe = subprocess.run([sys.executable, '-B', '-c',
            "import sys; sys.modules['streamlit']=None; sys.modules['hardening.ollama_client']=None; "
            "from hardening.framework import AssessmentRuns, describe"], capture_output=True, text=True, timeout=30)
        self.assertEqual(probe.returncode, 0, probe.stderr)


if __name__ == '__main__':
    unittest.main()
