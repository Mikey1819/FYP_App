from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hardening.actions import PASSWORD_LENGTH
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.vm_bridge import finding
from test_evidence_import import export_fixture, MACHINE_UUID


class FrameworkTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.imports = ImportedEvidenceStore(self.folder / "imports.sqlite3")
        self.runtime = AssessmentOrchestrator(self.imports)

    def start(self, payload=None):
        return self.runtime.start(json.dumps(payload or export_fixture()).encode(),
            expected_hostname="FIXTURE-SERVER", expected_machine_uuid=MACHINE_UUID)

    def test_restart_resumes_each_stage_and_completed_call_is_idempotent(self):
        payload = export_fixture()
        payload['observations'][0]['value'] = 0
        run = self.start(payload)
        for expected_role in ('Scanner Agent', 'Analysis Agent', 'Remediation Agent'):
            self.runtime = AssessmentOrchestrator(ImportedEvidenceStore(self.imports.path))
            run = self.runtime.advance(run.run_id)
            self.assertEqual(run.tasks[-1]['role'], expected_role)
        self.assertEqual(run.state, 'ready_for_review')
        self.assertEqual(run.tasks[-1]['output']['candidates'][0]['action_id'], PASSWORD_LENGTH.action_id)
        self.assertEqual(self.runtime.advance(run.run_id), run)
        self.assertIsNone(run.tasks[1]['output']['risk_score'])
        self.assertFalse(self.imports.path.with_name('imports_bridge.sqlite3').exists())

    def test_outcomes_distinguish_compliant_unknown_error_and_unsupported_findings(self):
        cases = [('compliant', None, 'assessment_complete'),
                 ('unknown', dict(state='missing', value=None), 'needs_review'),
                 ('error', dict(state='error', value=None, error='timeout'), 'needs_review'),
                 ('unsupported', dict(value=0), 'needs_review')]
        for name, changes, expected in cases:
            with self.subTest(name=name):
                payload = export_fixture()
                if changes:
                    payload['observations'][1 if name == 'unsupported' else 0].update(changes)
                run = self.runtime.complete_assessment(self.start(payload).run_id)
                self.assertEqual(run.state, expected)
                self.assertEqual(run.tasks[-1]['output']['candidates'], [])
                if name in ('unknown', 'error'):
                    self.assertIn('1.1.4', run.tasks[1]['output']['needs_evidence'])

    def test_same_evidence_creates_distinct_runs_without_duplicate_snapshot(self):
        first, second = self.start(), self.start()
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertEqual(first.evidence_sha256, second.evidence_sha256)
        self.assertEqual(len(self.imports.recent()), 1)
        self.runtime.complete_assessment(first.run_id)
        self.assertEqual(self.runtime.get(second.run_id).state, 'assessment_requested')

    def test_wrong_target_cannot_create_run(self):
        payload = export_fixture()
        payload['target']['hostname'] = 'OTHER-SERVER'
        with self.assertRaisesRegex(ValueError, 'selected target'):
            self.start(payload)
        with self.runtime._connection() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM framework_runs').fetchone()[0], 0)

    def test_concurrent_advances_do_not_duplicate_committed_tasks(self):
        run = self.start()
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda _: self.runtime.complete_assessment(run.run_id), range(4)))
        done = self.runtime.get(run.run_id)
        self.assertEqual(done.state, 'assessment_complete')
        self.assertEqual(len(done.tasks), 3)
        self.assertEqual(len({t['task_id'] for t in done.tasks}), 3)

    def test_failed_read_only_stage_can_resume_without_partial_result(self):
        run = self.start()
        with patch('hardening.agents.ScannerAgent.run', side_effect=ValueError('bad evidence')):
            with self.assertRaisesRegex(ValueError, 'bad evidence'):
                self.runtime.advance(run.run_id)
        pending = self.runtime.get(run.run_id)
        self.assertEqual(pending.state, 'assessment_requested')
        self.assertEqual(pending.tasks, ())
        self.assertEqual(self.runtime.complete_assessment(run.run_id).state, 'assessment_complete')

    def test_task_results_immutable_and_unknown_or_corrupt_state_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unknown framework run'):
            self.runtime.advance('unknown')
        run = self.runtime.complete_assessment(self.start().run_id)
        with self.assertRaises(sqlite3.IntegrityError):
            with self.runtime._connection() as db:
                db.execute('DELETE FROM framework_tasks WHERE run_id=?', (run.run_id,))
        with self.runtime._connection() as db:
            db.execute("UPDATE framework_runs SET state='execute' WHERE run_id=?", (run.run_id,))
        with self.assertRaisesRegex(ValueError, 'workflow state'):
            self.runtime.advance(run.run_id)

    def test_registry_eligibility_matches_bridge_boundaries(self):
        for value, expected in ((0, True), (13, True), (14, False), (15, False)):
            payload = export_fixture(); payload['observations'][0]['value'] = value
            run = self.runtime.complete_assessment(self.start(payload).run_id)
            record = self.imports.get(run.evidence_sha256)
            self.assertEqual(bool(run.tasks[-1]['output']['candidates']), expected)
            if expected:
                self.assertEqual(finding(record).evidence.value, value)
            else:
                with self.assertRaises(ValueError):
                    finding(record)

    def test_dispatch_rejects_altered_contract_before_invoking_role(self):
        run = self.start()
        task = self.runtime.next_task(run.run_id)
        for field, value in (('target_id', 'windows:other'), ('evidence_sha256', '0' * 64),
                             ('expected_state', 'findings_analysed'),
                             ('role', 'Remediation Agent'), ('operation', 'execute_approved')):
            with self.subTest(field=field), patch('hardening.agents.ScannerAgent.run') as scanner:
                with self.assertRaisesRegex(ValueError, 'mismatched assessment task'):
                    self.runtime.dispatch(replace(task, **{field: value}))
                scanner.assert_not_called()
                self.assertEqual(self.runtime.get(run.run_id), run)
        with self.assertRaisesRegex(ValueError, 'dispatch contract'):
            self.runtime.dispatch({'run_id': run.run_id})

    def test_delayed_duplicate_dispatch_cannot_advance_the_following_stage(self):
        run = self.start()
        task = self.runtime.next_task(run.run_id)
        # A task survives client restart, but is usable only at its bound state.
        restarted = AssessmentOrchestrator(ImportedEvidenceStore(self.imports.path))
        checked = restarted.dispatch(task)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            self.runtime.dispatch(task)
        self.assertEqual(self.runtime.get(run.run_id), checked)
        while (task := restarted.next_task(run.run_id)) is not None:
            restarted.dispatch(task)
        with self.assertRaisesRegex(ValueError, 'Stale'):
            restarted.dispatch(replace(self.runtime._next_task(run), operation='execute_approved'))
        self.assertEqual(len(restarted.get(run.run_id).tasks), 3)

    def test_concurrent_dispatch_of_same_message_commits_only_one_stage(self):
        run = self.start()
        task = self.runtime.next_task(run.run_id)
        def dispatch_once(_):
            try:
                return self.runtime.dispatch(task).state
            except ValueError as exc:
                return str(exc)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(dispatch_once, range(4)))
        self.assertEqual(results.count('assessment_checked'), 1)
        self.assertEqual(results.count('Stale or mismatched assessment task'), 3)
        self.assertEqual(len(self.runtime.get(run.run_id).tasks), 1)

    def test_run_bindings_and_task_history_cannot_be_replaced(self):
        run = self.runtime.complete_assessment(self.start().run_id)
        statements = [
            ('UPDATE framework_runs SET digest=? WHERE run_id=?', ('changed', run.run_id)),
            ('UPDATE framework_runs SET target_id=? WHERE run_id=?', ('other', run.run_id)),
            ('DELETE FROM framework_runs WHERE run_id=?', (run.run_id,)),
            ('INSERT OR REPLACE INTO framework_runs SELECT * FROM framework_runs WHERE run_id=?', (run.run_id,)),
            ('INSERT OR REPLACE INTO framework_tasks SELECT * FROM framework_tasks WHERE run_id=?', (run.run_id,)),
            # Conflict on position even with a new task ID.
            ("INSERT OR REPLACE INTO framework_tasks SELECT run_id,position,'new-id',role,operation,completed_at,output FROM framework_tasks WHERE run_id=? AND position=0", (run.run_id,)),
            # Conflict on task ID even with a new run/position pair.
            ("INSERT OR REPLACE INTO framework_tasks SELECT 'other-run',99,task_id,role,operation,completed_at,output FROM framework_tasks WHERE run_id=? AND position=0", (run.run_id,)),
        ]
        for sql, args in statements:
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                with self.runtime._connection() as db:
                    db.execute(sql, args)
            self.assertEqual(self.runtime.get(run.run_id), run)

    def test_existing_version_one_database_gains_guards_without_changing_results(self):
        run = self.runtime.complete_assessment(self.start().run_id)
        with self.runtime._connection() as db:
            for trigger in ('tasks_no_replace', 'runs_no_replace', 'runs_no_delete', 'runs_fixed_binding'):
                db.execute(f'DROP TRIGGER {trigger}')
        reopened = AssessmentOrchestrator(ImportedEvidenceStore(self.imports.path))
        self.assertEqual(reopened.get(run.run_id), run)
        with self.assertRaises(sqlite3.IntegrityError), reopened._connection() as db:
            db.execute('INSERT OR REPLACE INTO framework_tasks SELECT * FROM framework_tasks')

    def test_non_ui_client_and_separate_process_resume(self):
        evidence = self.folder / 'evidence.json'
        evidence.write_text(json.dumps(export_fixture()), encoding='utf-8')
        base = [sys.executable, '-B', '-m', 'hardening.framework', '--database', str(self.imports.path)]
        result = subprocess.run(base + ['--evidence', str(evidence), '--hostname', 'FIXTURE-SERVER',
            '--machine-uuid', MACHINE_UUID], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        run = json.loads(result.stdout)
        self.assertEqual(run['state'], 'assessment_complete')
        resumed = subprocess.run(base + ['--resume-run', run['run_id']], capture_output=True, text=True, timeout=30)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertEqual(json.loads(resumed.stdout), run)
        # The runtime remains importable in a process that refuses the UI/model modules.
        probe = subprocess.run([sys.executable, '-B', '-c',
            "import sys; sys.modules['streamlit']=None; sys.modules['hardening.ollama_client']=None; "
            "from hardening.framework import AssessmentOrchestrator"], capture_output=True, text=True, timeout=30)
        self.assertEqual(probe.returncode, 0, probe.stderr)


if __name__ == '__main__':
    unittest.main()
