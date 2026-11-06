"""Read-only database viewer (scripts/tools/show_database.py) over a simulated round. No real VM or model."""
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile

from hardening.framework import AssessmentRuns
from hardening.import_storage import ImportedEvidenceStore
from hardening.remediation import RemediationStore
from test_agentic import AgenticTestCase, FakeVm

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'tools' / 'show_database.py'
spec = importlib.util.spec_from_file_location('show_database', SCRIPT)
show_database = importlib.util.module_from_spec(spec)
spec.loader.exec_module(show_database)


class ShowDatabaseTests(AgenticTestCase):
    def setUp(self):
        # The dashboard's own file names: <imports>_framework and <imports>_agentic next to the imports file.
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        imports = ImportedEvidenceStore(self.folder / 'preview_imports.sqlite3')
        self.runtime = AssessmentRuns(imports)
        self.store = RemediationStore(self.folder / 'preview_imports_agentic.sqlite3', imports)

    def output(self, method, *args):
        viewer = show_database.Viewer(self.folder / 'preview_imports.sqlite3')
        buffer = io.StringIO()
        try:
            with redirect_stdout(buffer):
                getattr(viewer, method)(*args)
        finally:
            viewer.close()
        return buffer.getvalue()

    def fingerprint(self):
        return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(self.folder.glob('*'))}

    def test_views_show_a_round_from_scan_to_verdict_without_changing_any_file(self):
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        first, second = self.store.for_run(result['framework_run_id'])
        self.store.decide(first['proposal']['request_id'], approve=True, operator='admin01')
        self.store.decide(second['proposal']['request_id'], approve=False, operator='admin01')
        hardening.execute_approved(result['session_id'])
        before = self.fingerprint()

        overview = self.output('overview')
        for text in ('imported_assessments', 'framework_runs', 'rem_proposals', 'investigation_events',
                     'FIXTURE-SERVER', 'assessment', 'verification_scan', 'awaiting_approval'):
            self.assertIn(text, overview)

        plan = self.output('round', result['round_id'][:8], True)
        self.assertRegex(plan, r'1\s+1\.2\.2\s+REM-1\.2\.2\s+0 -> 5\s+\d+\s+approved by admin01\s+Verified compliant')
        self.assertIn('rejected by admin01', plan)
        self.assertIn('needs_review', plan)  # Deferred findings with their reason codes.
        self.assertIn('delegate_scanner({})', plan)  # Agent steps, without the repeated target_id.
        self.assertIn('Steps: Scanner Agent', plan)

        scan = self.output('scan', result['framework_run_id'][:10])  # A run ID prefix finds its scan.
        self.assertIn('1.2.2', scan)
        self.assertIn('not configured', scan)  # 9.3.1 is absent in the lab state, not "None".
        self.assertIn('between [1, 5]', scan)

        self.assertIn('Improvement', self.output('drift', 20))
        self.assertIn('REM-1.1.1', self.output('proposals', 20))
        raw = self.output('raw_table', 'imported_assessments', 1)
        self.assertIn('32 control results', raw)
        self.assertIn('<32 entries>', raw)  # The raw collector output is summarised, not dumped.

        self.assertEqual(self.fingerprint(), before)

    def test_missing_files_are_reported_not_created(self):
        empty = Path(tempfile.mkdtemp(dir=self.folder))
        viewer = show_database.Viewer(empty / 'preview_imports.sqlite3')
        self.assertFalse(any(viewer.db.values()))
        self.assertEqual(list(empty.iterdir()), [])
