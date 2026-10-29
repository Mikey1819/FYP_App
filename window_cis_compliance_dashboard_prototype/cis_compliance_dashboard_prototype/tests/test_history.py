"""Assessment history and drift records with the simulated VM. No real VM."""
from datetime import datetime, timezone
import sqlite3
import unittest

from streamlit.testing.v1 import AppTest

from hardening.history import HistoryService
from hardening.risk import analyse
from hardening.evidence_import import encode
from hardening.winrm_channel import LiveScanner
from test_agentic import LAB_STATE, AgenticTestCase, FakeVm
from test_local_security_controls import local_security_fixture
from test_winrm_channel import MACHINE_UUID, target


class HistoryTests(AgenticTestCase):
    def scan(self, **state):
        scanner = LiveScanner(self.runtime, target(), session_factory=FakeVm(dict(LAB_STATE, **state)))
        return scanner.request(target().hostname, target().machine_uuid)['framework_run_id']

    def test_regression_then_improvement_recorded_once_each(self):
        history = HistoryService(self.runtime, self.store)
        compliant = self.scan(**{'1.2.2': 5, '1.2.1': 30, '1.2.4': 30})
        regressed = self.scan()
        repaired = self.scan(**{'1.2.2': 5, '1.2.1': 30, '1.2.4': 30})
        self.assertEqual(history.record_drift(compliant), [])  # No earlier run: nothing to compare.
        changes = {c['control_id']: c['change'] for c in history.record_drift(regressed)}
        self.assertEqual(changes, {'1.2.2': 'Regression', '1.2.1': 'Compliant -> Unknown', '1.2.4': 'Compliant -> Unknown'})
        history.record_drift(regressed)  # Idempotent.
        history.record_drift(repaired)
        records = history.drift_records('windows:' + MACHINE_UUID)
        self.assertEqual(len(records), 6)
        lockout = [(r['change'], r['before'], r['after']) for r in records if r['control_id'] == '1.2.2']
        self.assertEqual(lockout, [('Improvement', 0, 5), ('Regression', 5, 0)])  # Newest first.
        with self.store._connection() as db, self.assertRaises(sqlite3.IntegrityError):
            db.execute('DELETE FROM drift_records')
        # 32 controls: repaired state leaves 3 non-compliant + 2 Unknown; LAB_STATE has 4 + 4.
        self.assertEqual([r['compliant'] for r in history.runs()], [27, 24, 27])
        self.assertEqual(history.previous_run(repaired), regressed)

    def test_agentic_round_and_verification_record_drift_automatically(self):
        vm = FakeVm()
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        proposal = self.store.for_run(result['framework_run_id'])[0]['proposal']['request_id']
        self.store.decide(proposal, approve=True, operator='admin01')
        hardening.execute_approved(result['session_id'])
        changes = {r['control_id']: r['change'] for r in hardening.history.drift_records('windows:' + MACHINE_UUID)}
        self.assertEqual(changes, {'1.2.2': 'Improvement', '1.2.1': 'Unknown -> Compliant', '1.2.4': 'Unknown -> Compliant'})

    def test_history_spans_catalogue_versions_and_feeds_the_drift_factor(self):
        doc = local_security_fixture()  # Schema 4 (16 controls), as in the first real VM scan.
        stamp = datetime.now(timezone.utc).isoformat()
        doc['started_at'] = doc['completed_at'] = stamp
        for row in doc['observations'] + doc['effective_context']:
            row['collected_at'] = stamp
        old = self.runtime.start(encode(doc), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        new = self.scan()  # Schema 5 (32 controls) with lockout threshold regressed to 0.
        changes = {c['control_id']: c['change'] for c in HistoryService(self.runtime, self.store).compare(old.run_id, new)}
        self.assertEqual(changes['1.2.2'], 'Regression')
        self.assertEqual(changes['17.1.1'], 'New in this catalogue')
        older = self.runtime.imports.get(old.evidence_sha256)
        current = self.runtime.imports.get(self.runtime.get(new).evidence_sha256)
        # An uploaded file (Imported) and a channel scan (Live) use the same collector, so they stay comparable.
        self.assertEqual((older.assessment.results[0].evidence.mode.value, current.assessment.results[0].evidence.mode.value),
                         ('Imported', 'Live'))
        self.assertEqual([r['evidence'] for r in HistoryService(self.runtime, self.store).runs()], ['Imported', 'Live'])
        finding = next(f for f in analyse(current, [older]) if f.control_id == '1.2.2')
        self.assertEqual(finding.factors['D'], 5)


def history_page(path):
    from pathlib import Path
    from hardening.history_view import render_history
    render_history(Path(path))


class HistoryPageTests(AgenticTestCase):
    def test_page_shows_history_drift_and_comparison(self):
        for state in ({'1.2.2': 5, '1.2.1': 30, '1.2.4': 30}, {}):
            LiveScanner(self.runtime, target(), session_factory=FakeVm(dict(LAB_STATE, **state))).request(
                target().hostname, target().machine_uuid)
        app = AppTest.from_function(history_page, args=(str(self.runtime.imports.path),), default_timeout=30).run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertTrue(any('regression' in w.value for w in app.warning))
        frames = [f.value for f in app.dataframe]
        self.assertEqual(len(frames[0]), 2)  # Two assessments.
        self.assertIn('Regression', set(frames[1]['Change']))


if __name__ == '__main__':
    unittest.main()
