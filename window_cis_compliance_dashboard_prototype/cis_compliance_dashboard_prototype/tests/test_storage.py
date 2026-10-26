"""Persistence checks use temporary databases and synthetic evidence only."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from hardening.demo import CURRENT_RESULTS, PREVIOUS_RESULTS, TARGET_ID
from hardening.demo_storage import load_demo
from hardening.domain import EvidenceMode, Rule, Operator, Status, assess
from hardening.storage import AssessmentStore, RiskInput


class StorageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "assessment.sqlite3"
        self.store = AssessmentStore(self.path)

    def test_restart_in_a_separate_python_process_without_reseeding(self):
        view = load_demo(self.store)
        script = """
import json, sys
from hardening.storage import AssessmentStore
store = AssessmentStore(sys.argv[1])
snapshot = store.get('1042')
print(json.dumps({'values': [r.evidence.value for r in snapshot.results],
                  'risk': {r.control_id: r.factors.score for r in snapshot.risks},
                  'previous': [r.previous_assessment_id for r in snapshot.risks]}))
"""
        process = subprocess.run([sys.executable, "-B", "-c", script, str(self.path)],
                                 cwd=Path(__file__).resolve().parents[1],
                                 capture_output=True, text=True, timeout=20, check=True)
        data = json.loads(process.stdout)
        self.assertEqual(data["values"], [0, 8, False, True, False])
        self.assertIs(type(data["values"][0]), int)
        self.assertIs(type(data["values"][2]), bool)
        self.assertEqual(data["risk"], {"DEMO-NLA": 85, "DEMO-LOCKOUT": 70, "DEMO-PASSWORD": 56})
        self.assertEqual(data["previous"], ["1041"] * 3)
        self.assertEqual(view["summary"].compliance_percent, 40)
        self.assertEqual(self.store.get("1042").results, CURRENT_RESULTS)

    def test_duplicate_seeding_is_idempotent_but_changes_are_rejected(self):
        first = load_demo(self.store)
        self.assertEqual(load_demo(self.store), first)
        self.assertEqual(len(self.store.history(target_id=TARGET_ID, mode=EvidenceMode.SYNTHETIC)), 2)
        with self.assertRaises(ValueError):
            self.store.save(CURRENT_RESULTS, initiated_by="demo-admin")
        changed = tuple(assess(r.assessment_id, r.control, replace(r.evidence, source="Changed source"))
                        for r in CURRENT_RESULTS)
        with self.assertRaises(ValueError):
            self.store.save(changed, initiated_by="demo-admin", allow_identical=True)
        self.assertEqual(self.store.get("1042").results, CURRENT_RESULTS)

    def test_database_refuses_update_delete_and_inserts_with_duplicate_ids(self):
        load_demo(self.store)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for sql in ("UPDATE assessment_snapshots SET target_id = 'other'",
                        "DELETE FROM assessment_snapshots",
                        "INSERT OR REPLACE INTO assessment_snapshots SELECT * FROM assessment_snapshots",
                        "INSERT INTO assessment_snapshots SELECT * FROM assessment_snapshots"):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(sql)
        self.assertEqual(self.store.get("1042").results, CURRENT_RESULTS)

    def test_missing_failed_and_malformed_evidence_survives_storage(self):
        values = (None, "8", False, [True], {"unexpected": 1})
        results = tuple(assess("errors", r.control,
                              replace(r.evidence, value=value, error="Access denied" if index == 2 else None))
                        for index, (r, value) in enumerate(zip(CURRENT_RESULTS, values)))
        self.store.save(results, initiated_by="test")
        self.assertEqual(self.store.get("errors").results, results)
        self.assertEqual([r.status for r in results], [Status.UNKNOWN] + [Status.ERROR] * 4)
        self.assertEqual(self.store.get("errors").risks, ())

    def test_invalid_snapshot_is_not_partially_saved(self):
        invalid = (
            (), (CURRENT_RESULTS[0], CURRENT_RESULTS[0]),
            (replace(CURRENT_RESULTS[0], status=Status.COMPLIANT),),
            (CURRENT_RESULTS[0], replace(CURRENT_RESULTS[1], assessment_id="different")),
        )
        for results in invalid:
            with self.subTest(results=results), self.assertRaises(ValueError):
                self.store.save(results, initiated_by="test")
        self.assertEqual(self.store.history(target_id=TARGET_ID, mode=EvidenceMode.SYNTHETIC), ())

    def test_risk_inputs_require_source_and_valid_noncompliant_finding(self):
        for args in ((True, 3, 3, 3, "demo"), (4, 3, 3, 3, "")):
            with self.assertRaises(ValueError):
                RiskInput(*args)
        for key in ("unknown", "DEMO-GUEST"):
            with self.assertRaises(ValueError):
                self.store.save(CURRENT_RESULTS, initiated_by="test",
                                risk_inputs={key: RiskInput(4, 3, 3, 3, "demo")})
        self.assertEqual(self.store.history(target_id=TARGET_ID, mode=EvidenceMode.SYNTHETIC), ())

    def test_history_selects_latest_compatible_result_and_isolates_metadata(self):
        self.store.save(PREVIOUS_RESULTS, initiated_by="test")
        base = PREVIOUS_RESULTS[0]
        current = CURRENT_RESULTS[0]
        variants = (
            replace(base.evidence, target_id="other"),
            replace(base.evidence, mode=EvidenceMode.IMPORTED),
            replace(base.evidence, collected_at=current.evidence.collected_at + timedelta(days=1)),
        )
        for index, evidence in enumerate(variants):
            self.store.save((assess(f"other-{index}", base.control, evidence),), initiated_by="test")
        for index, control in enumerate((replace(base.control, catalogue_version="other"),
                                         replace(base.control, profile="other"),
                                         replace(base.control, rule=Rule(Operator.AT_LEAST, 1)))):
            self.store.save((assess(f"rules-{index}", control, base.evidence),), initiated_by="test")
        self.assertEqual(self.store.previous_result(current), base)
        newer = assess("newer", base.control, replace(base.evidence, collected_at=base.evidence.collected_at + timedelta(days=1)))
        self.store.save((newer,), initiated_by="test")
        self.assertEqual(self.store.previous_result(current), newer)
        self.assertIsNone(self.store.previous_result(replace(current, evidence=replace(current.evidence, target_id="absent"))))

    def test_importing_older_history_does_not_rewrite_saved_risk(self):
        self.store.save(CURRENT_RESULTS, initiated_by="test",
                        risk_inputs={"DEMO-LOCKOUT": RiskInput(4, 3, 3, 3, "synthetic")})
        original = self.store.get("1042")
        self.assertEqual(original.risks[0].factors.drift, 1)
        self.assertIsNone(original.risks[0].previous_assessment_id)
        self.store.save(PREVIOUS_RESULTS, initiated_by="test")
        self.assertEqual(self.store.get("1042"), original)

    def test_concurrent_identical_save_only_inserts_once(self):
        def save(_):
            return self.store.save(CURRENT_RESULTS, initiated_by="test", allow_identical=True)
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(save, range(2))), [False, True])

    def test_newer_schema_is_refused_without_reset(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA user_version = 99")
        with self.assertRaisesRegex(ValueError, "Unsupported database schema"):
            AssessmentStore(self.path)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 99)

    def test_missing_snapshot_does_not_create_one(self):
        with self.assertRaises(KeyError):
            self.store.get("missing")
        self.assertEqual(self.store.history(target_id=TARGET_ID, mode=EvidenceMode.SYNTHETIC), ())


if __name__ == "__main__":
    unittest.main()
