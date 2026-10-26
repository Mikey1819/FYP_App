from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from hardening.import_storage import ImportedEvidenceStore
from test_evidence_import import export_fixture, MACHINE_UUID


class ImportStorageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / 'imports.sqlite3'
        self.store = ImportedEvidenceStore(self.path)
        self.raw = json.dumps(export_fixture()).encode()

    def save(self):
        return self.store.save(self.raw, expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)

    def test_saved_original_bytes_and_rules_survive_new_process(self):
        saved, inserted = self.save()
        self.assertTrue(inserted)
        self.assertEqual(saved.raw, self.raw)
        code = """
import json,sys
from hardening.import_storage import ImportedEvidenceStore
s=ImportedEvidenceStore(sys.argv[1]); r=s.get(s.recent()[0]['digest'])
print(json.dumps({'raw':r.raw.decode(), 'values':[x.evidence.value for x in r.assessment.results],
 'rules':[x.control.rule.expected for x in r.assessment.results]}))
"""
        process = subprocess.run([sys.executable, '-B', '-c', code, str(self.path)],
                                 capture_output=True, text=True, timeout=15,
                                 cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual(result['raw'].encode(), self.raw)
        self.assertEqual(result['rules'], [14, [1, 5], False, 1, 1])

    def test_duplicate_and_concurrent_uploads_preserve_first_snapshot(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.save(), range(2)))
        self.assertEqual(sum(inserted for _, inserted in results), 1)
        self.assertEqual(len(self.store.recent()), 1)
        first = results[0][0]
        again, inserted = self.save()
        self.assertFalse(inserted)
        self.assertEqual(first, again)

    def test_mismatched_or_malformed_data_saves_nothing(self):
        with self.assertRaises(ValueError):
            self.store.save(self.raw, expected_hostname='OTHER', expected_machine_uuid=MACHINE_UUID)
        with self.assertRaises(ValueError):
            self.store.save(b'{bad', expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        self.assertEqual(self.store.recent(), ())

    def test_error_and_unknown_survive_restart(self):
        data = export_fixture()
        data['observations'][0].update(state='error', value=None, error='timeout')
        data['observations'][4].update(state='missing', value=None)
        self.raw = json.dumps(data).encode()
        saved, _ = self.save()
        reopened = ImportedEvidenceStore(self.path).get(saved.assessment.source_sha256)
        self.assertEqual(reopened.assessment.results[0].status.value, 'Error')
        self.assertEqual(reopened.assessment.results[4].status.value, 'Unknown')

    def test_snapshots_reject_sql_overwrites_deletes_and_replacement(self):
        self.save()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for sql in ('UPDATE imported_assessments SET hostname="OTHER"',
                        'DELETE FROM imported_assessments',
                        'INSERT OR REPLACE INTO imported_assessments SELECT * FROM imported_assessments'):
                with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(sql)
        self.assertEqual(len(self.store.recent()), 1)

    def test_newer_schema_and_unrelated_database_preserved(self):
        other = self.path.parent / 'other.sqlite3'
        with closing(sqlite3.connect(other)) as connection, connection:
            connection.execute('CREATE TABLE unrelated (id INTEGER)')
        with self.assertRaises(ValueError): ImportedEvidenceStore(other)
        with closing(sqlite3.connect(other)) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 0)
            self.assertEqual(connection.execute('SELECT name FROM sqlite_master WHERE type="table"').fetchall(), [('unrelated',)])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute('PRAGMA user_version = 99')
        with self.assertRaises(ValueError): ImportedEvidenceStore(self.path)


if __name__ == '__main__':
    unittest.main()
