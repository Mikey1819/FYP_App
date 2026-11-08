"""Consistent backup, verification and restore drill of the application's SQLite stores (task 7 and task 17: backup and
restore instructions). Temporary directories only; the live data folder is never touched."""
from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path


def store(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as db:
        db.execute('CREATE TABLE t (v TEXT)')
        db.executemany('INSERT INTO t VALUES (?)', [(r,) for r in rows])
        db.commit()


def rows(path):
    with closing(sqlite3.connect(path)) as db:
        return [r[0] for r in db.execute('SELECT v FROM t ORDER BY v')]


class StoreBackupTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.data = self.root / 'app' / 'data'
        store(self.data / 'integration.sqlite3', ['ledger'])
        store(self.data / 'ubuntu' / 'integration_imports_agentic.sqlite3', ['round-1', 'round-2'])
        store(self.data / 'windows' / 'integration_imports.sqlite3', ['scan'])
        (self.data / 'agentic_evaluations').mkdir()
        (self.data / 'agentic_evaluations' / 'notes.txt').write_text('not a store')

    def test_backup_copies_every_store_with_a_manifest_and_verifies(self):
        from tools.backup_stores import backup, verify
        folder = backup(self.data, self.root / 'backups')
        manifest = json.loads((folder / 'manifest.json').read_text())
        self.assertEqual(sorted(manifest['files']), ['integration.sqlite3', 'ubuntu/integration_imports_agentic.sqlite3',
                                                     'windows/integration_imports.sqlite3'])
        self.assertTrue(all(f['integrity'] == 'ok' for f in manifest['files'].values()))
        self.assertEqual(verify(folder), [])
        self.assertEqual(rows(folder / 'ubuntu' / 'integration_imports_agentic.sqlite3'), ['round-1', 'round-2'])

    def test_backup_is_consistent_while_a_writer_holds_an_open_transaction(self):
        from tools.backup_stores import backup
        writer = sqlite3.connect(self.data / 'integration.sqlite3')
        self.addCleanup(writer.close)
        writer.execute('INSERT INTO t VALUES (?)', ('uncommitted',))  # open transaction, not committed
        folder = backup(self.data, self.root / 'backups')
        self.assertEqual(rows(folder / 'integration.sqlite3'), ['ledger'])

    def test_a_damaged_or_missing_backup_file_fails_verification(self):
        from tools.backup_stores import backup, verify
        folder = backup(self.data, self.root / 'backups')
        target = folder / 'windows' / 'integration_imports.sqlite3'
        target.write_bytes(target.read_bytes()[:-10] + b'0123456789')
        (folder / 'integration.sqlite3').unlink()
        problems = verify(folder)
        self.assertEqual(sorted(p.split(':')[0] for p in problems), ['integration.sqlite3',
                                                                     'windows/integration_imports.sqlite3'])

    def test_restore_drill_into_an_empty_folder_reproduces_every_store(self):
        from tools.backup_stores import backup, restore
        folder = backup(self.data, self.root / 'backups')
        target = self.root / 'restored'
        restore(folder, target)
        for name in ('integration.sqlite3', 'ubuntu/integration_imports_agentic.sqlite3',
                     'windows/integration_imports.sqlite3'):
            self.assertEqual(rows(target / name), rows(self.data / name), name)

    def test_restore_never_writes_into_a_folder_that_has_content(self):
        from tools.backup_stores import backup, restore
        folder = backup(self.data, self.root / 'backups')
        with self.assertRaises(ValueError):
            restore(folder, self.data)  # the live data folder
        self.assertEqual(rows(self.data / 'ubuntu' / 'integration_imports_agentic.sqlite3'), ['round-1', 'round-2'])

    def test_restore_refuses_a_backup_that_fails_verification(self):
        from tools.backup_stores import backup, restore
        folder = backup(self.data, self.root / 'backups')
        (folder / 'integration.sqlite3').write_bytes(b'not sqlite')
        with self.assertRaises(ValueError):
            restore(folder, self.root / 'restored')
        self.assertFalse((self.root / 'restored').exists())


if __name__ == '__main__':
    unittest.main()
