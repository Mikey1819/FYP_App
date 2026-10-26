"""Immutable imported snapshots and original bytes, isolated from demo workflows."""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from .domain import EvidenceMode, assess, summarise
from .evidence_import import ImportedAssessment, load_evidence
from .storage import _decode_result, _encode_result


@dataclass(frozen=True)
class SavedImport:
    assessment: ImportedAssessment
    imported_at: datetime
    raw: bytes


class ImportedEvidenceStore:
    """A separate database: imports cannot acquire simulated approvals or scores."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            existing = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if version not in (0, 1) or (existing and ('imported_assessments',) not in existing):
                raise ValueError("Unsupported imported-evidence database; existing data was not reset")
            connection.execute("""CREATE TABLE IF NOT EXISTS imported_assessments (
                digest TEXT PRIMARY KEY, hostname TEXT NOT NULL, target_id TEXT NOT NULL,
                collected_at TEXT NOT NULL, imported_at TEXT NOT NULL,
                snapshot TEXT NOT NULL, raw BLOB NOT NULL
            )""")
            for operation in ('UPDATE', 'DELETE'):
                connection.execute(f"""CREATE TRIGGER IF NOT EXISTS imports_no_{operation.lower()}
                    BEFORE {operation} ON imported_assessments BEGIN
                    SELECT RAISE(ABORT, 'Imported snapshots are immutable'); END""")
            connection.execute("""CREATE TRIGGER IF NOT EXISTS imports_no_replace
                BEFORE INSERT ON imported_assessments WHEN EXISTS
                (SELECT 1 FROM imported_assessments WHERE digest = NEW.digest)
                BEGIN SELECT RAISE(ABORT, 'Imported snapshot already exists'); END""")
            connection.execute('PRAGMA user_version = 1')

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save(self, raw: bytes, *, expected_hostname: str, expected_machine_uuid: str,
             now: datetime | None = None) -> tuple[SavedImport, bool]:
        # Validate again at the persistence boundary; no caller-supplied results/scores.
        result = load_evidence(raw, expected_hostname=expected_hostname,
                               expected_machine_uuid=expected_machine_uuid, now=now)
        imported_at = datetime.now(timezone.utc).isoformat()
        snapshot = json.dumps([_encode_result(r) for r in result.results], sort_keys=True, allow_nan=False)
        with self._connection() as connection:
            connection.execute('BEGIN IMMEDIATE')
            existing = connection.execute('SELECT raw FROM imported_assessments WHERE digest = ?',
                                          (result.source_sha256,)).fetchone()
            inserted = existing is None
            if existing:
                if existing[0] != raw:
                    raise ValueError('Existing digest has conflicting bytes')
            else:
                connection.execute('INSERT INTO imported_assessments VALUES (?, ?, ?, ?, ?, ?, ?)', (
                    result.source_sha256, result.hostname, result.target_id,
                    result.collected_at.astimezone(timezone.utc).isoformat(), imported_at, snapshot, raw))
        return self.get(result.source_sha256), inserted

    def get(self, digest: str) -> SavedImport:
        with self._connection() as connection:
            row = connection.execute('SELECT * FROM imported_assessments WHERE digest = ?', (digest,)).fetchone()
        if row is None:
            raise KeyError(digest)
        digest, hostname, target_id, collected_at, imported_at, snapshot, raw = row
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Stored source bytes failed integrity check')
        results = tuple(_decode_result(r) for r in json.loads(snapshot))
        summarise(results)
        if not results or any(r.evidence.target_id != target_id or r.evidence.mode != EvidenceMode.IMPORTED
                              or r.assessment_id != 'import-' + digest
                              or r != assess(r.assessment_id, r.control, r.evidence) for r in results):
            raise ValueError('Stored imported snapshot failed validation')
        return SavedImport(ImportedAssessment(results, target_id, hostname, digest,
                                              datetime.fromisoformat(collected_at)),
                           datetime.fromisoformat(imported_at), raw)

    def recent(self) -> tuple[dict, ...]:
        with self._connection() as connection:
            rows = connection.execute('''SELECT digest, hostname, target_id, collected_at, imported_at
                FROM imported_assessments ORDER BY collected_at DESC, digest DESC LIMIT 50''').fetchall()
        return tuple(dict(zip(('digest', 'hostname', 'target_id', 'collected_at', 'imported_at'), row))
                     for row in rows)
