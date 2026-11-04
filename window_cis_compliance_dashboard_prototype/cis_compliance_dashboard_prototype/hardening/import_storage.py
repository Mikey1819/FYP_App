"""Immutable evidence snapshots (live scans and imported files) and their original bytes."""

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from .domain import AssessmentResult, Control, Evidence, EvidenceMode, Operator, Rule, Status, assess, summarise
from .evidence_import import ImportedAssessment, load_evidence
from .server2022_catalogue import CATALOGUE

# Results are always read back in catalogue order, whatever order a snapshot was saved in.
ORDER = {c.control_id: i for i, c in enumerate(CATALOGUE)}


def _encode_result(result):
    data = asdict(result)
    data["evidence"]["collected_at"] = result.evidence.collected_at.isoformat()
    return data


def _decode_result(data):
    control = dict(data["control"])
    rule = control["rule"]
    operator = Operator(rule["operator"])
    expected = tuple(rule["expected"]) if operator == Operator.BETWEEN else rule["expected"]
    control["rule"] = Rule(operator, expected)
    evidence = dict(data["evidence"])
    evidence["collected_at"] = datetime.fromisoformat(evidence["collected_at"])
    evidence["mode"] = EvidenceMode(evidence["mode"])
    return AssessmentResult(data["assessment_id"], Control(**control), Evidence(**evidence),
                            Status(data["status"]), data["detail"])


@dataclass(frozen=True)
class SavedImport:
    assessment: ImportedAssessment
    imported_at: datetime
    raw: bytes


class ImportedEvidenceStore:
    """Evidence only: approvals, rounds and drift live in the agentic database."""

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
             now: datetime | None = None, mode: EvidenceMode = EvidenceMode.IMPORTED) -> tuple[SavedImport, bool]:
        # Validate again at the persistence boundary; no caller-supplied results/scores.
        result = load_evidence(raw, expected_hostname=expected_hostname,
                               expected_machine_uuid=expected_machine_uuid, now=now, mode=mode)
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
        results = tuple(sorted((_decode_result(r) for r in json.loads(snapshot)),
                               key=lambda r: ORDER[r.control.control_id]))
        summarise(results)
        if not results or any(r.evidence.target_id != target_id or r.evidence.mode not in (EvidenceMode.IMPORTED, EvidenceMode.LIVE)
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
