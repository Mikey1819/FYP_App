"""Durable register of assessment runs; no model, no agent and no VM access.

Each scan (Scanner Agent collection, verification rescan or an evidence file given to the command-line client)
becomes one immutable run bound to its validated evidence snapshot and target. The agents live in agentic.py;
this register only records runs.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from uuid import uuid4, uuid5, NAMESPACE_URL
import re

from .domain import EvidenceMode, summarise
from .import_storage import ImportedEvidenceStore

SCHEMA = 2  # PRAGMA user_version of the run register database.


@dataclass(frozen=True)
class AssessmentRun:
    run_id: str
    evidence_sha256: str
    target_id: str


class AssessmentRuns:
    """Creates and reads runs. Approval, execution and AI stay outside this API."""

    def __init__(self, imports: ImportedEvidenceStore):
        self.imports = imports
        self.path = imports.path.with_name(imports.path.stem + "_framework.sqlite3")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if (tables and version != SCHEMA) or tables - {"framework_runs"}:
                raise ValueError("Unsupported framework database; existing data was not reset")
            db.execute("""CREATE TABLE IF NOT EXISTS framework_runs (
                run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, target_id TEXT NOT NULL, created_at TEXT NOT NULL)""")
            # SQLite REPLACE can delete a conflicting row without firing delete triggers: guard the key first.
            db.execute("""CREATE TRIGGER IF NOT EXISTS runs_no_replace
                BEFORE INSERT ON framework_runs WHEN EXISTS (
                    SELECT 1 FROM framework_runs WHERE run_id = NEW.run_id)
                BEGIN SELECT RAISE(ABORT, 'Framework run already exists'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS runs_no_delete
                BEFORE DELETE ON framework_runs
                BEGIN SELECT RAISE(ABORT, 'Framework runs are retained'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS runs_no_update
                BEFORE UPDATE ON framework_runs
                BEGIN SELECT RAISE(ABORT, 'Framework runs are immutable'); END""")
            db.execute(f"PRAGMA user_version = {SCHEMA}")

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def start(self, raw: bytes, *, expected_hostname: str, expected_machine_uuid: str,
              collection_request_id: str | None = None, mode: EvidenceMode = EvidenceMode.IMPORTED) -> AssessmentRun:
        """Validate and store the evidence, then record one assessed run for it."""
        if collection_request_id is not None and (type(collection_request_id) is not str or
                not re.fullmatch(r'[a-f0-9]{32}', collection_request_id)):
            raise ValueError('Invalid collection request ID')
        record, _ = self.imports.save(raw, expected_hostname=expected_hostname,
                                     expected_machine_uuid=expected_machine_uuid, mode=mode)
        run_id = (uuid5(NAMESPACE_URL, 'cis-collection:' + collection_request_id).hex
                  if collection_request_id else uuid4().hex)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT digest,target_id FROM framework_runs WHERE run_id=?', (run_id,)).fetchone()
            if existing and existing != (record.assessment.source_sha256, record.assessment.target_id):
                raise ValueError('Collection request already belongs to different evidence')
            if not existing:
                db.execute("INSERT INTO framework_runs VALUES (?, ?, ?, ?)", (
                    run_id, record.assessment.source_sha256, record.assessment.target_id,
                    datetime.now(timezone.utc).isoformat()))
        return self.get(run_id)

    def get(self, run_id: str) -> AssessmentRun:
        with self._connection() as db:
            row = db.execute("SELECT run_id,digest,target_id FROM framework_runs WHERE run_id=?",
                             (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown framework run")
        return AssessmentRun(*row)

    def record(self, run_id: str):
        """The validated evidence snapshot of a run."""
        run = self.get(run_id)
        record = self.imports.get(run.evidence_sha256)
        if record.assessment.target_id != run.target_id:
            raise ValueError("Run target does not match its evidence")
        return record


def describe(runs: AssessmentRuns, run_id: str) -> dict:
    """Deterministic view of one run: per-control results and the risk ranking (no model)."""
    from .risk import analyse
    record = runs.record(run_id)
    results = record.assessment.results
    summary = summarise(results)
    return dict(run_id=run_id, target_id=record.assessment.target_id, hostname=record.assessment.hostname,
                evidence_sha256=record.assessment.source_sha256, evidence=results[0].evidence.mode.value,
                summary=dict(selected=summary.selected, compliant=summary.compliant,
                             non_compliant=summary.non_compliant, unknown=summary.unknown, error=summary.errors,
                             compliance_percent=summary.compliance_percent),
                controls=[dict(control_id=r.control.control_id, status=r.status.value, observed=r.evidence.value)
                          for r in results],
                ranking=[dict(control_id=f.control_id, score=f.score, level=f.level, factors=f.factors)
                         for f in analyse(record)])


def main():
    """Non-UI client (evaluation E02): assess an evidence file or show a stored run. Never touches a VM or a model."""
    import argparse

    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("--database", type=Path, required=True, help="Imported evidence database path")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--evidence", type=Path)
    mode.add_argument("--run")
    parser.add_argument("--hostname")
    parser.add_argument("--machine-uuid")
    args = parser.parse_args()
    if args.evidence and (not args.hostname or not args.machine_uuid):
        parser.error("--evidence requires --hostname and --machine-uuid")
    try:
        runs = AssessmentRuns(ImportedEvidenceStore(args.database))
        run_id = args.run
        if args.evidence:
            from .evidence_import import MAX_BYTES
            with args.evidence.open("rb") as source:
                raw = source.read(MAX_BYTES + 1)
            run_id = runs.start(raw, expected_hostname=args.hostname, expected_machine_uuid=args.machine_uuid).run_id
        print(json.dumps(describe(runs, run_id), indent=2, allow_nan=False, default=str))
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"Assessment could not complete: {exc}\n")


if __name__ == "__main__":
    main()
