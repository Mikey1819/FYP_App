"""UI-independent durable assessment runtime; no model or security execution.

This deterministic controller is the F1 foundation, not a new AI planner.
Each advance commits one role result and state transition atomically. An
interrupted read-only stage can be resumed without duplicating committed tasks.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from uuid import uuid4, uuid5, NAMESPACE_URL
import re

from .agents import ScannerAgent, AnalysisAgent, RemediationAgent
from .import_storage import ImportedEvidenceStore


@dataclass(frozen=True)
class AssessmentRun:
    run_id: str
    evidence_sha256: str
    target_id: str
    state: str
    tasks: tuple[dict, ...]


@dataclass(frozen=True)
class AssessmentTask:
    """Read-only dispatch contract bound to one run, input and workflow state."""

    run_id: str
    evidence_sha256: str
    target_id: str
    expected_state: str
    role: str
    operation: str


STAGES = (ScannerAgent(), AnalysisAgent(), RemediationAgent())
PENDING = ("assessment_requested", "assessment_checked", "findings_analysed")
TERMINAL = ("ready_for_review", "needs_review", "assessment_complete")


class AssessmentOrchestrator:
    """Delegates registered read-only roles; approval remains outside this API."""

    def __init__(self, imports: ImportedEvidenceStore):
        self.imports = imports
        self.path = imports.path.with_name(imports.path.stem + "_framework.sqlite3")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            version = db.execute("PRAGMA user_version").fetchone()[0]
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if version not in (0, 1) or (tables and tables != {"framework_runs", "framework_tasks"}):
                raise ValueError("Unsupported framework database; existing data was not reset")
            db.execute("""CREATE TABLE IF NOT EXISTS framework_runs (
                run_id TEXT PRIMARY KEY, digest TEXT NOT NULL, target_id TEXT NOT NULL,
                state TEXT NOT NULL, created_at TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS framework_tasks (
                run_id TEXT NOT NULL, position INTEGER NOT NULL, task_id TEXT UNIQUE NOT NULL,
                role TEXT NOT NULL, operation TEXT NOT NULL, completed_at TEXT NOT NULL,
                output TEXT NOT NULL, PRIMARY KEY (run_id, position))""")
            for operation in ("UPDATE", "DELETE"):
                db.execute(f"""CREATE TRIGGER IF NOT EXISTS tasks_no_{operation}
                    BEFORE {operation} ON framework_tasks
                    BEGIN SELECT RAISE(ABORT, 'Task results are immutable'); END""")
            # SQLite REPLACE can delete conflicting rows without firing delete
            # triggers. Guard both unique keys before the implicit deletion.
            db.execute("""CREATE TRIGGER IF NOT EXISTS tasks_no_replace
                BEFORE INSERT ON framework_tasks WHEN EXISTS (
                    SELECT 1 FROM framework_tasks WHERE task_id = NEW.task_id
                    OR (run_id = NEW.run_id AND position = NEW.position))
                BEGIN SELECT RAISE(ABORT, 'Task result already exists'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS runs_no_replace
                BEFORE INSERT ON framework_runs WHEN EXISTS (
                    SELECT 1 FROM framework_runs WHERE run_id = NEW.run_id)
                BEGIN SELECT RAISE(ABORT, 'Framework run already exists'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS runs_no_delete
                BEFORE DELETE ON framework_runs
                BEGIN SELECT RAISE(ABORT, 'Framework runs are retained'); END""")
            db.execute("""CREATE TRIGGER IF NOT EXISTS runs_fixed_binding
                BEFORE UPDATE OF run_id, digest, target_id, created_at ON framework_runs
                BEGIN SELECT RAISE(ABORT, 'Framework run binding is immutable'); END""")
            db.execute("PRAGMA user_version = 1")

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def start(self, raw: bytes, *, expected_hostname: str, expected_machine_uuid: str,
              collection_request_id: str | None = None) -> AssessmentRun:
        if collection_request_id is not None and (type(collection_request_id) is not str or
                not re.fullmatch(r'[a-f0-9]{32}', collection_request_id)):
            raise ValueError('Invalid collection request ID')
        record, _ = self.imports.save(raw, expected_hostname=expected_hostname,
                                     expected_machine_uuid=expected_machine_uuid)
        run_id = (uuid5(NAMESPACE_URL, 'cis-collection:' + collection_request_id).hex
                  if collection_request_id else uuid4().hex)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT digest,target_id FROM framework_runs WHERE run_id=?', (run_id,)).fetchone()
            if existing and existing != (record.assessment.source_sha256, record.assessment.target_id):
                raise ValueError('Collection request already belongs to different evidence')
            if not existing:
                db.execute("INSERT INTO framework_runs VALUES (?, ?, ?, ?, ?)", (
                    run_id, record.assessment.source_sha256, record.assessment.target_id,
                    PENDING[0], datetime.now(timezone.utc).isoformat()))
        return self.get(run_id)

    def get(self, run_id: str) -> AssessmentRun:
        with self._connection() as db:
            return self._get(db, run_id)

    def _get(self, db, run_id):
        row = db.execute("SELECT run_id,digest,target_id,state FROM framework_runs WHERE run_id=?",
                         (run_id,)).fetchone()
        if row is None:
            raise ValueError("Unknown framework run")
        if row[3] not in PENDING + TERMINAL:
            raise ValueError("Invalid framework workflow state")
        tasks = tuple({"position": pos, "task_id": tid, "role": role, "operation": op,
                       "state": "completed", "completed_at": at, "output": json.loads(output)}
                      for pos, tid, role, op, at, output in db.execute(
                          "SELECT position,task_id,role,operation,completed_at,output "
                          "FROM framework_tasks WHERE run_id=? ORDER BY position", (run_id,)))
        expected = PENDING.index(row[3]) if row[3] in PENDING else len(STAGES)
        if len(tasks) != expected or any(t["position"] != i or t["role"] != STAGES[i].role
                or t["operation"] != STAGES[i].operation for i, t in enumerate(tasks)):
            raise ValueError("Invalid framework task sequence")
        return AssessmentRun(*row, tasks)

    def advance(self, run_id: str) -> AssessmentRun:
        """Advance the current stage atomically for an in-process client."""
        return self._advance(run_id)

    @staticmethod
    def _next_task(run: AssessmentRun) -> AssessmentTask | None:
        if run.state in TERMINAL:
            return None
        agent = STAGES[PENDING.index(run.state)]
        return AssessmentTask(run.run_id, run.evidence_sha256, run.target_id,
                              run.state, agent.role, agent.operation)

    def next_task(self, run_id: str) -> AssessmentTask | None:
        """Return the only permitted next task; this grants no execution authority."""
        return self._next_task(self.get(run_id))

    def dispatch(self, task: AssessmentTask) -> AssessmentRun:
        """Reject altered or stale messages before invoking any role."""
        if type(task) is not AssessmentTask:
            raise ValueError("Expected an AssessmentTask dispatch contract")
        return self._advance(task.run_id, task)

    def _advance(self, run_id: str, task: AssessmentTask | None = None) -> AssessmentRun:
        with self._connection() as db:
            # Serialise concurrent callers, including process restarts. These
            # bounded offline stages perform neither model calls nor writes to a VM.
            db.execute("BEGIN IMMEDIATE")
            run = self._get(db, run_id)
            if task is not None and task != self._next_task(run):
                raise ValueError("Stale or mismatched assessment task")
            if run.state in TERMINAL:
                return run
            record = self.imports.get(run.evidence_sha256)
            if record.assessment.target_id != run.target_id:
                raise ValueError("Run target does not match its evidence")
            position = PENDING.index(run.state)
            agent = STAGES[position]
            output = agent.run(record)
            if position < len(STAGES) - 1:
                next_state = PENDING[position + 1]
            elif output["candidates"]:
                next_state = "ready_for_review"
            elif output["assessment_only_findings"] or run.tasks[1]["output"]["needs_evidence"]:
                next_state = "needs_review"
            else:
                next_state = "assessment_complete"
            db.execute("INSERT INTO framework_tasks VALUES (?, ?, ?, ?, ?, ?, ?)", (
                run_id, position, uuid4().hex, agent.role, agent.operation,
                datetime.now(timezone.utc).isoformat(), json.dumps(output, allow_nan=False)))
            db.execute("UPDATE framework_runs SET state=? WHERE run_id=?", (next_state, run_id))
            return self._get(db, run_id)

    def complete_assessment(self, run_id: str) -> AssessmentRun:
        for _ in STAGES:
            run = self.advance(run_id)
            if run.state in TERMINAL:
                return run
        raise ValueError("Assessment did not reach a bounded terminal state")


def main():
    """Local imported-file client; never dispatches a VM action or invokes AI."""
    import argparse
    from dataclasses import asdict

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True, help="Imported evidence database path")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--evidence", type=Path)
    mode.add_argument("--resume-run")
    parser.add_argument("--hostname")
    parser.add_argument("--machine-uuid")
    args = parser.parse_args()
    if args.evidence and (not args.hostname or not args.machine_uuid):
        parser.error("--evidence requires --hostname and --machine-uuid")
    try:
        runtime = AssessmentOrchestrator(ImportedEvidenceStore(args.database))
        run_id = args.resume_run
        if args.evidence:
            from .evidence_import import MAX_BYTES
            with args.evidence.open("rb") as source:
                raw = source.read(MAX_BYTES + 1)
            run_id = runtime.start(raw, expected_hostname=args.hostname,
                                   expected_machine_uuid=args.machine_uuid).run_id
        print(json.dumps(asdict(runtime.complete_assessment(run_id)), indent=2, allow_nan=False))
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        parser.exit(1, f"Assessment could not complete: {exc}\n")


if __name__ == "__main__":
    main()
