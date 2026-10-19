"""SQLite storage for immutable assessment aggregates; no host or model access.

Each snapshot includes its catalogue, raw evidence and risk inputs/results. JSON
preserves evidence types; the catalogue is never reconstructed from today's rules.
This small preview reads history in Python using the shared compatibility rules.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

from .domain import (
    AssessmentResult, Control, Evidence, EvidenceMode, Operator, RiskFactors,
    Rule, Status, assess, comparable, prioritise, summarise,
)
from .workflow_schema import create_workflow_tables


@dataclass(frozen=True)
class RiskInput:
    impact: int
    exposure: int
    privilege: int
    likelihood: int
    source: str

    def __post_init__(self):
        RiskFactors(self.impact, self.exposure, self.privilege, self.likelihood, 1)
        if not isinstance(self.source, str) or not self.source.strip():
            raise ValueError("Risk inputs must identify their source")


@dataclass(frozen=True)
class StoredRisk:
    control_id: str
    factors: RiskFactors
    source: str
    previous_assessment_id: str | None


@dataclass(frozen=True)
class Snapshot:
    results: tuple[AssessmentResult, ...]
    initiated_by: str
    risks: tuple[StoredRisk, ...]


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


def _decode_snapshot(payload):
    data = json.loads(payload)
    return Snapshot(tuple(_decode_result(row) for row in data["results"]), data["initiated_by"],
                    tuple(StoredRisk(row["control_id"], RiskFactors(**row["factors"]),
                                     row["source"], row["previous_assessment_id"])
                          for row in data["risks"]))


class AssessmentStore:
    SCHEMA_VERSION = 3

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, self.SCHEMA_VERSION):
                raise ValueError(f"Unsupported database schema version: {version}")
            connection.execute("""CREATE TABLE IF NOT EXISTS assessment_snapshots (
                assessment_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                mode TEXT NOT NULL,
                started_utc TEXT NOT NULL,
                saved_utc TEXT NOT NULL,
                payload TEXT NOT NULL
            )""")
            for operation in ("UPDATE", "DELETE"):
                connection.execute(f"""CREATE TRIGGER IF NOT EXISTS snapshots_no_{operation.lower()}
                    BEFORE {operation} ON assessment_snapshots BEGIN
                    SELECT RAISE(ABORT, 'Assessment snapshots are immutable'); END""")
            # SQLite REPLACE can bypass DELETE triggers unless recursive triggers
            # are enabled. Refuse the conflicting insertion itself as well.
            connection.execute("""CREATE TRIGGER IF NOT EXISTS snapshots_no_replace
                BEFORE INSERT ON assessment_snapshots
                WHEN EXISTS (SELECT 1 FROM assessment_snapshots WHERE assessment_id = NEW.assessment_id)
                BEGIN SELECT RAISE(ABORT, 'Assessment snapshots are immutable'); END""")
            create_workflow_tables(connection)
            connection.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _previous(connection, current):
        candidates = []
        for (payload,) in connection.execute(
            "SELECT payload FROM assessment_snapshots WHERE target_id = ? AND mode = ?",
            (current.evidence.target_id, current.evidence.mode.value),
        ):
            candidates.extend(result for result in _decode_snapshot(payload).results
                              if comparable(result, current))
        return max(candidates, key=lambda result: result.evidence.collected_at, default=None)

    def previous_result(self, current: AssessmentResult) -> AssessmentResult | None:
        with self._connection() as connection:
            return self._previous(connection, current)

    def save(self, results: tuple[AssessmentResult, ...], *, initiated_by: str,
             risk_inputs: dict[str, RiskInput] | None = None,
             allow_identical: bool = False) -> bool:
        """Atomically save one assessment. Only explicit identical fixture seeding is idempotent.

        Risk scores/drift are computed here, never accepted from callers. Subsequent
        history imports do not silently revise a previously saved score.
        """
        if not results:
            raise ValueError("An assessment must contain selected controls")
        summarise(results)
        if not isinstance(initiated_by, str) or not initiated_by.strip():
            raise ValueError("Assessment initiator is required")
        for result in results:
            if result != assess(result.assessment_id, result.control, result.evidence):
                raise ValueError("Stored results must match deterministic assessment")
        inputs = dict(risk_inputs or {})
        eligible = {r.control.control_id for r in results if r.status == Status.NON_COMPLIANT}
        if not inputs.keys() <= eligible or any(not isinstance(v, RiskInput) for v in inputs.values()):
            raise ValueError("Risk inputs must refer to non-compliant findings in this assessment")
        request = {"results": [_encode_result(r) for r in results], "initiated_by": initiated_by,
                   "risk_inputs": {key: asdict(value) for key, value in sorted(inputs.items())}}
        # Validate JSON before opening a transaction; reject non-finite/arbitrary objects.
        request = json.loads(json.dumps(request, allow_nan=False))
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT payload FROM assessment_snapshots WHERE assessment_id = ?",
                                          (results[0].assessment_id,)).fetchone()
            if existing:
                stored = json.loads(existing[0])
                if allow_identical and all(stored[key] == value for key, value in request.items()):
                    return False
                raise ValueError("Assessment ID already exists; snapshots cannot be overwritten")
            risks = []
            for result in results:
                control_id = result.control.control_id
                if control_id not in inputs:
                    continue
                baseline = inputs[control_id]
                previous = self._previous(connection, result)
                factors = prioritise(result, impact=baseline.impact, exposure=baseline.exposure,
                                     privilege=baseline.privilege, likelihood=baseline.likelihood,
                                     previous=previous)
                risks.append(asdict(StoredRisk(control_id, factors, baseline.source,
                                               previous.assessment_id if previous else None)))
            request["risks"] = risks
            started = min(r.evidence.collected_at for r in results).astimezone(timezone.utc)
            connection.execute("INSERT INTO assessment_snapshots VALUES (?, ?, ?, ?, ?, ?)", (
                results[0].assessment_id, results[0].evidence.target_id, results[0].evidence.mode.value,
                started.isoformat(), datetime.now(timezone.utc).isoformat(),
                json.dumps(request, sort_keys=True, allow_nan=False),
            ))
        return True

    def get(self, assessment_id: str) -> Snapshot:
        with self._connection() as connection:
            row = connection.execute("SELECT payload FROM assessment_snapshots WHERE assessment_id = ?",
                                     (assessment_id,)).fetchone()
        if row is None:
            raise KeyError(assessment_id)
        return _decode_snapshot(row[0])

    def history(self, *, target_id: str, mode: EvidenceMode) -> tuple[Snapshot, ...]:
        with self._connection() as connection:
            rows = connection.execute("""SELECT payload FROM assessment_snapshots
                WHERE target_id = ? AND mode = ? ORDER BY started_utc DESC, assessment_id DESC""",
                                      (target_id, mode.value)).fetchall()
        return tuple(_decode_snapshot(row[0]) for row in rows)
