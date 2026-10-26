"""File transport for one reviewed VM action. This module never executes commands."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from .domain import Status
from .actions import PASSWORD_LENGTH
from .evidence_import import load_evidence, _no_duplicates, _object, _time
from .vm_paths import workspace_path

ACTION = PASSWORD_LENGTH.action_id
CONTROL = PASSWORD_LENGTH.control_id
PARAMETERS = PASSWORD_LENGTH.parameters
IMPACT = PASSWORD_LENGTH.impact


def encode(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def finding(record):
    result = next(r for r in record.assessment.results if r.control.control_id == CONTROL)
    if not PASSWORD_LENGTH.eligible(result):
        raise ValueError("Only a confirmed non-compliant minimum password length is supported")
    return result


class BridgeStore:
    def __init__(self, path, imports):
        self.path, self.imports = Path(path), imports
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS machine_workspaces (
                target_id TEXT PRIMARY KEY, directory TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS proposals (
                id TEXT PRIMARY KEY, digest TEXT NOT NULL, payload BLOB NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY, decision TEXT NOT NULL, payload BLOB NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS receipts (
                id TEXT PRIMARY KEY, payload BLOB NOT NULL, verdict TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS investigation_runs (
                run_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS investigation_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL,
                kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)""")
            for table in ("proposals", "decisions", "receipts", "investigation_runs", "investigation_events"):
                for operation in ("UPDATE", "DELETE"):
                    db.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_{operation}
                        BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'Immutable VM audit'); END""")
                key = "sequence" if table == "investigation_events" else "run_id" if table == "investigation_runs" else "id"
                db.execute(f"""CREATE TRIGGER IF NOT EXISTS {table}_no_replace
                    BEFORE INSERT ON {table} WHEN EXISTS (SELECT 1 FROM {table} WHERE {key}=NEW.{key})
                    BEGIN SELECT RAISE(ABORT, 'VM audit record already exists'); END""")

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _proposal_payload(self, digest, reason):
        record = self.imports.get(digest)
        result = finding(record)
        payload = dict(request_id=uuid.uuid4().hex, evidence_sha256=digest,
                       hostname=record.assessment.hostname,
                       machine_uuid=record.assessment.target_id.removeprefix("windows:"),
                       control_id=CONTROL, action_id=ACTION, parameters=PARAMETERS,
                       expected_before=result.evidence.value, reason=str(reason)[:2000],
                       created_at=datetime.now(timezone.utc).isoformat())
        return payload

    def propose(self, digest, reason="Deterministic recommendation from the reviewed minimum-length rule."):
        payload = self._proposal_payload(digest, reason)
        with self._connection() as db:
            db.execute("INSERT INTO proposals VALUES (?, ?, ?)", (payload["request_id"], digest, encode(payload)))
        return payload["request_id"]

    def workspace(self, digest):
        target = self.imports.get(digest).assessment.target_id
        with self._connection() as db:
            row = db.execute("SELECT directory FROM machine_workspaces WHERE target_id=?", (target,)).fetchone()
        return workspace_path(row[0]) if row else None

    def save_workspace(self, digest, directory):
        target = self.imports.get(digest).assessment.target_id
        directory = workspace_path(directory)
        with self._connection() as db:
            db.execute("""INSERT INTO machine_workspaces VALUES (?, ?)
                ON CONFLICT(target_id) DO UPDATE SET directory=excluded.directory""", (target, directory))
        return directory

    def get(self, identifier):
        with self._connection() as db:
            row = db.execute("SELECT payload FROM proposals WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise ValueError("Unknown VM proposal")
            decision = db.execute("SELECT decision,payload FROM decisions WHERE id=?", (identifier,)).fetchone()
            receipt = db.execute("SELECT verdict,payload FROM receipts WHERE id=?", (identifier,)).fetchone()
        return dict(proposal=json.loads(row[0]), decision=decision[0] if decision else None,
                    request=decision[1] if decision and decision[0] == "approved" else None,
                    verdict=receipt[0] if receipt else None,
                    decision_record=json.loads(decision[1]) if decision else None,
                    receipt=receipt[1] if receipt else None)

    def recent(self, digest):
        with self._connection() as db:
            rows = db.execute("SELECT id FROM proposals WHERE digest=? ORDER BY rowid DESC LIMIT 20", (digest,)).fetchall()
        return [self.get(r[0]) for r in rows]

    def decide(self, identifier, *, approve, operator, now=None):
        if type(approve) is not bool or not operator.strip() or len(operator) > 100:
            raise ValueError("An explicit decision and operator name are required")
        now = now or datetime.now(timezone.utc)
        proposal = self.get(identifier)["proposal"]
        finding(self.imports.get(proposal["evidence_sha256"]))
        request = {k: v for k, v in proposal.items() if k not in ("reason", "created_at")}
        request.update(schema_version=1, approved_by=operator.strip(), approved_at=now.isoformat(),
                       expires_at=(now + timedelta(hours=24)).isoformat())
        payload = encode(request if approve else {"operator": operator.strip(), "at": now.isoformat()})
        with self._connection() as db:
            db.execute("INSERT INTO decisions VALUES (?, ?, ?)",
                       (identifier, "approved" if approve else "rejected", payload))
        return payload if approve else None

    def accept_receipt(self, raw, *, now=None, expected_request_id=None):
        if type(raw) is not bytes or len(raw) > 200000:
            raise ValueError("VM receipt exceeds size limit")
        data = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicates)
        _object(data, "schema_version request_id request_sha256 status before_evidence after_evidence", "receipt")
        if expected_request_id is not None and data["request_id"] != expected_request_id:
            raise ValueError("Receipt belongs to a different test request; return the receipt for this test")
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError("Unsupported receipt version")
        record = self.get(data["request_id"])
        request_bytes = record["request"]
        if request_bytes is None or hashlib.sha256(request_bytes).hexdigest() != data["request_sha256"]:
            raise ValueError("Receipt does not match an approved request")
        request = json.loads(request_bytes)
        if data["status"] not in ("applied", "execution_failed", "verification_unavailable"):
            raise ValueError("Unsupported runner outcome")
        decoded = {}
        for key in ("before_evidence", "after_evidence"):
            value = data[key]
            if value is None and key == "after_evidence":
                continue
            if type(value) is not str:
                raise ValueError("Missing VM evidence")
            try:
                evidence = base64.b64decode(value, validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("Invalid receipt evidence encoding") from exc
            assessed = load_evidence(evidence, expected_hostname=request["hostname"],
                                     expected_machine_uuid=request["machine_uuid"], now=now)
            start = _time(json.loads(evidence)["started_at"])
            if start < _time(request["approved_at"]) or assessed.collected_at > _time(request["expires_at"]):
                raise ValueError("Receipt evidence outside approval interval")
            decoded[key] = (evidence, assessed, start)
        before = next(r for r in decoded["before_evidence"][1].results if r.control.control_id == CONTROL)
        if before.status != Status.NON_COMPLIANT or before.evidence.value != request["expected_before"]:
            raise ValueError("Runner precondition evidence does not match the approved observation")
        verdict = "Unresolved: " + data["status"]
        if "after_evidence" in decoded:
            _, after, start = decoded["after_evidence"]
            if start < decoded["before_evidence"][1].collected_at:
                raise ValueError("Verification precedes the precondition check")
            if data["status"] == "applied":
                checked = next(r for r in after.results if r.control.control_id == CONTROL)
                verdict = "Verified compliant" if checked.status == Status.COMPLIANT else "Verification failed"
        elif data["status"] == "applied":
            raise ValueError("Successful execution requires fresh verification evidence")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT payload,verdict FROM receipts WHERE id=?", (data["request_id"],)).fetchone()
            if old:
                if old[0] != raw:
                    raise ValueError("A different receipt is already recorded; review manually")
            else:
                db.execute("INSERT INTO receipts VALUES (?, ?, ?)", (data["request_id"], raw, verdict))
        # Preserve fresh snapshots separately. Idempotent, so an interrupted import can be repeated.
        for evidence, _, _ in decoded.values():
            self.imports.save(evidence, expected_hostname=request["hostname"],
                              expected_machine_uuid=request["machine_uuid"], now=now)
        return verdict
