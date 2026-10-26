"""Proposal/approval records and the Remediation Agent (report Section 4.6.3).

The Orchestrator proposes a library action; the administrator approves or rejects
it here; the Remediation Agent executes only an approved request, once, over the
Scanner's WinRM channel, then verifies with the same collector and rule.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

from .action_library import LIBRARY
from .domain import Status
from .evidence_import import _no_duplicates, _object, _time, load_evidence
from .vm_bridge import encode
from .winrm_channel import ChannelError

APP = Path(__file__).resolve().parents[1]
RUNNER = APP.parent / 'scripts' / 'Invoke-RemediationAction.ps1'
APPROVAL_LIFETIME = timedelta(hours=1)
CLOCK_SKEW = timedelta(minutes=5)
TABLES = ('rem_proposals', 'rem_decisions', 'rem_receipts', 'agentic_rounds', 'drift_records',
          'investigation_runs', 'investigation_events')


def _now():
    return datetime.now(timezone.utc)


def _same_value(observed, expected):
    return type(observed) is type(expected) and observed == expected


class RemediationStore:
    """Append-only agentic records. Also hosts agent traces for the bounded Coordinator."""

    def __init__(self, path, imports):
        self.path, self.imports = Path(path), imports
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS rem_proposals (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, payload BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS rem_decisions (id TEXT PRIMARY KEY, decision TEXT NOT NULL, payload BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS rem_receipts (id TEXT PRIMARY KEY, payload BLOB NOT NULL, verdict TEXT NOT NULL)')
            db.execute('''CREATE TABLE IF NOT EXISTS agentic_rounds (id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
                created_at TEXT NOT NULL, payload TEXT NOT NULL)''')
            # ConfigurationDrift (report Section 4.5): one record per detected change between consecutive runs.
            db.execute('''CREATE TABLE IF NOT EXISTS drift_records (id TEXT PRIMARY KEY, target_id TEXT NOT NULL,
                current_run_id TEXT NOT NULL, control_id TEXT NOT NULL, payload TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS investigation_runs (run_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL,
                created_at TEXT NOT NULL, payload TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS investigation_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)''')
            for table in TABLES:
                key = {'investigation_events': 'sequence', 'investigation_runs': 'run_id'}.get(table, 'id')
                for operation in ('UPDATE', 'DELETE'):
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS {table}_no_{operation} BEFORE {operation} ON {table}
                        BEGIN SELECT RAISE(ABORT, 'Immutable agentic audit'); END''')
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table}
                    WHEN EXISTS (SELECT 1 FROM {table} WHERE {key}=NEW.{key})
                    BEGIN SELECT RAISE(ABORT, 'Agentic audit record already exists'); END''')

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    # Rounds: one Orchestrator assessment or one post-remediation verification scan.
    def add_round(self, session_id, kind, framework_run_id, *, round_id=None, **details):
        payload = dict(session_id=session_id, kind=kind, framework_run_id=framework_run_id, **details)
        identifier = round_id or uuid.uuid4().hex
        with self._connection() as db:
            db.execute('INSERT INTO agentic_rounds VALUES (?,?,?,?)',
                       (identifier, session_id, _now().isoformat(), json.dumps(payload)))
        return identifier

    def rounds(self, session_id):
        with self._connection() as db:
            rows = db.execute('SELECT id,created_at,payload FROM agentic_rounds WHERE session_id=? ORDER BY rowid',
                              (session_id,)).fetchall()
        return [dict(round_id=i, created_at=c, **json.loads(p)) for i, c, p in rows]

    def propose(self, *, session_id, framework_run_id, record, control_id, action_id, rank, reason, risk_score=None):
        action = LIBRARY.get(action_id)
        if action is None or action.control_id != control_id:
            raise ValueError('Action is not in the pre-approved library for this control')
        results = record.assessment.results
        result = next((r for r in results if r.control.control_id == control_id), None)
        if result is None or not action.eligible(result):
            raise ValueError('Only a confirmed non-compliant finding can receive a library action')
        if action.blocked_by(results):
            raise ValueError('Prerequisite controls are not compliant yet: ' + ', '.join(action.blocked_by(results)))
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            for (raw,) in db.execute('SELECT payload FROM rem_proposals WHERE run_id=?', (framework_run_id,)):
                if json.loads(raw)['control_id'] == control_id:
                    raise ValueError('This finding already has a proposal in this assessment')
            payload = dict(request_id=uuid.uuid4().hex, session_id=session_id, framework_run_id=framework_run_id,
                           evidence_sha256=record.assessment.source_sha256, hostname=record.assessment.hostname,
                           machine_uuid=record.assessment.target_id.removeprefix('windows:'),
                           control_id=control_id, action_id=action_id, value=action.target_value,
                           expected_before=result.evidence.value, rank=rank, risk_score=risk_score,
                           reason=str(reason)[:1000], proposed_by='AI Agent Orchestrator',
                           created_at=_now().isoformat())
            db.execute('INSERT INTO rem_proposals VALUES (?,?,?)',
                       (payload['request_id'], framework_run_id, encode(payload)))
        return payload

    def get(self, proposal_id):
        with self._connection() as db:
            row = db.execute('SELECT payload FROM rem_proposals WHERE id=?', (proposal_id,)).fetchone()
            if row is None:
                raise ValueError('Unknown remediation proposal')
            decision = db.execute('SELECT decision,payload FROM rem_decisions WHERE id=?', (proposal_id,)).fetchone()
            receipt = db.execute('SELECT verdict,payload FROM rem_receipts WHERE id=?', (proposal_id,)).fetchone()
        return dict(proposal=json.loads(row[0]), decision=decision[0] if decision else None,
                    request=decision[1] if decision and decision[0] == 'approved' else None,
                    decision_record=json.loads(decision[1]) if decision else None,
                    verdict=receipt[0] if receipt else None, receipt=receipt[1] if receipt else None)

    def for_run(self, framework_run_id):
        with self._connection() as db:
            ids = [r[0] for r in db.execute('SELECT id FROM rem_proposals WHERE run_id=? ORDER BY rowid',
                                            (framework_run_id,))]
        return sorted((self.get(i) for i in ids), key=lambda r: r['proposal']['rank'])

    def decide(self, proposal_id, *, approve, operator, comment='', now=None):
        if type(approve) is not bool or type(operator) is not str or not operator.strip() or len(operator) > 100:
            raise ValueError('An explicit decision and administrator name are required')
        now = now or _now()
        current = self.get(proposal_id)
        if current['decision'] is not None:
            raise ValueError('This proposal already has a decision; a new proposal needs a new scan')
        proposal = current['proposal']
        if approve:
            request = {k: proposal[k] for k in ('request_id', 'evidence_sha256', 'hostname', 'machine_uuid',
                                                'control_id', 'action_id', 'value', 'expected_before')}
            request.update(schema_version=2, approved_by=operator.strip(), approved_at=now.isoformat(),
                           expires_at=(now + APPROVAL_LIFETIME).isoformat())
            payload = encode(request)
        else:
            payload = encode(dict(operator=operator.strip(), comment=str(comment)[:500], at=now.isoformat()))
        with self._connection() as db:
            db.execute('INSERT INTO rem_decisions VALUES (?,?,?)',
                       (proposal_id, 'approved' if approve else 'rejected', payload))
        return payload if approve else None

    def record_refusal(self, proposal_id, state, detail):
        """Execution never started a write (refused before the VM ledger claim) or its outcome is uncertain."""
        payload = encode(dict(schema_version=2, request_id=proposal_id, status=state, error=str(detail)[:300]))
        verdict = {'channel_lost': 'Unresolved: outcome uncertain (channel lost); rescan to observe, never retry blindly',
                   'invalid_receipt': 'Unresolved: receipt failed validation (' + str(detail)[:150] + '); rescan to observe',
                   }.get(state, 'Refused before execution: ' + str(detail)[:200])
        with self._connection() as db:
            db.execute('INSERT INTO rem_receipts VALUES (?,?,?)', (proposal_id, payload, verdict))
        return verdict

    def accept_receipt(self, raw, *, now=None):
        if type(raw) is not bytes or len(raw) > 200000:
            raise ValueError('Receipt exceeds size limit')
        data = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_no_duplicates)
        _object(data, 'schema_version request_id request_sha256 status before_evidence after_evidence', 'receipt')
        if data['schema_version'] != 2 or data['status'] not in ('applied', 'execution_failed', 'verification_unavailable'):
            raise ValueError('Unsupported remediation receipt')
        record = self.get(data['request_id'])
        if record['request'] is None or hashlib.sha256(record['request']).hexdigest() != data['request_sha256']:
            raise ValueError('Receipt does not match an approved request')
        request = json.loads(record['request'])
        decoded = {}
        for key in ('before_evidence', 'after_evidence'):
            if data[key] is None and key == 'after_evidence':
                continue
            if type(data[key]) is not str:
                raise ValueError('Missing VM evidence in receipt')
            evidence = base64.b64decode(data[key], validate=True)
            assessed = load_evidence(evidence, expected_hostname=request['hostname'],
                                     expected_machine_uuid=request['machine_uuid'], now=now)
            started = _time(json.loads(evidence)['started_at'])
            if started < _time(request['approved_at']) - CLOCK_SKEW or assessed.collected_at > _time(request['expires_at']) + CLOCK_SKEW:
                raise ValueError('Receipt evidence outside the approval interval')
            decoded[key] = (evidence, assessed)
        control = request['control_id']
        before = next(r for r in decoded['before_evidence'][1].results if r.control.control_id == control)
        if before.status != Status.NON_COMPLIANT or not _same_value(before.evidence.value, request['expected_before']):
            raise ValueError('Precondition evidence does not match the approved observation')
        verdict = 'Unresolved: ' + data['status']
        if 'after_evidence' in decoded and data['status'] == 'applied':
            after = next(r for r in decoded['after_evidence'][1].results if r.control.control_id == control)
            verdict = 'Verified compliant' if after.status == Status.COMPLIANT else 'Verification failed'
        elif data['status'] == 'applied':
            raise ValueError('Successful execution requires fresh verification evidence')
        with self._connection() as db:
            db.execute('INSERT INTO rem_receipts VALUES (?,?,?)', (data['request_id'], raw, verdict))
        for evidence, _ in decoded.values():
            self.imports.save(evidence, expected_hostname=request['hostname'],
                              expected_machine_uuid=request['machine_uuid'], now=now)
        return verdict


class RemediationAgent:
    """Executes one approved request per call. No self-approval, no generated commands, no retry."""
    role = 'Remediation Agent'

    def __init__(self, store, scanner):
        self.store, self.scanner = store, scanner

    def execute(self, proposal_id, *, now=None):
        record = self.store.get(proposal_id)
        if record['decision'] != 'approved' or record['request'] is None:
            raise ValueError('Only an administrator-approved proposal can be executed')
        if record['verdict'] is not None:
            raise ValueError('This request was already attempted; it is never replayed')
        request = json.loads(record['request'])
        if _time(request['expires_at']) <= (now or _now()):
            raise ValueError('Approval expired; rescan and approve a new proposal')
        target = self.scanner.target
        if (request['hostname'].casefold() != target.hostname.casefold()
                or request['machine_uuid'].casefold() != target.machine_uuid.casefold()):
            raise ValueError('Approved request belongs to a different VM than the live connection')
        self.scanner.identity()
        parameters = dict(RequestJson=record['request'].decode('ascii'),
                          ExpectedRequestSha256=hashlib.sha256(record['request']).hexdigest(),
                          ExpectedComputerName=target.hostname, ExpectedMachineUuid=target.machine_uuid,
                          CollectorText=self.scanner.collector_text())
        try:
            output, had_errors, errors = self.scanner._run(RUNNER.read_text(encoding='utf-8-sig'), parameters)
        except ChannelError as exc:
            return self.store.record_refusal(proposal_id, 'channel_lost', exc.detail)
        if had_errors or len(output) != 1:
            return self.store.record_refusal(proposal_id, 'refused', errors[0] if errors else 'No receipt returned')
        try:
            return self.store.accept_receipt(output[0].encode('utf-8'), now=now)
        except (ValueError, KeyError, StopIteration) as exc:
            # The VM may have written before the receipt failed validation: uncertain, never retried.
            return self.store.record_refusal(proposal_id, 'invalid_receipt', str(exc))
