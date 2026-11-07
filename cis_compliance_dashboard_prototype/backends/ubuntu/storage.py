"""Ubuntu persistence: three isolated SQLite files with the Windows store's 11 table purposes.

File 0 holds validated sanitized evidence bytes, file 1 framework runs, file 2 agentic records.
The files are not one atomic transaction: evidence is written first, runs and rounds are
idempotent, and broken cross-file links are reported rather than repaired or invented.

Reads re-validate stored bytes against the time they were received. A historical read is not
fresh evidence and never authorises new work; freshness for new work is checked by its caller.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import NAMESPACE_URL, uuid5

from system.contracts import WorkflowBinding, encode_record
from .envelope import ExpectedEvidence, parse_bundle

def _rules(rules):
    from .predicates import CIS_AUDIT_WORDING_V1, CIS_AUDIT_WORDING_V2
    versions = {'v1': CIS_AUDIT_WORDING_V1, 'v2': CIS_AUDIT_WORDING_V2}
    return {**rules, 'audit_wording': versions[rules['audit_wording']]} if 'audit_wording' in rules else rules


# Documented interpretation decisions, newest last; a stored scan may match the rules in force when it was stored.
EARLIER_RULES = (dict(ssh_effective_authority=False, cis_audit_authority=False),  # before both decisions
                 dict(cis_audit_authority=False),  # after the SSH decision, before the 6.3.3.4 wording decision
                 dict(audit_wording='v1'),  # 6.3.3.4 reviewed, 6.3.3.8 not yet (live 11:20 scan)
                 dict(audit_wording='v2'))  # 6.3.3.4 and 6.3.3.8 reviewed, 5.3.3.2.2 not yet (live 15:17, 15:18)
from .predicates import Assessment

PAYLOAD_VERSION = 1
ROUND_MODES = ('deterministic', 'agentic')

# (table, DDL, unique keys). Unique keys feed the anti-REPLACE triggers: SQLite REPLACE deletes
# conflicting rows without firing DELETE triggers, so every unique key is guarded before insert.
_EVIDENCE = (
    ('imported_assessments', '''CREATE TABLE imported_assessments (
        digest TEXT PRIMARY KEY, request_id TEXT NOT NULL, target_id TEXT NOT NULL,
        registration_epoch TEXT NOT NULL, hostname TEXT NOT NULL, evidence_mode TEXT NOT NULL,
        collected_at TEXT NOT NULL, imported_at TEXT NOT NULL, payload_version INTEGER NOT NULL,
        expected TEXT NOT NULL, snapshot TEXT NOT NULL, raw BLOB NOT NULL,
        UNIQUE(target_id, registration_epoch, request_id))''',
     (('digest',), ('target_id', 'registration_epoch', 'request_id'))),
)
_FRAMEWORK = (
    ('framework_runs', '''CREATE TABLE framework_runs (
        run_id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, target_id TEXT NOT NULL,
        registration_epoch TEXT NOT NULL, workflow_session_id TEXT NOT NULL,
        state TEXT NOT NULL, created_at TEXT NOT NULL)''',
     (('run_id',), ('digest',))),
    # Legacy purpose retained for parity with the Windows store; nothing writes here.
    ('framework_tasks', '''CREATE TABLE framework_tasks (
        run_id TEXT NOT NULL, position INTEGER NOT NULL, task_id TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL, operation TEXT NOT NULL, completed_at TEXT NOT NULL,
        output TEXT NOT NULL, PRIMARY KEY (run_id, position))''',
     (('task_id',), ('run_id', 'position'))),
)
_AGENTIC = (
    ('agentic_rounds', '''CREATE TABLE agentic_rounds (
        id TEXT PRIMARY KEY, session_id TEXT NOT NULL, target_id TEXT NOT NULL,
        registration_epoch TEXT NOT NULL, framework_run_id TEXT NOT NULL,
        created_at TEXT NOT NULL, payload TEXT NOT NULL)''', (('id',),)),
    ('investigation_runs', '''CREATE TABLE investigation_runs (run_id TEXT PRIMARY KEY,
        assessment_id TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)''', (('run_id',),)),
    ('investigation_events', '''CREATE TABLE investigation_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL, kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL)''',
     (('sequence',),)),
    ('rem_proposals', 'CREATE TABLE rem_proposals (id TEXT PRIMARY KEY, run_id TEXT NOT NULL, payload BLOB NOT NULL)',
     (('id',),)),
    ('rem_decisions', 'CREATE TABLE rem_decisions (id TEXT PRIMARY KEY, decision TEXT NOT NULL, payload BLOB NOT NULL)',
     (('id',),)),
    ('rem_comments', 'CREATE TABLE rem_comments (id TEXT PRIMARY KEY, payload TEXT NOT NULL)', (('id',),)),
    ('rem_receipts', 'CREATE TABLE rem_receipts (id TEXT PRIMARY KEY, payload BLOB NOT NULL, verdict TEXT NOT NULL)',
     (('id',),)),
    ('drift_records', '''CREATE TABLE drift_records (id TEXT PRIMARY KEY, target_id TEXT NOT NULL,
        current_run_id TEXT NOT NULL, control_id TEXT NOT NULL, payload TEXT NOT NULL)''', (('id',),)),
)
# PRAGMA application_id marks each file as this store's; a Windows or unknown database never matches.
_FILES = ((0x55425645, '', _EVIDENCE), (0x55425646, '_framework', _FRAMEWORK), (0x55425641, '_agentic', _AGENTIC))
_SCHEMA_VERSION = 1


def _triggers(table, keys):
    clash = ' OR '.join('(' + ' AND '.join(f'{c}=NEW.{c}' for c in key) + ')' for key in keys)
    yield (f'{table}_no_UPDATE', f'''CREATE TRIGGER {table}_no_UPDATE BEFORE UPDATE ON {table}
        BEGIN SELECT RAISE(ABORT, 'Ubuntu records are append-only'); END''')
    yield (f'{table}_no_DELETE', f'''CREATE TRIGGER {table}_no_DELETE BEFORE DELETE ON {table}
        BEGIN SELECT RAISE(ABORT, 'Ubuntu records are append-only'); END''')
    yield (f'{table}_no_replace', f'''CREATE TRIGGER {table}_no_replace BEFORE INSERT ON {table}
        WHEN EXISTS (SELECT 1 FROM {table} WHERE {clash})
        BEGIN SELECT RAISE(ABORT, 'Ubuntu record already exists'); END''')


def _objects(tables):
    names = set()
    for table, _, keys in tables:
        names.add(table)
        names.update(name for name, _ in _triggers(table, keys))
    return frozenset(names)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _snapshot(assessments):
    return _canonical([{'control_id': a.control_id, 'status': a.status.value,
                        'checks': [[c.name, c.state, c.reason] for c in a.checks]} for a in assessments])


def _utc_now(now):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset().total_seconds() != 0:
        raise ValueError('UTC validation time required')
    return now


def _stamp():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class StoredEvidence:
    """Sanitized evidence as validated when received. Historical; not fresh authority for new work."""
    raw: bytes
    raw_sha256: str
    expected: ExpectedEvidence
    started_at: str
    completed_at: str
    received_at: str
    assessments: tuple[Assessment, ...]


@dataclass(frozen=True)
class UbuntuRun:
    run_id: str
    digest: str
    target_id: str
    registration_epoch: str
    workflow_session_id: str
    state: str
    created_at: str


@dataclass(frozen=True)
class UbuntuRound:
    round_id: str
    framework_run_id: str
    evidence_sha256: str
    kind: str
    mode: str
    created_at: str
    details: dict | None = None


@dataclass(frozen=True)
class StoredProposal:
    proposal_id: str
    payload: dict
    decision: str | None
    approved_raw: bytes | None
    receipts: tuple


class AgentLogStore:
    """The agentic file's investigation tables, in the shape the unchanged Windows InvestigationLog writes to."""

    def __init__(self, path):
        self.path = Path(path)

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()


class UbuntuStore:
    def __init__(self, path):
        base = Path(path)
        self.paths = tuple(base.with_name(base.stem + suffix + '.sqlite3') if suffix else base
                           for _, suffix, _ in _FILES)
        base.parent.mkdir(parents=True, exist_ok=True)
        # Inspect every file read-only first: a foreign database is refused before anything is written.
        states = [self._inspect(p, app_id, tables) for p, (app_id, _, tables) in zip(self.paths, _FILES)]
        for p, state, (app_id, _, tables) in zip(self.paths, states, _FILES):
            if state == 'new':
                self._create(p, app_id, tables)

    # ---- schema ownership -------------------------------------------------------------------
    @staticmethod
    def _inspect(path, app_id, tables):
        if not path.exists() or path.stat().st_size == 0:
            return 'new'
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)) as db:
            found = db.execute('PRAGMA application_id').fetchone()[0]
            version = db.execute('PRAGMA user_version').fetchone()[0]
            names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        if (found, version, names) == (0, 0, set()):
            return 'new'
        if found != app_id or version != _SCHEMA_VERSION:
            raise ValueError('Refusing to adopt or modify a database that is not this Ubuntu store')
        if names != _objects(tables):
            raise ValueError('Ubuntu store schema or append-only guards were altered; refusing to use it')
        return 'ready'

    @staticmethod
    def _create(path, app_id, tables):
        with closing(sqlite3.connect(path, timeout=5)) as db, db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchone()[0]:
                # Another process initialised it meanwhile; accept only an exact match.
                db.rollback()
                UbuntuStore._inspect(path, app_id, tables)
                return
            for table, ddl, keys in tables:
                db.execute(ddl)
                for _, trigger in _triggers(table, keys):
                    db.execute(trigger)
            db.execute(f'PRAGMA application_id={app_id}')
            db.execute(f'PRAGMA user_version={_SCHEMA_VERSION}')

    def _db(self, index):
        db = sqlite3.connect(self.paths[index], timeout=5)
        db.row_factory = sqlite3.Row
        return closing(db)

    # ---- evidence (file 0) ------------------------------------------------------------------
    def save_evidence(self, raw, expected, *, now=None):
        """Validate fresh evidence and store its exact bytes; an identical replay is idempotent."""
        if type(raw) is not bytes or type(expected) is not ExpectedEvidence:
            raise ValueError('Evidence bytes and expected ownership required')
        digest = hashlib.sha256(raw).hexdigest()
        with self._db(0) as db:
            row = db.execute('SELECT raw, expected FROM imported_assessments WHERE digest=?', (digest,)).fetchone()
        if row is not None:
            if row['raw'] != raw or row['expected'] != _canonical(expected.__dict__):
                raise ValueError('Existing evidence digest has conflicting bytes or ownership')
            # Recovery replay: validated against its original receipt time, not re-declared fresh.
            return self.get_evidence(digest, expected.target_id, expected.registration_epoch)
        received = _utc_now(now)
        bundle = parse_bundle(raw, expected, now=received)
        with self._db(0) as db, db:
            db.execute('BEGIN IMMEDIATE')
            clash = db.execute('''SELECT digest FROM imported_assessments WHERE digest=? OR
                (target_id=? AND registration_epoch=? AND request_id=?)''',
                (digest, expected.target_id, expected.registration_epoch, expected.request_id)).fetchone()
            if clash is not None and clash['digest'] != digest:
                raise ValueError('Collection request already has different evidence')
            if clash is None:
                db.execute('INSERT INTO imported_assessments VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (
                    digest, expected.request_id, expected.target_id, expected.registration_epoch,
                    expected.hostname, expected.evidence_mode, bundle.completed_at, received.isoformat(),
                    PAYLOAD_VERSION, _canonical(expected.__dict__), _snapshot(bundle.assessments), raw))
        return self.get_evidence(digest, expected.target_id, expected.registration_epoch)

    def get_evidence(self, digest, target_id, registration_epoch):
        with self._db(0) as db:
            row = db.execute('SELECT * FROM imported_assessments WHERE digest=?', (digest,)).fetchone()
        if row is None or (row['target_id'], row['registration_epoch']) != (target_id, registration_epoch):
            raise ValueError('No stored evidence for this target and registration epoch')
        raw = row['raw']
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Stored evidence bytes failed integrity check')
        if row['payload_version'] != PAYLOAD_VERSION:
            raise ValueError('Unsupported stored evidence payload version')
        try:
            expected = ExpectedEvidence(**json.loads(row['expected']))
        except (TypeError, json.JSONDecodeError):
            raise ValueError('Stored evidence ownership is malformed') from None
        if ((expected.target_id, expected.registration_epoch, expected.request_id, expected.hostname,
             expected.evidence_mode) != (row['target_id'], row['registration_epoch'], row['request_id'],
                                         row['hostname'], row['evidence_mode'])):
            raise ValueError('Stored evidence ownership columns disagree')
        imported = datetime.fromisoformat(row['imported_at'])
        bundle = parse_bundle(raw, expected, now=imported)
        if bundle.completed_at != row['collected_at']:
            raise ValueError('Stored assessment differs from current predicate evaluation; reassessment required')
        if _snapshot(bundle.assessments) != row['snapshot']:
            # Only a documented interpretation change may explain a difference: the stored snapshot must match an
            # earlier rule set exactly; the evidence is then shown under the current rules.
            # Every scan stored before the 2.1.2 retention registration was evaluated without that review.
            candidates = [dict(r, reviewed_avahi_retention=False) for r in ({},) + EARLIER_RULES] + list(EARLIER_RULES)
            if not any(_snapshot(parse_bundle(raw, expected, now=imported, **_rules(rules)).assessments) == row['snapshot']
                       for rules in candidates):
                raise ValueError('Stored assessment differs from current predicate evaluation; reassessment required')
        return StoredEvidence(raw, digest, expected, bundle.started_at, bundle.completed_at,
                              row['imported_at'], bundle.assessments)

    # ---- framework runs (file 1) ------------------------------------------------------------
    def start_run(self, raw, expected, binding, *, now=None):
        """Persist evidence first, then one idempotent run for it. Creates no round."""
        self._check_binding(binding, expected.target_id, expected.registration_epoch)
        evidence = self.save_evidence(raw, expected, now=now)
        run_id = uuid5(NAMESPACE_URL, _canonical(['ubuntu-run', evidence.raw_sha256])).hex
        with self._db(1) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM framework_runs WHERE digest=?', (evidence.raw_sha256,)).fetchone()
            if row is None:
                db.execute('INSERT INTO framework_runs VALUES (?,?,?,?,?,?,?)', (
                    run_id, evidence.raw_sha256, binding.target_id, binding.registration_epoch,
                    binding.workflow_session_id, 'assessed', _stamp()))
                row = db.execute('SELECT * FROM framework_runs WHERE run_id=?', (run_id,)).fetchone()
        run = UbuntuRun(*row)
        if (run.run_id, run.target_id, run.registration_epoch, run.workflow_session_id) != (
                run_id, binding.target_id, binding.registration_epoch, binding.workflow_session_id):
            raise ValueError('Evidence already belongs to another workflow run')
        return run

    def history(self, target_id, registration_epoch):
        with self._db(1) as db:
            rows = db.execute('''SELECT * FROM framework_runs WHERE target_id=? AND registration_epoch=?
                ORDER BY created_at, rowid''', (target_id, registration_epoch)).fetchall()
        return tuple(UbuntuRun(*r) for r in rows)

    def _run(self, run_id):
        with self._db(1) as db:
            row = db.execute('SELECT * FROM framework_runs WHERE run_id=?', (run_id,)).fetchone()
        return UbuntuRun(*row) if row else None

    # ---- agentic rounds (file 2) ------------------------------------------------------------
    def agent_log(self):
        return AgentLogStore(self.paths[2])

    def record_round(self, binding, run_id, *, mode, details=None, kind='assessment'):
        """Record one round for an existing, linked run. Idempotent per workflow, run and kind.

        `details` holds an agentic round's references and validated outcomes (never model free text beyond
        the bounded goal); a deterministic assessment has none. A `verification` round is a deterministic fresh
        scan after execution and names the assessment round it verifies.
        """
        self._check_binding(binding, binding.target_id, binding.registration_epoch)
        if mode not in ROUND_MODES or kind not in ('assessment', 'verification'):
            raise ValueError('Unsupported round mode or kind')
        if details is not None and (type(details) is not dict or len(_canonical(details)) > 65536):
            raise ValueError('Round details must be bounded')
        if kind == 'verification':
            if mode != 'deterministic' or not details or set(details) != {'verifies_round', 'request_ids'}:
                raise ValueError('A verification round is deterministic and names what it verifies')
        elif (mode == 'deterministic') != (details is None):
            raise ValueError('Agentic rounds need bounded details; deterministic rounds have none')
        run = self._run(run_id)
        if run is None or (run.target_id, run.registration_epoch, run.workflow_session_id) != (
                binding.target_id, binding.registration_epoch, binding.workflow_session_id):
            raise ValueError('Round requires a stored run in the same workflow, target and epoch')
        self.get_evidence(run.digest, run.target_id, run.registration_epoch)
        payload = _canonical({'payload_version': PAYLOAD_VERSION, 'kind': kind, 'mode': mode,
                              'binding': json.loads(encode_record(binding)), 'framework_run_id': run.run_id,
                              'evidence_sha256': run.digest, **({'details': details} if details is not None else {})})
        round_id = uuid5(NAMESPACE_URL, _canonical(['ubuntu-round', binding.workflow_session_id,
                                                    run.run_id, kind])).hex
        with self._db(2) as db, db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT payload FROM agentic_rounds WHERE id=?', (round_id,)).fetchone()
            if row is not None:
                if row['payload'] != payload:
                    raise ValueError('Round already recorded with different details')
                return round_id
            db.execute('INSERT INTO agentic_rounds VALUES (?,?,?,?,?,?,?)', (
                round_id, binding.backend_session_id, binding.target_id, binding.registration_epoch,
                run.run_id, _stamp(), payload))
        return round_id

    def rounds(self, binding):
        encoded = json.loads(encode_record(binding))
        with self._db(2) as db:
            rows = db.execute('''SELECT * FROM agentic_rounds WHERE session_id=? AND target_id=?
                AND registration_epoch=? ORDER BY created_at, rowid''',
                (binding.backend_session_id, binding.target_id, binding.registration_epoch)).fetchall()
        result = []
        for row in rows:
            payload = json.loads(row['payload'])
            if payload['binding'] == encoded:
                result.append(UbuntuRound(row['id'], row['framework_run_id'], payload['evidence_sha256'],
                                          payload['kind'], payload['mode'], row['created_at'], payload.get('details')))
        return tuple(result)

    # ---- proposals, decisions, comments, receipts (file 2) ----------------------------------
    def add_proposal(self, binding, plan, *, title, preview):
        """Persist one deterministic, unapproved plan for a round of this workflow. Idempotent."""
        from vm.ubuntu.remediation_schema import canonical
        self._check_binding(binding, binding.target_id, binding.registration_epoch)
        f = plan.fields
        if (f['target_id'], f['registration_epoch'], f['workflow_session_id']) != (
                binding.target_id, binding.registration_epoch, binding.workflow_session_id):
            raise ValueError('Plan belongs to another workflow, target or registration epoch')
        row = next((r for r in self.rounds(binding) if r.round_id == f['round_id']), None)
        if row is None:
            raise ValueError('Plan must belong to a recorded round of this workflow')
        if type(title) is not str or not 0 < len(title) <= 200 or type(preview) is not dict:
            raise ValueError('Invalid proposal presentation')
        payload = canonical({'payload_version': PAYLOAD_VERSION, 'proposal_id': plan.proposal_id,
                             'workflow_session_id': binding.workflow_session_id, 'round_id': f['round_id'],
                             'action': {'action_id': plan.spec.action_id, 'version': plan.spec.version,
                                        'implementation_sha256': plan.spec.implementation_sha256},
                             'fields': f, 'title': title, 'preview': preview})
        with self._db(2) as db, db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT payload FROM rem_proposals WHERE id=?', (plan.proposal_id,)).fetchone()
            if old is not None:
                if bytes(old['payload']) != payload:
                    raise ValueError('Proposal ID already holds another plan')
                return plan.proposal_id
            db.execute('INSERT INTO rem_proposals VALUES (?,?,?)', (plan.proposal_id, row.framework_run_id, payload))
        return plan.proposal_id

    def _proposal(self, binding, proposal_id):
        self._check_binding(binding, binding.target_id, binding.registration_epoch)
        with self._db(2) as db:
            row = db.execute('SELECT payload FROM rem_proposals WHERE id=?', (proposal_id,)).fetchone()
        payload = json.loads(bytes(row['payload'])) if row else None
        if (payload is None or payload['workflow_session_id'] != binding.workflow_session_id
                or (payload['fields']['target_id'], payload['fields']['registration_epoch'])
                != (binding.target_id, binding.registration_epoch)):
            raise ValueError('No such proposal in this workflow, target and registration epoch')
        return payload

    def record_decision(self, binding, proposal_id, *, approved=None, rejected=None):
        """One append-only decision per proposal: exact approved bytes, or a rejection that writes nothing."""
        from vm.ubuntu.remediation_schema import canonical, parse_request
        from .actions import PLAN_FIELDS
        payload = self._proposal(binding, proposal_id)
        if (approved is None) == (rejected is None):
            raise ValueError('Decide by approval or rejection')
        if approved is not None:
            request = parse_request(approved.raw)
            if (hashlib.sha256(approved.raw).hexdigest() != approved.sha256 or request['proposal_id'] != proposal_id
                    or any(request[k] != payload['fields'][k] for k in PLAN_FIELDS) or request['action'] != payload['action']):
                raise ValueError('Approval does not match the stored plan exactly')
            decision, data = 'approved', approved.raw
        else:
            operator, at = rejected
            if type(operator) is not str or not 0 < len(operator.strip()) <= 128:
                raise ValueError('A named operator is required to reject')
            decision, data = 'rejected', canonical({'decision': 'rejected', 'proposal_id': proposal_id,
                                                    'operator': operator.strip(), 'decided_at': _utc_now(at).isoformat()})
        with self._db(2) as db, db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT decision, payload FROM rem_decisions WHERE id=?', (proposal_id,)).fetchone()
            if old is not None:
                if (old['decision'], bytes(old['payload'])) != (decision, data):
                    raise ValueError('Proposal already decided')
                return True
            db.execute('INSERT INTO rem_decisions VALUES (?,?,?)', (proposal_id, decision, data))
        return False

    def add_comment(self, binding, proposal_id, operator, text, at):
        """Optional comment, kept apart from the approval bytes."""
        from vm.ubuntu.remediation_schema import canonical
        self._proposal(binding, proposal_id)
        if type(text) is not str or not 0 < len(text) <= 1000 or type(operator) is not str or not operator.strip():
            raise ValueError('Invalid comment')
        data = canonical({'proposal_id': proposal_id, 'operator': operator.strip(), 'text': text,
                          'at': _utc_now(at).isoformat()})
        comment_id = hashlib.sha256(data).hexdigest()[:32]
        with self._db(2) as db, db:
            if db.execute('SELECT 1 FROM rem_comments WHERE id=?', (comment_id,)).fetchone() is None:
                db.execute('INSERT INTO rem_comments VALUES (?,?)', (comment_id, data.decode('utf-8')))
        return comment_id

    def record_receipt(self, binding, proposal_id, raw):
        """Append the target's exact receipt for this proposal's approved request (reconciliation adds more)."""
        from vm.ubuntu.remediation_schema import parse_receipt
        self._proposal(binding, proposal_id)
        with self._db(2) as db:
            decision = db.execute('SELECT decision, payload FROM rem_decisions WHERE id=?', (proposal_id,)).fetchone()
        if decision is None or decision['decision'] != 'approved':
            raise ValueError('Only an approved proposal can have an execution receipt')
        approved = bytes(decision['payload'])
        receipt = parse_receipt(raw)
        if (receipt['request_id'], receipt['request_sha256']) != (json.loads(approved)['request_id'],
                                                                  hashlib.sha256(approved).hexdigest()):
            raise ValueError('Receipt belongs to another request')
        receipt_id = hashlib.sha256(raw).hexdigest()
        with self._db(2) as db, db:
            if db.execute('SELECT 1 FROM rem_receipts WHERE id=?', (receipt_id,)).fetchone() is None:
                db.execute('INSERT INTO rem_receipts VALUES (?,?,?)', (receipt_id, raw, receipt['outcome']))
        return receipt_id

    def proposals(self, binding, round_id):
        from vm.ubuntu.remediation_schema import parse_receipt
        self._check_binding(binding, binding.target_id, binding.registration_epoch)
        with self._db(2) as db:
            rows = db.execute('SELECT id, payload FROM rem_proposals ORDER BY rowid').fetchall()
            decisions = {r['id']: (r['decision'], bytes(r['payload'])) for r in db.execute('SELECT * FROM rem_decisions')}
            receipts = [parse_receipt(bytes(r['payload'])) for r in db.execute('SELECT payload FROM rem_receipts ORDER BY rowid')]
        result = []
        for row in rows:
            payload = json.loads(bytes(row['payload']))
            if payload['workflow_session_id'] != binding.workflow_session_id or payload['round_id'] != round_id:
                continue
            decision, data = decisions.get(row['id'], (None, None))
            approved = data if decision == 'approved' else None
            request_id = json.loads(approved)['request_id'] if approved else None
            result.append(StoredProposal(row['id'], payload, decision, approved,
                                         tuple(r for r in receipts if request_id and r['request_id'] == request_id)))
        return tuple(result)

    # ---- consistency ------------------------------------------------------------------------
    def consistency_errors(self):
        """Report integrity failures and broken links across the three files; never repair them."""
        errors = []
        for index, (path, (app_id, _, tables)) in enumerate(zip(self.paths, _FILES)):
            try:
                self._inspect(path, app_id, tables)
                with self._db(index) as db:
                    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                        errors.append(f'{path.name}: SQLite integrity check failed')
            except (ValueError, sqlite3.DatabaseError) as error:
                errors.append(f'{path.name}: {error}')
        with self._db(0) as db:
            evidence = {r['digest']: (r['target_id'], r['registration_epoch'])
                        for r in db.execute('SELECT digest, target_id, registration_epoch FROM imported_assessments')}
        with self._db(1) as db:
            runs = {r['run_id']: r for r in db.execute('SELECT * FROM framework_runs')}
        with self._db(2) as db:
            rounds = db.execute('SELECT id, target_id, registration_epoch, framework_run_id FROM agentic_rounds').fetchall()
        linked = {r['digest'] for r in runs.values()}
        for digest, (target, epoch) in evidence.items():
            try:
                self.get_evidence(digest, target, epoch)
            except ValueError as error:
                errors.append(f'evidence {digest}: {error}')
            if digest not in linked:
                errors.append(f'orphan evidence {digest}: no framework run references it')
        for run_id, run in runs.items():
            if evidence.get(run['digest']) != (run['target_id'], run['registration_epoch']):
                errors.append(f'run {run_id}: references missing or mismatched evidence')
        for row in rounds:
            run = runs.get(row['framework_run_id'])
            if run is None or (run['target_id'], run['registration_epoch']) != (row['target_id'], row['registration_epoch']):
                errors.append(f'round {row["id"]}: references missing or mismatched run')
        with self._db(2) as db:
            proposals = {r['id']: json.loads(bytes(r['payload'])) for r in db.execute('SELECT * FROM rem_proposals')}
            decisions = {r['id']: (r['decision'], bytes(r['payload'])) for r in db.execute('SELECT * FROM rem_decisions')}
            receipts = [bytes(r['payload']) for r in db.execute('SELECT payload FROM rem_receipts')]
        round_ids = {row['id'] for row in rounds}
        for proposal_id, payload in proposals.items():
            if payload['round_id'] not in round_ids:
                errors.append(f'proposal {proposal_id}: references a missing round')
        approved = set()
        for proposal_id, (decision, data) in decisions.items():
            if proposal_id not in proposals:
                errors.append(f'decision {proposal_id}: references a missing proposal')
            elif decision == 'approved':
                approved.add((json.loads(data)['request_id'], hashlib.sha256(data).hexdigest()))
        for data in receipts:
            doc = json.loads(data)
            if (doc['request_id'], doc['request_sha256']) not in approved:
                errors.append(f'receipt {hashlib.sha256(data).hexdigest()}: has no matching approved request')
        return tuple(errors)

    @staticmethod
    def _check_binding(binding, target_id, registration_epoch):
        if type(binding) is not WorkflowBinding or binding.platform != 'ubuntu':
            raise ValueError('Ubuntu workflow binding required')
        if (binding.target_id, binding.registration_epoch) != (target_id, registration_epoch):
            raise ValueError('Evidence and workflow belong to different targets or registration epochs')
