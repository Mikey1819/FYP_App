"""Host-authoritative workflow bindings and durable at-most-once dispatch intents.

No time-based lock takeover. An unresolved owner survives process and dashboard restarts.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4, uuid5, NAMESPACE_URL

from .contracts import VerificationRefused, WorkflowBinding, OperationState, encode_record, decode_record


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _renamed(identity, old):
    """The same machine ID under another name: a copy of a machine, or one renamed or reinstalled since."""
    name, before = identity.hostname[:63], old['hostname'][:63]
    copy = ('give the copy its own hardware UUID (VirtualBox, with the VM off: VBoxManage modifyvm "<VM name>" '
            '--hardwareuuid <new UUID>)' if identity.platform == 'windows' else 'give the copy its own machine ID')
    return VerificationRefused(
        f"This laptop already knows this machine's ID ({identity.machine_identity}) as {before} (last at "
        f"{old['current_endpoint']}), but the server now calls itself {name}. A copied VM keeps the ID of the "
        'machine it was copied from, and so does a renamed or reinstalled server, so the program does not accept the '
        'ID under another name.',
        f'If this server is a copy of {before}, {copy}, then pair it again. If it is {before} itself, renamed, '
        f'rename it back to {before}.')


class CoordinationLedger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise ValueError('Unsupported integration ledger version')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS workflow_bindings (
                    workflow_session_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operation_claims (
                    operation_id TEXT PRIMARY KEY, dispatch_key TEXT UNIQUE NOT NULL,
                    command_sha256 TEXT NOT NULL, workflow_session_id TEXT NOT NULL,
                    target_id TEXT NOT NULL, registration_epoch TEXT NOT NULL, kind TEXT NOT NULL,
                    state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    mutation INTEGER NOT NULL, result TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operation_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL,
                    time TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS target_owners (
                    target_id TEXT NOT NULL, registration_epoch TEXT NOT NULL,
                    operation_id TEXT NOT NULL, workflow_session_id TEXT NOT NULL,
                    generation TEXT NOT NULL, state TEXT NOT NULL,
                    PRIMARY KEY(target_id, registration_epoch));
                CREATE TABLE IF NOT EXISTS acceptance_runs (
                    request_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, registration_epoch TEXT NOT NULL,
                    scenario TEXT NOT NULL, runner_digest TEXT NOT NULL, approved_raw BLOB NOT NULL,
                    created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS acceptance_outcomes (
                    request_id TEXT PRIMARY KEY, outcome TEXT NOT NULL, settled_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS target_registrations (
                    target_id TEXT PRIMARY KEY, platform TEXT NOT NULL,
                    machine_identity TEXT NOT NULL, hostname TEXT NOT NULL,
                    endpoint TEXT NOT NULL, fingerprint TEXT, epoch TEXT NOT NULL,
                    UNIQUE(platform, machine_identity));
                -- A registered machine found at a new address by a pairing code: appended, never rewritten.
                CREATE TABLE IF NOT EXISTS endpoint_moves (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL,
                    endpoint TEXT NOT NULL, moved_at TEXT NOT NULL, proof TEXT NOT NULL);
                -- A registered Ubuntu machine whose SSH host key changed, proven by a re-pair by code (the signed
                -- pairing answer named the new key and the login found it): a new key under a new registration
                -- epoch. Appended, never rewritten (2026-11-13).
                CREATE TABLE IF NOT EXISTS key_changes (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, epoch TEXT NOT NULL, changed_at TEXT NOT NULL, proof TEXT NOT NULL);
            ''')
            for table, key in (('workflow_bindings', 'workflow_session_id'), ('operation_events', 'sequence'),
                               ('target_registrations', 'target_id'), ('acceptance_runs', 'request_id'),
                               ('acceptance_outcomes', 'request_id'), ('endpoint_moves', 'sequence'),
                               ('key_changes', 'sequence')):
                for operation in ('UPDATE', 'DELETE'):
                    db.execute(f'''CREATE TRIGGER IF NOT EXISTS {table}_no_{operation}
                        BEFORE {operation} ON {table}
                        BEGIN SELECT RAISE(ABORT, 'Immutable integration audit'); END''')
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table}
                    WHEN EXISTS(SELECT 1 FROM {table} WHERE {key}=NEW.{key})
                    BEGIN SELECT RAISE(ABORT, 'Audit record already exists'); END''')
            db.execute('PRAGMA user_version=1')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _current(db, platform):
        """Each registration of this platform with its current endpoint (the latest pairing move, else the original),
        and its current host key and epoch (the latest proven key change, else the original)."""
        return db.execute('''SELECT r.target_id, r.platform, r.machine_identity, r.hostname, r.endpoint,
                                COALESCE((SELECT k.fingerprint FROM key_changes k WHERE k.target_id=r.target_id
                                    ORDER BY k.sequence DESC LIMIT 1), r.fingerprint) AS fingerprint,
                                COALESCE((SELECT k.epoch FROM key_changes k WHERE k.target_id=r.target_id
                                    ORDER BY k.sequence DESC LIMIT 1), r.epoch) AS epoch,
                                COALESCE((SELECT m.endpoint FROM endpoint_moves m WHERE m.target_id=r.target_id
                                    ORDER BY m.sequence DESC LIMIT 1), r.endpoint) AS current_endpoint
                              FROM target_registrations r WHERE r.platform=?''', (platform,)).fetchall()

    def register(self, identity, endpoint, *, readdress=False, key_confirmed=False):
        """Persist public facts only. Duplicate identity at another endpoint requires explicit review: here that
        review is a pairing code (`readdress`), which may move the same machine (same hostname) to its new address.
        A changed Ubuntu host key is accepted only with that review and `key_confirmed`: the signed pairing answer
        named exactly this key and the login found it (2026-11-13). It is then recorded under a new registration
        epoch, so approvals and sessions of the old key no longer count; never while a change is open there."""
        endpoint_key = f'{endpoint.host}:{endpoint.port}'
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            current = self._current(db, identity.platform)
            old = next((r for r in current if r['machine_identity'] == identity.machine_identity), None)
            if old:
                if old['hostname'].casefold() != identity.hostname.casefold():
                    raise _renamed(identity, old)
                epoch = old['epoch']
                if old['fingerprint'] != identity.host_fingerprint and readdress and key_confirmed:
                    if db.execute('SELECT 1 FROM target_owners WHERE target_id=?', (old['target_id'],)).fetchone():
                        raise VerificationRefused(
                            f"The SSH host key of {old['hostname'][:63]} changed, but a change made by this program is "
                            'still open on it under the old key.',
                            'Restore the server to the state with its old key, settle the open change, then re-pair.')
                    epoch = uuid4().hex
                    db.execute('INSERT INTO key_changes (target_id, fingerprint, epoch, changed_at, proof) '
                               'VALUES (?,?,?,?,?)', (old['target_id'], identity.host_fingerprint, epoch, now(),
                                                      'pairing_code'))
                elif old['fingerprint'] != identity.host_fingerprint:
                    raise VerificationRefused(
                        f"This laptop recorded another SSH host key for {old['hostname'][:63]} "
                        f"({old['fingerprint']}). A reinstalled server, or a machine in the middle, shows a new key.",
                        'Check the host key on the server\'s own console (ssh-keygen -lf '
                        '/etc/ssh/ssh_host_ed25519_key.pub). If the server was restored or reinstalled, start pairing on '
                        'it and use Re-pair: a changed key is accepted only through a pairing code.')
                if old['current_endpoint'] != endpoint_key:
                    other = next((r for r in current if r is not old and r['current_endpoint'] == endpoint_key), None)
                    if other is not None:
                        raise VerificationRefused(
                            f"This laptop has another machine, {other['hostname'][:63]} (ID {other['machine_identity']}),"
                            f" recorded at {endpoint_key}, so {identity.hostname[:63]} cannot be recorded there too.",
                            f"Give {identity.hostname[:63]} another address (for example a fixed one) and pair it again.")
                    if not readdress:
                        raise VerificationRefused(
                            f"{old['hostname'][:63]} is recorded at {old['current_endpoint']}, but answered at "
                            f"{endpoint_key}.", 'Start pairing on the server and use Re-pair below.')
                    db.execute('INSERT INTO endpoint_moves (target_id, endpoint, moved_at, proof) VALUES (?,?,?,?)',
                               (old['target_id'], endpoint_key, now(), 'pairing_code'))
                return old['target_id'], epoch
            target = ('windows:' + identity.machine_identity.lower() if identity.platform == 'windows'
                      else 'ubuntu:' + str(uuid4()))
            epoch = uuid4().hex
            db.execute('INSERT INTO target_registrations VALUES(?,?,?,?,?,?,?)',
                       (target, identity.platform, identity.machine_identity, identity.hostname,
                        endpoint_key, identity.host_fingerprint, epoch))
            return target, epoch

    def registration(self, platform, machine_identity):
        """The public facts recorded for one machine (target, epoch, hostname, current endpoint, host key, and when its
        current key was proven by a re-pair, or None for the key it was first paired with), or None."""
        with self._db() as db:
            row = next((r for r in self._current(db, platform) if r['machine_identity'] == machine_identity), None)
            changed = None if row is None else db.execute(
                'SELECT changed_at FROM key_changes WHERE target_id=? ORDER BY sequence DESC LIMIT 1',
                (row['target_id'],)).fetchone()
        return None if row is None else {'target_id': row['target_id'], 'epoch': row['epoch'], 'hostname': row['hostname'],
                                         'endpoint': row['current_endpoint'], 'fingerprint': row['fingerprint'],
                                         'key_changed_at': changed[0] if changed else None}

    def known_fingerprint(self, endpoint):
        with self._db() as db:
            rows = [r for r in self._current(db, 'ubuntu') if r['current_endpoint'] == f'{endpoint.host}:{endpoint.port}']
        if len(rows) > 1:
            raise ValueError('Ambiguous endpoint registration')
        return rows[0]['fingerprint'] if rows else None

    def add_binding(self, binding):
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            raw = encode_record(binding)
            old = db.execute('SELECT payload FROM workflow_bindings WHERE workflow_session_id=?',
                             (binding.workflow_session_id,)).fetchone()
            if old:
                if old[0] != raw:
                    raise ValueError('Workflow binding cannot change')
                return binding
            db.execute('INSERT INTO workflow_bindings VALUES(?,?)', (binding.workflow_session_id, raw))
        return binding

    def binding_for_backend(self, platform, target, epoch, backend_session_id):
        for binding in self.bindings_for_target(platform, target, epoch):
            if binding.backend_session_id == backend_session_id:
                return binding
        return None

    def bindings_for_target(self, platform, target, epoch):
        with self._db() as db:
            rows = db.execute('SELECT payload FROM workflow_bindings').fetchall()
        bindings = (decode_record(WorkflowBinding, row[0]) for row in rows)
        return tuple(b for b in bindings if (b.platform, b.target_id, b.registration_epoch) == (platform, target, epoch))

    def assessment_binding(self, platform, target, epoch, operation_id):
        """Reserve the same first workflow across retries and independent processes."""
        if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 128:
            raise ValueError('Invalid operation ID')
        workflow = uuid5(NAMESPACE_URL, canonical(['assessment', platform, target, epoch, operation_id])).hex
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            operation = db.execute('SELECT workflow_session_id FROM operation_claims WHERE operation_id=?',
                                   (operation_id,)).fetchone()
            if operation:
                workflow = operation[0]
            row = db.execute('SELECT payload FROM workflow_bindings WHERE workflow_session_id=?', (workflow,)).fetchone()
            if row:
                binding = decode_record(WorkflowBinding, row[0])
                if (binding.platform, binding.target_id, binding.registration_epoch) != (platform, target, epoch):
                    raise ValueError('Operation belongs to another target or registration epoch')
                return binding
            binding = WorkflowBinding(workflow, platform, target, epoch, uuid4().hex, now())
            db.execute('INSERT INTO workflow_bindings VALUES(?,?)', (workflow, encode_record(binding)))
        return binding

    def resume(self, workflow, platform, target, epoch):
        with self._db() as db:
            row = db.execute('SELECT payload FROM workflow_bindings WHERE workflow_session_id=?', (workflow,)).fetchone()
        if row is None:
            raise ValueError('Unknown workflow')
        binding = decode_record(WorkflowBinding, row[0])
        if (binding.platform, binding.target_id, binding.registration_epoch) != (platform, target, epoch):
            raise ValueError('Workflow belongs to another platform, target or registration epoch')
        return binding

    def claim(self, binding, operation_id, kind, command, *, mutation=False, stack=False):
        """`stack` (Ubuntu commit-confirm only, 2026-11-13): an execution may be claimed while every open command of
        the workflow is an execution waiting for its confirmation over a fresh login; the target's owner stays the
        first of them and is handed to the next open one when it settles (_hand_over). Never used on Windows."""
        if not operation_id or len(operation_id) > 128:
            raise ValueError('Invalid operation ID')
        encoded = canonical({'binding': encode_record(binding), 'kind': kind, 'command': command})
        digest = hashlib.sha256(encoded.encode('utf-8')).hexdigest()
        # Execution command contains the round and exact request set. Operation ID is intentionally excluded.
        dispatch = digest
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            stored = db.execute('SELECT payload FROM workflow_bindings WHERE workflow_session_id=?',
                                (binding.workflow_session_id,)).fetchone()
            if stored is None or stored[0] != encode_record(binding):
                raise ValueError('Unregistered workflow binding')
            # An ID conflict always takes precedence over another row with matching bytes.
            old = db.execute('SELECT * FROM operation_claims WHERE operation_id=?', (operation_id,)).fetchone()
            if old and old['command_sha256'] != digest:
                raise ValueError('Operation ID was used for different command bytes')
            if old is None:
                old = db.execute('SELECT * FROM operation_claims WHERE dispatch_key=?', (dispatch,)).fetchone()
            if old:
                if old['command_sha256'] != digest:
                    raise ValueError('Operation ID was used for different command bytes')
                return False, OperationState(old['operation_id'], old['state'], detail=old['result'])
            # Serialize all commands within a workflow; every remote mutation also owns the target.
            busy = db.execute("SELECT 1 FROM operation_claims WHERE workflow_session_id=? AND state NOT IN ('completed','refused')",
                              (binding.workflow_session_id,)).fetchone()
            owner = db.execute('SELECT 1 FROM target_owners WHERE target_id=? AND registration_epoch=?',
                               (binding.target_id, binding.registration_epoch)).fetchone()
            if (busy or owner) and not (stack and kind == 'execution' and mutation
                                        and self._all_waiting(db, binding)):
                raise ValueError('Target or workflow has an unresolved operation; reconciliation is required')
            stamp = now()
            db.execute('INSERT INTO operation_claims VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                       (operation_id, dispatch, digest, binding.workflow_session_id, binding.target_id,
                        binding.registration_epoch, kind, 'running', stamp, stamp, int(mutation), ''))
            if mutation and not owner:
                db.execute('INSERT INTO target_owners VALUES(?,?,?,?,?,?)', (binding.target_id,
                           binding.registration_epoch, operation_id, binding.workflow_session_id, uuid4().hex, 'running'))
            db.execute('INSERT INTO operation_events(operation_id,time,kind,payload) VALUES(?,?,?,?)',
                       (operation_id, stamp, 'claimed', canonical({'command_sha256': digest})))
        return True, OperationState(operation_id, 'running')

    @staticmethod
    def _all_waiting(db, binding):
        """Every open command of the workflow is a running execution waiting for its confirmation, and the target's
        owner (if any) is one of them."""
        open_rows = db.execute("SELECT operation_id, kind, state, mutation FROM operation_claims WHERE "
                               "workflow_session_id=? AND state NOT IN ('completed','refused')",
                               (binding.workflow_session_id,)).fetchall()
        if not open_rows:
            return False
        for row in open_rows:
            if (row['kind'], row['state'], row['mutation']) != ('execution', 'running', 1):
                return False
            if not db.execute("SELECT 1 FROM operation_events WHERE operation_id=? AND kind='awaiting_confirmation'",
                              (row['operation_id'],)).fetchone():
                return False
        owner = db.execute('SELECT operation_id FROM target_owners WHERE target_id=? AND registration_epoch=?',
                           (binding.target_id, binding.registration_epoch)).fetchone()
        return owner is None or owner[0] in {row['operation_id'] for row in open_rows}

    @staticmethod
    def _hand_over(db, operation_id):
        """After `operation_id` gave up the target: the next open mutation on the same target (a stacked
        commit-confirm change) becomes its owner, so the target is never left unowned while one is open."""
        row = db.execute('SELECT target_id, registration_epoch FROM operation_claims WHERE operation_id=?',
                         (operation_id,)).fetchone()
        if row is None or db.execute('SELECT 1 FROM target_owners WHERE target_id=? AND registration_epoch=?',
                                     (row[0], row[1])).fetchone():
            return
        nxt = db.execute("SELECT operation_id, workflow_session_id, state FROM operation_claims WHERE target_id=? AND "
                         "registration_epoch=? AND mutation=1 AND state IN ('running','unresolved','cancel_requested') "
                         'ORDER BY created_at, rowid LIMIT 1', (row[0], row[1])).fetchone()
        if nxt is not None:
            db.execute('INSERT INTO target_owners VALUES(?,?,?,?,?,?)',
                       (row[0], row[1], nxt[0], nxt[1], uuid4().hex, nxt[2]))

    def recorded(self, binding, kind, command):
        """True when a completed claim with exactly these command bytes exists for this binding (read-only). The
        ledger keeps only the digest, so a caller proves what was recorded by presenting the same command again."""
        encoded = canonical({'binding': encode_record(binding), 'kind': kind, 'command': command})
        digest = hashlib.sha256(encoded.encode('utf-8')).hexdigest()
        with self._db() as db:
            return db.execute("SELECT 1 FROM operation_claims WHERE dispatch_key=? AND kind=? AND state='completed'",
                              (digest, kind)).fetchone() is not None

    def unsettled(self, workflow_session_id):
        """Operations of one workflow that are neither completed nor refused, oldest first (read-only)."""
        with self._db() as db:
            rows = db.execute("SELECT operation_id, kind, state, result FROM operation_claims WHERE workflow_session_id=? "
                              "AND state NOT IN ('completed','refused') ORDER BY created_at", (workflow_session_id,))
            return [dict(operation_id=r[0], kind=r[1], state=r[2], result=r[3]) for r in rows.fetchall()]

    def operation_state(self, operation_id):
        with self._db() as db:
            row = db.execute('SELECT state,result FROM operation_claims WHERE operation_id=?', (operation_id,)).fetchone()
        return OperationState(operation_id, row[0], detail=row[1]) if row else OperationState(operation_id, 'refused', code='unknown_operation')

    def reconcile(self, operation_id, state, *, detail=''):
        """Settle an unresolved or interrupted operation from backend/target evidence; never a time-based takeover.

        The caller must hold target evidence for `state` (for example a target receipt). Appends an audit event.
        """
        if state not in ('completed', 'refused'):
            raise ValueError('Reconciliation settles to completed or refused only')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT state FROM operation_claims WHERE operation_id=?', (operation_id,)).fetchone()
            if not old or old[0] not in ('unresolved', 'running', 'cancel_requested'):
                raise ValueError('Only an unsettled operation can be reconciled')
            stamp = now()
            db.execute('UPDATE operation_claims SET state=?,updated_at=?,result=? WHERE operation_id=?',
                       (state, stamp, detail, operation_id))
            db.execute('INSERT INTO operation_events(operation_id,time,kind,payload) VALUES(?,?,?,?)',
                       (operation_id, stamp, 'reconciled_' + state, canonical({'from': old[0], 'detail': detail})))
            db.execute('DELETE FROM target_owners WHERE operation_id=?', (operation_id,))
            self._hand_over(db, operation_id)
        return self.operation_state(operation_id)

    def owner(self, target_id, epoch):
        """The operation holding this target (running or unresolved) and its workflow, or None (read-only)."""
        with self._db() as db:
            row = db.execute('SELECT operation_id, workflow_session_id FROM target_owners WHERE target_id=? AND '
                             'registration_epoch=?', (target_id, epoch)).fetchone()
        return None if row is None else dict(operation_id=row[0], workflow_session_id=row[1])

    def owned_elsewhere(self, target_id, epoch):
        """Targets (other than this one) that hold a running or unresolved change."""
        with self._db() as db:
            rows = db.execute('SELECT target_id, registration_epoch FROM target_owners').fetchall()
        return tuple((t, e) for t, e in rows if (t, e) != (target_id, epoch))

    # ---- execution acceptance evidence (append-only) ---------------------------------------------
    def add_acceptance(self, request_id, target_id, epoch, scenario, runner_digest, approved_raw):
        if scenario not in ('confirm', 'rollback') or type(approved_raw) is not bytes:
            raise ValueError('Invalid acceptance record')
        with self._db() as db:
            db.execute('INSERT INTO acceptance_runs VALUES(?,?,?,?,?,?,?)',
                       (request_id, target_id, epoch, scenario, runner_digest, approved_raw, now()))

    def settle_acceptance(self, request_id, outcome):
        """Record the first settled outcome of an acceptance run; later calls change nothing."""
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM acceptance_runs WHERE request_id=?', (request_id,)).fetchone():
                raise ValueError('Unknown acceptance run')
            if not db.execute('SELECT 1 FROM acceptance_outcomes WHERE request_id=?', (request_id,)).fetchone():
                db.execute('INSERT INTO acceptance_outcomes VALUES(?,?,?)', (request_id, outcome, now()))

    def acceptance_runs(self, target_id, epoch):
        with self._db() as db:
            rows = db.execute('''SELECT r.request_id, r.scenario, r.runner_digest, r.approved_raw, r.created_at, o.outcome
                FROM acceptance_runs r LEFT JOIN acceptance_outcomes o ON o.request_id = r.request_id
                WHERE r.target_id=? AND r.registration_epoch=? ORDER BY r.created_at''', (target_id, epoch)).fetchall()
        return [dict(request_id=r[0], scenario=r[1], runner_digest=r[2], raw=bytes(r[3]), created_at=r[4], outcome=r[5])
                for r in rows]

    def note(self, operation_id, kind):
        """Append a host-clock audit event to an existing operation (no state change); returns its time."""
        if not isinstance(kind, str) or not kind.replace('_', '').isalpha() or len(kind) > 64:
            raise ValueError('Invalid event kind')
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute('SELECT 1 FROM operation_claims WHERE operation_id=?', (operation_id,)).fetchone():
                raise ValueError('Unknown operation')
            stamp = now()
            db.execute('INSERT INTO operation_events(operation_id,time,kind,payload) VALUES(?,?,?,?)',
                       (operation_id, stamp, kind, canonical({})))
        return stamp

    def first_event(self, operation_id, kind):
        """Host time of the first `kind` event of an operation, or None."""
        with self._db() as db:
            row = db.execute('SELECT time FROM operation_events WHERE operation_id=? AND kind=? ORDER BY sequence LIMIT 1',
                             (operation_id, kind)).fetchone()
        return row[0] if row else None

    def transition(self, operation_id, state, *, detail=''):
        allowed = {'running': {'completed', 'refused', 'unresolved', 'cancel_requested'},
                   'cancel_requested': {'completed', 'unresolved'}, 'unresolved': set()}
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT state FROM operation_claims WHERE operation_id=?', (operation_id,)).fetchone()
            if not old or state not in allowed.get(old[0], set()):
                raise ValueError('Invalid operation transition; reconciliation cannot authorize replay')
            stamp = now()
            db.execute('UPDATE operation_claims SET state=?,updated_at=?,result=? WHERE operation_id=?',
                       (state, stamp, detail, operation_id))
            db.execute('INSERT INTO operation_events(operation_id,time,kind,payload) VALUES(?,?,?,?)',
                       (operation_id, stamp, state, canonical({'detail': detail})))
            if state in ('completed', 'refused'):
                db.execute('DELETE FROM target_owners WHERE operation_id=?', (operation_id,))
                self._hand_over(db, operation_id)
            else:
                db.execute('UPDATE target_owners SET state=? WHERE operation_id=?', (state, operation_id))
        return self.operation_state(operation_id)
