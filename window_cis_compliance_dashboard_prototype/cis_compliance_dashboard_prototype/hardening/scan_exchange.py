"""Fixed read-only shared-folder collection queue; never launches commands.

Folder access is the trust boundary. Digests bind bytes, not sender identity.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import base64
import hashlib
import json
import re
import sqlite3
from uuid import uuid4

from .evidence_import import load_evidence, _uuid, _time, _no_duplicates, _object
from .server2022_catalogue import FULL_CATALOGUE_ID
from .vm_bridge import encode

APP = Path(__file__).resolve().parents[1]
COLLECTOR = APP.parent / 'scripts' / 'Collect-Server2022Evidence.ps1'
DEFAULT_EXCHANGE = APP / 'data' / 'vm_exchange' / 'scan_queue'
MAX_RESPONSE = 100000


def worker_status(directory, hostname, machine_uuid, *, now=None):
    """A bounded worker report, never proof of a live/authenticated connection."""
    machine_uuid = _uuid(machine_uuid)
    if type(hostname) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', hostname):
        raise ValueError('Supply the exact VM computer name')
    now = now or datetime.now(timezone.utc)
    path = Path(directory) / ('worker-' + machine_uuid + '.json')
    try:
        with path.open('rb') as handle:
            raw = handle.read(4097)
    except FileNotFoundError:
        return dict(state='not_seen', detail='No worker report for this target. Start the worker inside the VM.')
    except OSError:
        return dict(state='unavailable', detail='Worker report could not be read from the shared folder.')
    try:
        if len(raw) > 4096:
            raise ValueError('Oversized report')
        doc = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_no_duplicates)
        _object(doc, 'schema_version hostname machine_uuid collector_sha256 state reported_at valid_until worker_instance_id', 'worker report')
        if (type(doc['schema_version']) is not int or doc['schema_version'] != 1
                or any(type(doc[k]) is not str for k in doc if k != 'schema_version')
                or doc['state'] not in ('ready', 'busy', 'stopped')
                or not re.fullmatch(r'[a-f0-9]{32}', doc['worker_instance_id'])
                or not re.fullmatch(r'[a-f0-9]{64}', doc['collector_sha256'])):
            raise ValueError('Unsupported worker report')
        reported, valid_until = _time(doc['reported_at']), _time(doc['valid_until'])
        maximum = 150 if doc['state'] == 'busy' else 15
        if not timedelta(0) < valid_until - reported <= timedelta(seconds=maximum):
            raise ValueError('Invalid worker report lifetime')
        if doc['hostname'].casefold() != hostname.casefold() or _uuid(doc['machine_uuid']) != machine_uuid:
            return dict(state='target_mismatch', detail='Worker report does not match the selected target.')
        if reported > now + timedelta(seconds=5):
            return dict(state='clock_mismatch', detail='Worker clock is ahead; synchronize host and VM clocks.')
        if valid_until <= now:
            return dict(state='stale', detail='Worker report expired. Refresh or restart the VM worker.', last_state=doc['state'])
        if doc['collector_sha256'] != hashlib.sha256(COLLECTOR.read_bytes()).hexdigest():
            return dict(state='collector_mismatch', detail='Worker is using a different collector. Copy the current collector and restart it.')
        return dict(state=doc['state'], reported_at=doc['reported_at'], valid_until=doc['valid_until'],
                    detail='Worker-reported state; not authenticated attestation or scan evidence.')
    except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
        return dict(state='invalid', detail='Worker report is incomplete or invalid. Refresh the status.')


class ScanExchange:
    def __init__(self, runtime, directory=DEFAULT_EXCHANGE):
        self.runtime, self.directory = runtime, Path(directory).resolve()
        self.path = runtime.imports.path.with_name(runtime.imports.path.stem + '_scans.sqlite3')
        self.directory.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute('CREATE TABLE IF NOT EXISTS scan_requests (id TEXT PRIMARY KEY, target TEXT NOT NULL, origin TEXT, payload BLOB NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS scan_responses (id TEXT PRIMARY KEY, payload BLOB NOT NULL)')
            for table in ('scan_requests', 'scan_responses'):
                for operation in ('UPDATE', 'DELETE'):
                    db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{operation} BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT,'Immutable scan record'); END")
                db.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table} WHEN EXISTS (SELECT 1 FROM {table} WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'Existing scan record'); END")

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _file(self, identifier, kind):
        if type(identifier) is not str or not re.fullmatch(r'[a-f0-9]{32}', identifier):
            raise ValueError('Invalid scan request ID')
        return self.directory / f'{identifier}-{kind}.json'

    def request(self, hostname, machine_uuid, *, origin_run_id=None, now=None):
        now = now or datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError('Clock must include timezone')
        if type(hostname) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', hostname):
            raise ValueError('Supply the exact VM computer name')
        machine_uuid = _uuid(machine_uuid)
        if origin_run_id:
            run = self.runtime.get(origin_run_id)
            record = self.runtime.imports.get(run.evidence_sha256)
            if run.target_id != 'windows:' + machine_uuid or record.assessment.hostname.casefold() != hostname.casefold():
                raise ValueError('Scan origin does not match the registered target')
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            pending = db.execute('SELECT r.id,r.payload FROM scan_requests r LEFT JOIN scan_responses s ON r.id=s.id WHERE r.target=? AND s.id IS NULL ORDER BY r.rowid DESC', (machine_uuid,)).fetchall()
            for identifier, raw in pending:
                doc = json.loads(raw)
                if _time(doc['expires_at']) > now:
                    if doc['hostname'].casefold() != hostname.casefold():
                        raise ValueError('A pending scan binds this UUID to another hostname')
                    break
            else:
                identifier = uuid4().hex
                doc = dict(schema_version=1, request_id=identifier, operation='collect_server2022_evidence',
                    hostname=hostname, machine_uuid=machine_uuid, created_at=now.isoformat(),
                    expires_at=(now + timedelta(minutes=10)).isoformat(), catalogue_id=FULL_CATALOGUE_ID,
                    collector_sha256=hashlib.sha256(COLLECTOR.read_bytes()).hexdigest())
                raw = encode(doc)
                db.execute('INSERT INTO scan_requests VALUES (?,?,?,?)', (identifier, machine_uuid, origin_run_id, raw))
            # Worker ignores incomplete JSON until the next poll; claiming only follows validation.
            path = self._file(identifier, 'request')
            try:
                with path.open('xb') as handle:
                    handle.write(raw)
            except FileExistsError:
                if path.read_bytes() != raw:
                    raise ValueError('Queued scan file differs from its saved request')
        return dict(request_id=identifier, state='awaiting_worker', hostname=hostname,
                    expires_at=doc['expires_at'], request_sha256=hashlib.sha256(raw).hexdigest())

    def get(self, identifier):
        self._file(identifier, 'request')
        with self._connection() as db:
            row = db.execute('SELECT payload FROM scan_requests WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise ValueError('Unknown scan request')
        return row[0]

    def worker_status(self, hostname, machine_uuid, *, now=None):
        return worker_status(self.directory, hostname, machine_uuid, now=now)

    def _validate_response(self, identifier, raw, now):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_RESPONSE:
            raise ValueError('Scan response exceeds size limit')
        try:
            doc = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_no_duplicates)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError('Invalid scan response JSON') from exc
        _object(doc, 'schema_version request_id request_sha256 status evidence error', 'scan response')
        request_raw = self.get(identifier)
        request = json.loads(request_raw)
        if (type(doc['schema_version']) is not int or doc['schema_version'] != 1 or doc['request_id'] != identifier
                or doc['request_sha256'] != hashlib.sha256(request_raw).hexdigest()):
            raise ValueError('Scan response does not match this request')
        if doc['status'] == 'collection_failed':
            if doc['evidence'] is not None or doc['error'] not in ('collection_failed', 'timeout'):
                raise ValueError('Invalid failed collection response')
            return doc, None, request
        if doc['status'] != 'collected' or doc['error'] is not None or type(doc['evidence']) is not str:
            raise ValueError('Invalid collection status')
        try:
            evidence = base64.b64decode(doc['evidence'], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid encoded collection evidence') from exc
        assessment = load_evidence(evidence, expected_hostname=request['hostname'],
                                   expected_machine_uuid=request['machine_uuid'], now=now)
        source = json.loads(evidence.decode('utf-8-sig'))
        if source['schema_version'] != 5 or source['catalogue_id'] != request['catalogue_id']:
            raise ValueError('Worker returned a different collector contract')
        if not _time(request['created_at']) <= _time(source['started_at']) <= assessment.collected_at <= _time(request['expires_at']):
            raise ValueError('Evidence outside scan request window; check VM clock')
        return doc, evidence, request

    def accept(self, identifier, raw, *, now=None):
        doc, evidence, request = self._validate_response(identifier, raw, now)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT payload FROM scan_responses WHERE id=?', (identifier,)).fetchone()
            if old and old[0] != raw:
                raise ValueError('A different response already belongs to this scan')
            if not old:
                db.execute('INSERT INTO scan_responses VALUES (?,?)', (identifier, raw))
        if evidence is None:
            return dict(request_id=identifier, state='collection_failed', error=doc['error'])
        run = self.runtime.start(evidence, expected_hostname=request['hostname'],
            expected_machine_uuid=request['machine_uuid'], collection_request_id=identifier)
        run = self.runtime.complete_assessment(run.run_id)
        return dict(request_id=identifier, state='assessment_ready', framework_run_id=run.run_id,
                    evidence_sha256=run.evidence_sha256, target_id=run.target_id)

    def poll(self, identifier, *, now=None):
        request = json.loads(self.get(identifier))
        with self._connection() as db:
            saved = db.execute('SELECT payload FROM scan_responses WHERE id=?', (identifier,)).fetchone()
        if saved:
            return self.accept(identifier, saved[0], now=now)
        response = self._file(identifier, 'response')
        if response.exists():
            with response.open('rb') as handle:
                raw = handle.read(MAX_RESPONSE + 1)
            return self.accept(identifier, raw, now=now)
        state = 'expired' if _time(request['expires_at']) <= (now or datetime.now(timezone.utc)) else 'awaiting_worker'
        return dict(request_id=identifier, state=state)
