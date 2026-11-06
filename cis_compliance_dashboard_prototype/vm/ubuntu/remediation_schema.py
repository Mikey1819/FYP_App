"""`ubuntu-remediation` schema 1: exact approved request bytes and execution receipts. Python 3.10, stdlib only.

Canonical UTF-8 JSON (sorted keys, compact separators, no NaN). A request is accepted only in its exact
canonical encoding, so the approved bytes and their SHA-256 are the only form a runner will execute.
A hash binds bytes; it is not independent authentication of the human approver.
"""
from datetime import datetime, timedelta
import json
import re
from .collection import IDS

REQUEST_NAMESPACE, RECEIPT_NAMESPACE = 'ubuntu-remediation', 'ubuntu-remediation-receipt'
MAX_APPROVAL_SECONDS, MAX_BEFORE_STATE_AGE, MAX_JOB_SECONDS = 3600, 300, 1800
REQUEST_LIMIT = 256 * 1024
ACTION_ID = (r'(ubuntu\.[0-9]+(\.[0-9]+)*\.v[0-9]+|maintenance\.[a-z_]+\.v[0-9]+|recovery\.[a-z_]+\.v[0-9]+'
             r'|fixture\.[a-z_]+\.v[0-9]+)')
RECOVERY_KINDS = ('restore_backup', 'manual_console', 'snapshot_restore')
OUTCOMES = ('applied', 'refused', 'unresolved', 'reconciled_applied', 'reconciled_not_applied', 'running',
            'rolled_back')
REQUEST_FIELDS = frozenset((
    'namespace', 'schema_version', 'request_id', 'proposal_id', 'platform', 'target_id', 'registration_epoch',
    'hostname', 'machine_id', 'workflow_session_id', 'round_id', 'evidence_sha256', 'catalogue_version',
    'control_id', 'predicate_id', 'action', 'parameters', 'before_state_sha256', 'expected_after_sha256',
    'before_state_collected_at', 'approver', 'approved_at', 'expires_at', 'job_deadline_seconds', 'recovery'))
RECEIPT_FIELDS = frozenset(('namespace', 'schema_version', 'request_id', 'request_sha256', 'outcome', 'code',
                            'before_state_sha256', 'after_state_sha256', 'started_at', 'completed_at'))
HEX32, HEX64 = r'[0-9a-f]{32}', r'[0-9a-f]{64}'


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate field')
        result[key] = value
    return result


def _load(raw, limit):
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError('Document size limit')
    try:
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite value')))
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError('Malformed document') from None
    if type(doc) is not dict or canonical(doc) != raw:
        raise ValueError('Document is not in its exact canonical encoding')
    return doc


def utc(value):
    if type(value) is not str or len(value) > 40:
        raise ValueError('Invalid timestamp')
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError('UTC timestamp required')
    return parsed


def _match(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _check(condition, message):
    if not condition:
        raise ValueError(message)


def parse_request(raw):
    doc = _load(raw, REQUEST_LIMIT)
    _check(set(doc) == REQUEST_FIELDS, 'Unexpected request fields')
    _check(doc['namespace'] == REQUEST_NAMESPACE and type(doc['schema_version']) is int and doc['schema_version'] == 1,
           'Unsupported request contract')
    for key in ('request_id', 'proposal_id', 'workflow_session_id', 'round_id', 'machine_id'):
        _check(_match(HEX32, doc[key]), 'Invalid ' + key)
    for key in ('evidence_sha256', 'before_state_sha256', 'expected_after_sha256'):
        _check(_match(HEX64, doc[key]), 'Invalid ' + key)
    _check(doc['platform'] == 'ubuntu' and _match(r'ubuntu:[A-Za-z0-9-]{1,64}', doc['target_id'])
           and _match(r'[A-Za-z0-9_-]{1,64}', doc['registration_epoch'])
           and _match(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', doc['hostname']), 'Invalid target binding')
    _check(_match(r'[A-Za-z0-9._-]{1,64}', doc['catalogue_version']) and doc['control_id'] in IDS
           and _match(re.escape('ubuntu.' + str(doc['control_id']) + '.predicate.v') + r'[0-9]+', doc['predicate_id']),
           'Invalid control binding')
    action = doc['action']
    _check(type(action) is dict and set(action) == {'action_id', 'version', 'implementation_sha256'}
           and _match(ACTION_ID, action['action_id']) and type(action['version']) is int and action['version'] >= 1
           and _match(HEX64, action['implementation_sha256']), 'Invalid action binding')
    _check(type(doc['parameters']) is dict and len(canonical(doc['parameters'])) <= 65536, 'Invalid parameters')
    _check(type(doc['approver']) is str and 0 < len(doc['approver']) <= 128
           and not any(ord(c) < 32 for c in doc['approver']), 'Invalid approver')
    approved, expires, collected = utc(doc['approved_at']), utc(doc['expires_at']), utc(doc['before_state_collected_at'])
    _check(timedelta(0) < expires - approved <= timedelta(seconds=MAX_APPROVAL_SECONDS), 'Invalid approval expiry')
    _check(timedelta(0) <= approved - collected <= timedelta(seconds=MAX_BEFORE_STATE_AGE),
           'Before-state evidence was too old at approval')
    _check(type(doc['job_deadline_seconds']) is int and 1 <= doc['job_deadline_seconds'] <= MAX_JOB_SECONDS,
           'Invalid job deadline')
    recovery = doc['recovery']
    _check(type(recovery) is dict and set(recovery) == {'kind', 'scope'} and recovery['kind'] in RECOVERY_KINDS
           and type(recovery['scope']) is list and len(recovery['scope']) <= 64
           and all(type(s) is str and 0 < len(s) <= 256 for s in recovery['scope']), 'Invalid recovery scope')
    return doc


def receipt(request_id, request_sha256, outcome, code, before, after, started_at, completed_at):
    doc = dict(namespace=RECEIPT_NAMESPACE, schema_version=1, request_id=request_id, request_sha256=request_sha256,
               outcome=outcome, code=code, before_state_sha256=before, after_state_sha256=after,
               started_at=started_at, completed_at=completed_at)
    raw = canonical(doc)
    parse_receipt(raw)
    return raw


def parse_receipt(raw):
    doc = _load(raw, 16384)
    _check(set(doc) == RECEIPT_FIELDS and doc['namespace'] == RECEIPT_NAMESPACE
           and type(doc['schema_version']) is int and doc['schema_version'] == 1, 'Unsupported receipt contract')
    _check(doc['request_id'] is None or _match(HEX32, doc['request_id']), 'Invalid receipt request')
    _check(_match(HEX64, doc['request_sha256']) and doc['outcome'] in OUTCOMES
           and _match(r'[a-z_]{1,64}', doc['code']), 'Invalid receipt outcome')
    _check(doc['request_id'] is not None or (doc['outcome'], doc['code']) == ('refused', 'invalid_request'),
           'Only an unparseable request may lack a request ID')
    for key in ('before_state_sha256', 'after_state_sha256'):
        _check(doc[key] is None or _match(HEX64, doc[key]), 'Invalid receipt state digest')
    _check(utc(doc['started_at']) <= utc(doc['completed_at']), 'Impossible receipt times')
    return doc
