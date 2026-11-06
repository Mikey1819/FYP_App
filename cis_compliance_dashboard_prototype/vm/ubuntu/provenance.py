"""Target-side provenance envelope for sanitized observations. Python 3.10, standard library only.

The helper reports facts and how they were collected. It never reports compliance, risk or
scores; the host re-validates every field and computes results itself.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from .collection import IDS, collect_observations
from .evidence_schema import validate_observations

# Exact helper bundle. A deployed copy must be byte-identical to the host copy that computes the expected digest.
HELPER_FILES = ('__init__.py', 'collection.py', 'collector.py', 'evidence_schema.py', 'inventory.py',
                'probes.py', 'provenance.py', 'scap_results.py', 'spec.py', 'cli.py', 'collect',
                'remediation_schema.py', 'runner.py', 'runner_cli.py', 'families.py', 'family_sysctl.py', 'family_core.py', 'family_restore.py', 'runner')
REQUEST = {
    'target_id': r'ubuntu:[A-Za-z0-9-]{1,64}',
    'registration_epoch': r'[A-Za-z0-9_-]{1,64}',
    'hostname': r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}',
    'machine_id': r'[0-9a-f]{32}',
    'request_id': r'[0-9a-f]{32}',
    'benchmark_sha256': r'[0-9a-f]{64}',
    'source_lock_sha256': r'[0-9a-f]{64}',
    'evidence_mode': r'Live \(SSH\)|Synthetic fixture',
}
ARTIFACT_KINDS = ('sanitized_scap_summary', 'sanitized_probe_summary')
MAX_ENVELOPE = 10*1024*1024


def collector_digest(directory=None):
    directory = Path(directory) if directory is not None else Path(__file__).resolve().parent
    digest = hashlib.sha256(b'ubuntu2204-readonly-v1\0')
    for name in HELPER_FILES:
        path = directory/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Incomplete collector helper bundle')
        data = path.read_bytes()
        digest.update(name.encode('ascii') + b'\0' + str(len(data)).encode('ascii') + b'\0' + data)
    return digest.hexdigest()


def validate_request(request):
    if type(request) is not dict or set(request) != set(REQUEST):
        raise ValueError('Unexpected collection request fields')
    for key, pattern in REQUEST.items():
        if type(request[key]) is not str or not re.fullmatch(pattern, request[key]):
            raise ValueError('Invalid collection request field')
    return dict(request)


def _utc(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError('UTC collection time required')
    return value.astimezone(timezone.utc).isoformat()


def _exit_state(observations):
    states = {o['state'] for o in observations.values()}
    if states == {'ok'}:
        return 'ok'
    if states == {'error'}:
        return 'error'
    if states == {'missing'}:
        return 'missing'
    return 'partial'


def build_envelope(request, observations, *, started_at, completed_at, collector_sha256, artifacts=()):
    request = validate_request(request)
    started, completed = _utc(started_at), _utc(completed_at)
    if not started_at <= completed_at or completed_at - started_at > timedelta(minutes=10):
        raise ValueError('Impossible collection interval')
    if type(collector_sha256) is not str or not re.fullmatch(r'[0-9a-f]{64}', collector_sha256):
        raise ValueError('Invalid collector digest')
    if type(observations) is not dict or set(observations) != set(IDS):
        raise ValueError('Every selected control must be accounted for')
    clean, probes = {}, {}
    for cid in IDS:
        if not observations[cid]:
            raise ValueError('A selected control has no observations')
        clean[cid] = validate_observations(cid, observations[cid])
        probes[cid] = {'probe_id': 'ubuntu.' + cid + '.effective.v1', 'version': 1, 'source': 'fixed-target-helper',
                       'started_at': started, 'completed_at': completed, 'exit_state': _exit_state(clean[cid])}
    exported = []
    for artifact in artifacts:
        if (type(artifact) is not dict or set(artifact) != {'kind', 'sha256', 'bytes'} or artifact['kind'] not in ARTIFACT_KINDS
                or type(artifact['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', artifact['sha256'])
                or type(artifact['bytes']) is not int or not 0 <= artifact['bytes'] <= MAX_ENVELOPE):
            raise ValueError('Invalid sanitized artifact metadata')
        exported.append(dict(artifact))
    if len(exported) > 64:
        raise ValueError('Too many artifacts')
    document = dict(namespace='ubuntu-cis', schema_version=1, collector='ubuntu2204-readonly-v1',
                    catalogue='ubuntu2204-cis2-selected30-v1', transformation='allowlisted-normalized-facts-v1',
                    collector_sha256=collector_sha256, started_at=started, completed_at=completed,
                    observations=clean, probes=probes, artifacts=exported, **request)
    raw = json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    if len(raw) > MAX_ENVELOPE:
        raise ValueError('Evidence envelope size limit')
    return raw


def run_collection(io, request, *, clock=None, registered_firewall_manager=None, scap_engine_version=None):
    """Collect once on a preflighted target and return exact sanitized envelope bytes.

    Live collection requires the accepted OpenSCAP version; the selected-rule scan is then mandatory.
    """
    request = validate_request(request)
    if request['evidence_mode'] == 'Live (SSH)' and scap_engine_version is None:
        raise ValueError('Live collection requires the accepted OpenSCAP engine version')
    if getattr(io, '_verified', False) is not True:
        raise ValueError('Verified target preflight is required')
    if getattr(io, '_identity', None) != (request['machine_id'], request['hostname'].casefold()):
        raise ValueError('Collection request does not match the preflighted target identity')
    clock = clock or (lambda: datetime.now(timezone.utc))
    started = clock()
    scap = None if scap_engine_version is None else (request['request_id'], scap_engine_version)
    observations = collect_observations(io, registered_firewall_manager=registered_firewall_manager, scap_request=scap)
    completed = clock()
    return build_envelope(request, observations, started_at=started, completed_at=completed,
                          collector_sha256=collector_digest())
