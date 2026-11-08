"""Strict ownership/provenance envelope for sanitized Ubuntu collector bytes."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from .catalogue import CATALOGUE_IDS
from .evidence import validate_observations
from .predicates import evaluate, Assessment
from vm.ubuntu.spec import SCAP_RULES

FIELDS = frozenset(('namespace','schema_version','collector','catalogue','target_id','registration_epoch',
    'hostname','machine_id','request_id','benchmark_sha256','source_lock_sha256','collector_sha256','started_at',
    'completed_at','evidence_mode','observations','artifacts','transformation','probes'))


@dataclass(frozen=True)
class ExpectedEvidence:
    target_id: str
    registration_epoch: str
    hostname: str
    machine_id: str
    request_id: str
    benchmark_sha256: str
    source_lock_sha256: str
    collector_sha256: str
    evidence_mode: str = 'Live (SSH)'


@dataclass(frozen=True)
class EvidenceBundle:
    raw: bytes
    raw_sha256: str
    expected: ExpectedEvidence
    started_at: str
    completed_at: str
    assessments: tuple[Assessment, ...]


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate evidence JSON field')
        result[key] = value
    return result


def _time(value):
    if type(value) is not str or len(value) > 40:
        raise ValueError('Invalid evidence timestamp')
    result = datetime.fromisoformat(value)
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError('Evidence timestamp must be UTC')
    return result


def _avahi_retention(doc):
    """The registered 2.1.2 retention review for this evidence's machine (system.config.UBUNTU_AVAHI_RETENTION)."""
    from system.config import UBUNTU_AVAHI_RETENTION
    return UBUNTU_AVAHI_RETENTION.get(doc.get('machine_id')) == 'mask'


def parse_bundle(raw, expected, *, now=None, ssh_effective_authority=True, cis_audit_authority=True, audit_wording=None,
                 reviewed_avahi_retention=None):
    if type(raw) is not bytes or not 1 <= len(raw) <= 10*1024*1024:
        raise ValueError('Evidence envelope size limit')
    try:
        doc = json.loads(raw, object_pairs_hook=_pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite evidence')))
        if type(doc) is not dict or set(doc) != FIELDS:
            raise ValueError('Unexpected evidence envelope fields')
        if (doc['namespace'] != 'ubuntu-cis' or type(doc['schema_version']) is not int or doc['schema_version'] != 1
                or doc['collector'] != 'ubuntu2204-readonly-v1' or doc['catalogue'] not in CATALOGUE_IDS
                or doc['transformation'] != 'allowlisted-normalized-facts-v1'):
            raise ValueError('Unsupported evidence contract')
        for field in ExpectedEvidence.__dataclass_fields__:
            if type(doc[field]) is not str or doc[field] != getattr(expected,field):
                raise ValueError('Evidence ownership or source mismatch')
        if not re.fullmatch('[0-9a-f]{32}',doc['machine_id']):
            raise ValueError('Invalid machine identity')
        for field in ('benchmark_sha256','source_lock_sha256','collector_sha256'):
            if not re.fullmatch('[0-9a-f]{64}',doc[field]):
                raise ValueError('Invalid evidence provenance hash')
        started, completed = _time(doc['started_at']), _time(doc['completed_at'])
        now = now or datetime.now(timezone.utc)
        if not started <= completed <= now + timedelta(seconds=5) or completed-started > timedelta(minutes=10):
            raise ValueError('Impossible evidence times')
        if started < now - timedelta(minutes=10):
            raise ValueError('Evidence is too old for a new scan response')
        selected = CATALOGUE_IDS[doc['catalogue']]  # v1: stored scans before 2026-11-08; v2: current
        if type(doc['observations']) is not dict or set(doc['observations']) != selected:
            raise ValueError('Evidence must account for every selected control')
        if type(doc['probes']) is not dict or set(doc['probes']) != selected:
            raise ValueError('Each control requires probe provenance')
        for cid, probe in doc['probes'].items():
            if type(probe) is not dict or set(probe) != {'probe_id','version','source','started_at','completed_at','exit_state'}:
                raise ValueError('Unexpected probe provenance')
            if (probe['probe_id'] != 'ubuntu.'+cid+'.effective.v1' or type(probe['version']) is not int or probe['version'] != 1
                    or probe['source'] != 'fixed-target-helper' or probe['exit_state'] not in ('ok','missing','error','partial')):
                raise ValueError('Unsupported probe provenance')
            if not started <= _time(probe['started_at']) <= _time(probe['completed_at']) <= completed:
                raise ValueError('Probe time outside collection interval')
            validate_observations(cid,doc['observations'][cid])
            # SCAP is the primary automated source for live scans; omission must be explicit, not silent.
            if (expected.evidence_mode == 'Live (SSH)' and cid in SCAP_RULES
                    and 'scap_rules' not in doc['observations'][cid]):
                raise ValueError('Live evidence must account for the selected SCAP rules')
            if probe['exit_state'] != 'ok' and all(o['state']=='ok' for o in doc['observations'][cid].values()):
                raise ValueError('Failed probe cannot supply only successful observations')
        if type(doc['artifacts']) is not list or len(doc['artifacts']) > 64:
            raise ValueError('Invalid sanitized artifact list')
        for artifact in doc['artifacts']:
            if (type(artifact) is not dict or set(artifact) != {'kind','sha256','bytes'}
                    or artifact['kind'] not in ('sanitized_scap_summary', 'sanitized_probe_summary')
                    or type(artifact['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',artifact['sha256'])
                    or type(artifact['bytes']) is not int or not 0 <= artifact['bytes'] <= 10*1024*1024):
                raise ValueError('Invalid sanitized artifact metadata')
        assessments = tuple(evaluate(cid,doc['observations'][cid],ssh_effective_authority=ssh_effective_authority,
                                     cis_audit_authority=cis_audit_authority, audit_wording=audit_wording,
                                     reviewed_avahi_retention=_avahi_retention(doc) if reviewed_avahi_retention is None
                                     else reviewed_avahi_retention)
                            for cid in sorted(selected))
        return EvidenceBundle(raw,hashlib.sha256(raw).hexdigest(),expected,doc['started_at'],doc['completed_at'],assessments)
    except (TypeError,KeyError,UnicodeError,RecursionError,json.JSONDecodeError):
        raise ValueError('Malformed Ubuntu evidence envelope') from None
