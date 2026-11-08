"""Deterministic Ubuntu risk ranking using the Windows rubric unchanged. No model input.

The category tables, likelihood mapping, surface baselines, factor validation, score and bands are
imported from the existing Windows engine, so shared categories yield identical factors. Ubuntu adds
only per-control categorical attributes and named Linux extensions, read from a manifest that must be
human-reviewed before scores are shown. Only confirmed Non-Compliant findings are scored.
"""
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
from hardening.domain import RiskFactors
from hardening.risk import CONSEQUENCE, LIKELIHOOD, PRIVILEGE_SCOPE, SURFACE_EXPOSURE
from system.contracts import ComplianceStatus, FindingRow, RecordRef
from .catalogue import EXPECTED_IDS

APP = Path(__file__).resolve().parents[2]
MANIFEST = APP/'catalogues'/'ubuntu2204-risk.json'
CATALOGUE = APP/'catalogues'/'ubuntu2204.json'
WINDOWS = {'consequence': CONSEQUENCE, 'privilege': PRIVILEGE_SCOPE,
           'surface': {k: (v, f'base exposure {v}') for k, v in SURFACE_EXPOSURE.items()}}
FIELDS = {'schema_version', 'policy_version', 'review_status', 'reviewer', 'reviewed_at', 'method', 'extensions', 'controls'}
CONTROL_FIELDS = {'level', 'assessment', 'consequence', 'privilege_scope', 'surface', 'rationale'}


@dataclass(frozen=True)
class Policy:
    version: str
    activated: bool
    version_label: str
    controls: dict
    tables: dict  # kind -> name -> (score, reason); Windows tables plus reviewed-pending Linux extensions


@dataclass(frozen=True)
class Derivation:
    impact: int
    privilege: int
    likelihood: int
    surface: str
    surface_score: int
    reasons: tuple
    rationale: str


@dataclass(frozen=True)
class RiskInput:
    reference: RecordRef  # the assessment run
    round_id: str
    evidence: object      # StoredEvidence-like: .expected, .completed_at, .assessments


def _text(value, limit):
    return type(value) is str and 0 < len(value) <= limit


def validate_policy(doc, catalogue=None):
    if type(doc) is not dict or set(doc) != FIELDS or doc['schema_version'] != 1 or not _text(doc['policy_version'], 64):
        raise ValueError('Unsupported Ubuntu risk manifest')
    status = doc['review_status']
    if status == 'approved':
        if not _text(doc['reviewer'], 128) or not _text(doc['reviewed_at'], 40):
            raise ValueError('An approved risk policy needs a named reviewer and review time')
        stamp = datetime.fromisoformat(doc['reviewed_at'])
        if stamp.tzinfo is None or stamp.utcoffset().total_seconds() != 0:
            raise ValueError('Review time must be UTC')
    elif status != 'pending_human_review' or doc['reviewer'] is not None or doc['reviewed_at'] is not None:
        raise ValueError('Unknown risk review state')
    extensions = doc['extensions']
    if type(extensions) is not dict or not set(extensions) <= set(WINDOWS):
        raise ValueError('Unknown risk extension kind')
    tables = {kind: dict(table) for kind, table in WINDOWS.items()}
    for kind, entries in extensions.items():
        if type(entries) is not dict:
            raise ValueError('Invalid risk extension table')
        for name, entry in entries.items():
            if (not re.fullmatch(r'[a-z][a-z0-9_]{2,40}', name) or name in WINDOWS[kind] or type(entry) is not dict
                    or set(entry) != {'score', 'reason'} or type(entry['score']) is not int
                    or not 1 <= entry['score'] <= 5 or not _text(entry['reason'], 400)):
                raise ValueError('Invalid or colliding Linux risk extension')
            tables[kind][name] = (entry['score'], 'Linux extension: ' + entry['reason'])
    catalogue = catalogue if catalogue is not None else json.loads(CATALOGUE.read_text(encoding='utf-8'))
    source = {c['control_id']: (c['server_level'], c['cis_assessment_type']) for c in catalogue['controls']}
    controls = doc['controls']
    if type(controls) is not dict or set(controls) != EXPECTED_IDS:
        raise ValueError('Risk manifest must cover exactly the 30 selected controls')
    for cid, attrs in controls.items():
        if (type(attrs) is not dict or set(attrs) != CONTROL_FIELDS or attrs['consequence'] not in tables['consequence']
                or attrs['privilege_scope'] not in tables['privilege'] or attrs['surface'] not in tables['surface']
                or not _text(attrs['rationale'], 300)):
            raise ValueError('Unknown or incomplete risk attributes')
        if (attrs['level'], attrs['assessment']) != source[cid] or (attrs['level'], attrs['assessment'] == 'Automated') not in LIKELIHOOD:
            raise ValueError('Risk classification differs from the selected PDF recommendation')
    activated = status == 'approved'
    label = (f"{doc['policy_version']} (reviewed by {doc['reviewer']}, {doc['reviewed_at']})" if activated
             else f"{doc['policy_version']} (DRAFT, pending human review)")
    return Policy(doc['policy_version'], activated, label, controls, tables)


def load_policy(path=MANIFEST):
    return validate_policy(json.loads(Path(path).read_text(encoding='utf-8')))


def derive(policy, control_id):
    a = policy.controls[control_id]
    impact, impact_reason = policy.tables['consequence'][a['consequence']]
    privilege, privilege_reason = policy.tables['privilege'][a['privilege_scope']]
    surface_score, surface_reason = policy.tables['surface'][a['surface']]
    likelihood = LIKELIHOOD[(a['level'], a['assessment'] == 'Automated')]
    reasons = (f"I={impact}: {a['consequence']}: {impact_reason}",
               f"P={privilege}: {a['privilege_scope']}: {privilege_reason}",
               f"L={likelihood}: Level {a['level']}, {a['assessment']} (compatibility heuristic from the Windows "
               'Table 4.15 mapping, not a measured exploit probability)')
    return Derivation(impact, privilege, likelihood, a['surface'], surface_score, reasons, a['rationale'])


def _compatible(prior, current):
    p, c = prior.evidence.expected, current.evidence.expected
    return (prior.reference.platform == current.reference.platform == 'ubuntu'
            and prior.reference.target_id == current.reference.target_id
            and prior.reference.record_id != current.reference.record_id
            and prior.round_id != current.round_id  # a scan superseded within the same round is not history
            and (p.target_id, p.registration_epoch) == (c.target_id, c.registration_epoch)
            and p.evidence_mode == c.evidence_mode  # synthetic and live evidence never compare
            and (p.benchmark_sha256, p.source_lock_sha256) == (c.benchmark_sha256, c.source_lock_sha256)
            and datetime.fromisoformat(prior.evidence.completed_at) < datetime.fromisoformat(current.evidence.completed_at))


def rank(current, previous, policy, *, allow_draft=False):
    """Confirmed Non-Compliant findings, highest score first, stable control-ID ties."""
    if not policy.activated and not allow_draft:
        raise ValueError('Ubuntu risk attributes are pending human review; scores are withheld')
    history = sorted((p for p in previous if _compatible(p, current)),
                     key=lambda p: datetime.fromisoformat(p.evidence.completed_at), reverse=True)
    rows = []
    for result in current.evidence.assessments:
        if result.status is not ComplianceStatus.NON_COMPLIANT:
            continue  # Unknown and Error are never scored.
        d = derive(policy, result.control_id)
        e_reason = (f'E={d.surface_score}: surface {d.surface}, {policy.tables["surface"][d.surface][1].rstrip(".")}. '
                    'No reviewed Linux effective-context adjustment is defined; base exposure only.')
        prior = next(((p, a) for p in history for a in p.evidence.assessments if a.control_id == result.control_id
                      and a.status in (ComplianceStatus.COMPLIANT, ComplianceStatus.NON_COMPLIANT)), None)
        if prior is None:
            drift, d_reason, reference = 1, 'D=1: no previous comparable assessment.', None
        else:
            drift = 5 if prior[1].status is ComplianceStatus.COMPLIANT else 3
            d_reason = (f'D={drift}: previous comparable assessment was {prior[1].status.value}'
                        + (' (regression).' if drift == 5 else ' (persistent failure, even if the value changed).'))
            reference = prior[0].reference
        factors = RiskFactors(d.impact, d.surface_score, d.privilege, d.likelihood, drift)
        rows.append((factors, result.control_id, d.reasons[:2] + (e_reason,) + d.reasons[2:] + (d_reason, d.rationale),
                     reference))
    rows.sort(key=lambda row: (-row[0].score, row[1]))
    return tuple(FindingRow(cid, f.impact, f.exposure, f.privilege, f.likelihood, f.drift, f.score, f.level,
                            reasons, policy.version_label, n, reference)
                 for n, (f, cid, reasons, reference) in enumerate(rows, 1))
