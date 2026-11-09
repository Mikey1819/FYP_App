"""Immutable public records. Credentials and platform-private services never belong here."""
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import StrEnum
import ipaddress
import json
import re
import types
from typing import Protocol, Union, get_args, get_origin, get_type_hints, runtime_checkable


class AssessmentMode(StrEnum):
    AGENTIC = 'agentic'
    DETERMINISTIC = 'deterministic'


class ComplianceStatus(StrEnum):
    COMPLIANT = 'Compliant'
    NON_COMPLIANT = 'Non-Compliant'
    UNKNOWN = 'Unknown'
    ERROR = 'Error'


class AuxiliaryKind(StrEnum):
    METADATA_REFRESH = 'metadata_refresh'
    REBOOT = 'reboot'
    RECOVERY = 'recovery'


def utc(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError('UTC timestamp required')
    return parsed


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    method: str = 'auto'

    def __post_init__(self):
        if type(self.host) is not str or not self.host or len(self.host) > 253:
            raise ValueError('Invalid endpoint host')
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', p)
                       for p in self.host.split('.')):
                raise ValueError('Use a hostname or IP, without a URL, path or whitespace') from None
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('Invalid endpoint port')
        if self.method not in ('auto', 'ssh', 'winrm'):
            raise ValueError('Unsupported transport')


@dataclass(frozen=True)
class ConnectionRequest:
    endpoint: Endpoint
    expected_hostname: str
    expected_machine_identity: str
    credential_ref: str
    saved_profile_id: str | None = None


@dataclass(frozen=True)
class Capabilities:
    can_assess: bool = False
    can_remediate: bool = False
    can_use_model: bool = False
    requires_setup: bool = True
    blocked_reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConnectionResult:
    state: str
    connection_session_id: str | None = None
    detected_platform: str | None = None
    os_version: str | None = None
    transport: str | None = None
    target_id: str | None = None
    capabilities: Capabilities = Capabilities()
    diagnostic_code: str = ''
    detail: str = ''


@dataclass(frozen=True)
class RecordRef:
    platform: str
    target_id: str
    record_id: str

    def __post_init__(self):
        if self.platform not in ('windows', 'ubuntu') or not self.target_id.startswith(self.platform + ':'):
            raise ValueError('Platform-qualified target reference required')
        if not self.record_id or not self.target_id.split(':', 1)[1]:
            raise ValueError('Empty record reference')


@dataclass(frozen=True)
class WorkflowBinding:
    workflow_session_id: str
    platform: str
    target_id: str
    registration_epoch: str
    backend_session_id: str
    created_at: str

    def __post_init__(self):
        RecordRef(self.platform, self.target_id, self.backend_session_id)
        utc(self.created_at)
        if not self.workflow_session_id or not self.registration_epoch:
            raise ValueError('Workflow and registration epoch required')


@dataclass(frozen=True)
class TargetSummary:
    reference: RecordRef
    hostname: str
    os_release: str
    transport: str
    evidence_mode: str
    connection_state: str


@dataclass(frozen=True)
class AssessmentSummary:
    reference: RecordRef
    selected: int
    compliant: int
    non_compliant: int
    unknown: int
    error: int
    coverage_percent: float
    compliance_percent: float | None
    catalogue_id: str
    collected_at: str

    def __post_init__(self):
        counts = (self.selected, self.compliant, self.non_compliant, self.unknown, self.error)
        if any(type(v) is not int or v < 0 for v in counts) or sum(counts[1:]) != self.selected:
            raise ValueError('Invalid assessment counts')
        determinate = self.compliant + self.non_compliant
        expected = 100 * self.compliant / determinate if determinate else None
        coverage = 100 * determinate / self.selected if self.selected else 0
        if self.coverage_percent != coverage or self.compliance_percent != expected:
            raise ValueError('Counts disagree with percentages')
        utc(self.collected_at)

    @classmethod
    def from_counts(cls, reference, selected, compliant, non_compliant, unknown, error, catalogue_id, collected_at):
        determinate = compliant + non_compliant
        return cls(reference, selected, compliant, non_compliant, unknown, error,
                   100 * determinate / selected if selected else 0,
                   100 * compliant / determinate if determinate else None, catalogue_id, collected_at)


@dataclass(frozen=True)
class Subcheck:
    name: str
    status: ComplianceStatus
    detail: str


@dataclass(frozen=True)
class ControlRow:
    control_id: str
    title: str
    area: str
    profile: str
    source: str
    status: ComplianceStatus
    applicability: str
    observed: str
    expected: str
    subchecks: tuple[Subcheck, ...] = ()
    evidence_references: tuple[RecordRef, ...] = ()
    fix: str = ''  # Who fixes it: 'Program fix', or 'Manual: not automated' (shown in the Controls tab).


@dataclass(frozen=True)
class FindingRow:
    control_id: str
    I: int
    E: int
    P: int
    L: int
    D: int
    score: int
    level: str
    derivation_reasons: tuple[str, ...]
    risk_policy_version: str
    rank: int
    history_reference: RecordRef | None = None


@dataclass(frozen=True)
class ProposalRow:
    reference: RecordRef
    kind: str
    control_id: str | None
    action_id: str
    title: str
    version: str
    exact_preview: str
    impacts: tuple[str, ...]
    recovery: str
    dependencies: tuple[str, ...]
    decision: str | None
    expiry: str | None
    reason: str
    eligible_commands: tuple[str, ...]
    # Exact approved request ID shown for execution confirmation (Ubuntu); None when undecided or unused.
    approved_request_id: str | None = None
    # Digest of the approved before-state: the backup a recovery request must name (Ubuntu).
    before_state_sha256: str | None = None
    # Who approved it, as recorded in the approved request (shown like the Windows page).
    approved_by: str | None = None
    # Who rejected it, and the optional decision comments as (operator, text), as the Windows page shows them.
    rejected_by: str | None = None
    comments: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ResultRow:
    proposal_reference: RecordRef
    execution_state: str
    verification_status: ComplianceStatus | None
    receipt_reference: RecordRef | None
    verification_assessment_reference: RecordRef | None
    recovery_state: str
    detail: str


@dataclass(frozen=True)
class AgentEvent:
    run: str
    role: str
    event_kind: str
    tool_name: str
    safe_arguments: str
    result_summary: str
    reason_code: str
    timestamp: str
    provenance: str


@dataclass(frozen=True)
class PlanRow:
    """The orchestrator's decision for one Non-Compliant control, in words (reason codes are fixed vocabularies)."""
    control_id: str
    title: str
    decision: str
    reason: str
    flag: str


@dataclass(frozen=True)
class WorkspaceSnapshot:
    target: TargetSummary
    workflow_binding: WorkflowBinding | None = None
    current_round_reference: RecordRef | None = None
    summary: AssessmentSummary | None = None
    controls: tuple[ControlRow, ...] = ()
    findings: tuple[FindingRow, ...] = ()
    proposals: tuple[ProposalRow, ...] = ()
    results: tuple[ResultRow, ...] = ()
    events: tuple[AgentEvent, ...] = ()
    step_states: tuple[str, ...] = ('pending',) * 6
    goal: str | None = None
    goal_read_as: str | None = None
    available_commands: tuple[str, ...] = ()
    revision: str = ''
    plan: tuple[PlanRow, ...] = ()


@dataclass(frozen=True)
class HistoryRow:
    run_reference: RecordRef
    target: TargetSummary
    time: str
    catalogue: str
    counts: AssessmentSummary
    evidence_mode: str
    round_kind: str
    compatible_prior_reference: RecordRef | None


@dataclass(frozen=True)
class OperationState:
    operation_id: str
    state: str
    result_references: tuple[RecordRef, ...] = ()
    code: str = ''
    detail: str = ''


@dataclass(frozen=True)
class RoundHandle:
    operation_id: str
    binding: WorkflowBinding
    round_reference: RecordRef | None
    state: str


ExecutionHandle = RoundHandle


@dataclass(frozen=True)
class DecisionResult:
    reference: RecordRef
    state: str
    existing: bool = False


@dataclass(frozen=True)
class ComparisonResult:
    comparable: bool
    reason: str
    changes: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class MetadataRefreshInput:
    repository_digest: str


@dataclass(frozen=True)
class RebootInput:
    staged_request_ids: tuple[str, ...]
    maintenance_window: str


@dataclass(frozen=True)
class RecoveryInput:
    original_request_id: str
    backup_manifest_digest: str
    restoration_choice: str


AuxiliaryInput = MetadataRefreshInput | RebootInput | RecoveryInput


@dataclass(frozen=True)
class ManualReviewInput:
    assessment_reference: RecordRef
    control_reference: RecordRef
    evidence_digest: str
    package_index_digest: str
    policy_version: str
    reviewer: str
    decision: str
    reason: str


@runtime_checkable
class WorkspaceBackend(Protocol):
    def capabilities(self, connection_session_id: str) -> Capabilities: ...
    def snapshot(self, connection_session_id: str, workflow_session_id: str | None, round_ref: RecordRef | None = None) -> WorkspaceSnapshot: ...
    def start_round(self, connection_session_id: str, workflow_session_id: str | None, goal: str | None, mode: AssessmentMode, operation_id: str) -> RoundHandle: ...
    def decide(self, connection_session_id: str, workflow_session_id: str, proposal_ref: RecordRef, approved: bool, operator: str, comment: str, operation_id: str) -> DecisionResult: ...
    def execute_approved(self, connection_session_id: str, workflow_session_id: str, round_ref: RecordRef, expected_approved_request_ids: tuple[str, ...], deterministic: bool, operation_id: str) -> ExecutionHandle: ...
    def history(self, target_id: str | None, limit: int) -> tuple[HistoryRow, ...]: ...
    def compare(self, before: RecordRef, after: RecordRef) -> ComparisonResult: ...
    def operation_state(self, operation_id: str) -> OperationState: ...
    def request_auxiliary(self, connection_session_id: str, workflow_session_id: str, kind: AuxiliaryKind, basis: RecordRef | None, inputs: AuxiliaryInput, operation_id: str) -> RecordRef | OperationState: ...
    def dispatch_auxiliary(self, connection_session_id: str, workflow_session_id: str, proposal_ref: RecordRef, operation_id: str) -> ExecutionHandle | OperationState: ...
    def record_manual_review(self, connection_session_id: str, workflow_session_id: str, review: ManualReviewInput, operation_id: str) -> RecordRef | OperationState: ...
    def cancel_operation(self, connection_session_id: str, workflow_session_id: str, subject_operation_id: str, operator: str, operation_id: str) -> OperationState: ...
    def reconcile_operation(self, connection_session_id: str, subject_operation_id: str) -> OperationState: ...


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _decode(kind, value):
    origin, args = get_origin(kind), get_args(kind)
    if origin in (Union, types.UnionType):
        for member in args:
            try:
                return _decode(member, value)
            except (TypeError, ValueError):
                pass
        raise ValueError('Invalid union value')
    if origin is tuple:
        if type(value) is not list:
            raise ValueError('Sequence required')
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_decode(args[0], item) for item in value)
        if len(args) != len(value):
            raise ValueError('Wrong tuple length')
        return tuple(_decode(t, v) for t, v in zip(args, value))
    if is_dataclass(kind):
        if type(value) is not dict or set(value) != {f.name for f in fields(kind)}:
            raise ValueError('Record fields do not match schema')
        hints = get_type_hints(kind)
        return kind(**{k: _decode(hints[k], v) for k, v in value.items()})
    if isinstance(kind, type) and issubclass(kind, StrEnum):
        return kind(value)
    if kind is float and type(value) in (int, float):
        return float(value)
    if type(value) is not kind:
        raise ValueError('Wrong record value type')
    return value


def _plain(value):
    if is_dataclass(value):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    if isinstance(value, StrEnum):
        return value.value
    return value


def encode_record(value):
    if not is_dataclass(value) or type(value).__module__ != __name__:
        raise ValueError('Only public records may be serialized')
    raw = json.dumps(_plain(value), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    decode_record(type(value), raw)
    return raw


def decode_record(kind, raw):
    if len(raw) > 10 * 1024 * 1024:
        raise ValueError('Record exceeds limit')
    def invalid(_):
        raise ValueError('Nonfinite JSON number')
    return _decode(kind, json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid))
