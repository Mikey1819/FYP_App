"""Host-side registered Ubuntu action families and deterministic action plans.

`FAMILIES` is empty: no Ubuntu remediation family is implemented yet (tasks 11-15). Reserved catalogue
action IDs are not implementations. Parameters come from deterministic planners, never from a model.
"""
from dataclasses import dataclass, field
from uuid import uuid4
from vm.ubuntu.remediation_schema import MAX_JOB_SECONDS

CATALOGUE_VERSION = 'ubuntu2204-cis2-selected30-v1'
PLAN_FIELDS = ('target_id', 'registration_epoch', 'hostname', 'machine_id', 'workflow_session_id', 'round_id',
               'evidence_sha256', 'control_id', 'predicate_id', 'parameters', 'before_state_sha256',
               'expected_after_sha256', 'before_state_collected_at', 'recovery', 'job_deadline_seconds')


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    version: int
    implementation_sha256: str
    control_ids: tuple
    validate: object
    max_seconds: int
    # Deterministic planner: (control_id, stored evidence) -> exact parameters, or None when not eligible.
    propose: object = None
    title: str = ''
    recovery: dict = None


def _sysctl_specs():
    """Host specs for the sysctl family (1.5.1, 3.3.1, 3.3.2, 3.3.8); fixture-tested, not validated on the VM."""
    import json
    from system.contracts import ComplianceStatus
    from vm.ubuntu.family_sysctl import IMPLEMENTATION_SHA256, MANAGED, REQUIRED, validate_params

    def propose(control_id, evidence):
        result = next((a for a in evidence.assessments if a.control_id == control_id), None)
        if result is None or result.status is not ComplianceStatus.NON_COMPLIANT:
            return None
        facts = json.loads(evidence.raw)['observations'][control_id]
        if facts.get('sysctl_resolution', {}).get('value') != 'complete':
            return None  # unresolved load sources: no deterministic plan
        keys = dict(REQUIRED[control_id])
        if any('.ipv6.' in k for k in keys):
            ipv6 = facts.get('ipv6_enabled', {})
            if ipv6.get('state') != 'ok':
                return None
            if ipv6['value'] is False:  # affirmatively disabled IPv6: its keys are not applicable
                keys = {k: v for k, v in keys.items() if '.ipv6.' not in k}
        return {'keys': keys}
    specs = {}
    for control_id in sorted(REQUIRED):
        action_id = 'ubuntu.' + control_id + '.v1'
        specs[action_id] = ActionSpec(
            action_id, 1, IMPLEMENTATION_SHA256, (control_id,), lambda p, c=control_id: validate_params(c, p), 60,
            propose=propose, title='Set ' + ', '.join(sorted(REQUIRED[control_id])) + ' (runtime and managed drop-in)',
            recovery={'kind': 'restore_backup', 'scope': [MANAGED] + ['runtime:' + k for k in sorted(REQUIRED[control_id])]})
    return specs


FAMILIES = _sysctl_specs()


@dataclass(frozen=True)
class ActionPlan:
    spec: ActionSpec
    proposal_id: str
    fields: dict = field(repr=False)


def plan_action(spec, *, families=FAMILIES, parameters, **fields):
    """A deterministic, unapproved plan for one registered family and control."""
    if families.get(spec.action_id) is not spec:
        raise ValueError('Action family is not registered or implemented: ' + str(spec.action_id))
    fields = dict(fields, parameters=parameters)
    if set(fields) != set(PLAN_FIELDS):
        raise ValueError('Action plan fields are incomplete or unexpected')
    if fields['control_id'] not in spec.control_ids:
        raise ValueError('Action family does not support this control')
    spec.validate(parameters)
    deadline = fields['job_deadline_seconds']
    if type(deadline) is not int or not 1 <= deadline <= min(spec.max_seconds, MAX_JOB_SECONDS):
        raise ValueError('Job deadline exceeds the family limit')
    return ActionPlan(spec, uuid4().hex, fields)
