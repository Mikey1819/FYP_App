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


def _core_spec():
    """Host spec for the core-dump family (1.5.3); fixture-tested, not validated on the VM."""
    import json
    from system.contracts import ComplianceStatus
    from vm.ubuntu.family_core import ACTION_ID, COREDUMP_MANAGED, IMPLEMENTATION_SHA256, LIMITS_MANAGED, SYSCTL_PARAMS
    from vm.ubuntu.family_sysctl import MANAGED, validate_params

    def validate(params):
        if (type(params) is not dict or set(params) != {'sysctl', 'limits', 'coredump'} or params['limits'] is not True
                or type(params['coredump']) is not bool or params['sysctl'] != SYSCTL_PARAMS):
            raise ValueError('Invalid core-dump family parameters')
        validate_params('1.5.3', params['sysctl'])

    def propose(control_id, evidence):
        result = next((a for a in evidence.assessments if a.control_id == control_id), None)
        if result is None or result.status is not ComplianceStatus.NON_COMPLIANT:
            return None
        facts = json.loads(evidence.raw)['observations'][control_id]
        installed = facts.get('systemd_coredump_installed', {})
        if (facts.get('sysctl_resolution', {}).get('value') != 'complete' or installed.get('state') != 'ok'
                or facts.get('hard_core_limits', {}).get('state') != 'ok'):
            return None  # unresolved sources: no deterministic plan
        return {'sysctl': dict(SYSCTL_PARAMS), 'limits': True, 'coredump': installed['value']}
    return {ACTION_ID: ActionSpec(ACTION_ID, 1, IMPLEMENTATION_SHA256, ('1.5.3',), validate, 60, propose=propose,
                                  title='Restrict core dumps: hard core 0, fs.suid_dumpable 0, coredump storage off',
                                  recovery={'kind': 'restore_backup',
                                            'scope': [LIMITS_MANAGED, MANAGED, COREDUMP_MANAGED, 'runtime:fs.suid_dumpable']})}


def _auth_specs():
    """Host specs for sudo logfile (5.2.3) and password minlen (5.3.3.2.2); fixture-tested, not validated on the VM."""
    import json
    from system.contracts import ComplianceStatus
    from vm.ubuntu.family_auth import IMPLEMENTATION_SHA256, PWQ_MANAGED, SUDO_LOGFILE, SUDO_MANAGED

    def failing(control_id, evidence):
        result = next((a for a in evidence.assessments if a.control_id == control_id), None)
        if result is None or result.status is not ComplianceStatus.NON_COMPLIANT:
            return None
        return json.loads(evidence.raw)['observations'][control_id]

    def propose_sudo(control_id, evidence):
        facts = failing(control_id, evidence)
        if (facts is None or facts.get('sudoers_resolution', {}).get('value') != 'complete'
                or facts.get('sudoers_syntax_valid', {}).get('value') is not True):
            return None
        return {'logfile': SUDO_LOGFILE}

    def propose_minlen(control_id, evidence):
        facts = failing(control_id, evidence)
        if facts is None or facts.get('pam_resolution', {}).get('value') != 'complete':
            return None
        return {'minlen': 14}

    def validate_sudo(params):
        if params != {'logfile': SUDO_LOGFILE}:
            raise ValueError('Only the approved sudo log path is managed')

    def validate_minlen(params):
        if type(params) is not dict or set(params) != {'minlen'} or type(params['minlen']) is not int or params['minlen'] != 14:
            raise ValueError('Only minlen = 14 is managed')
    return {
        'ubuntu.5.2.3.v1': ActionSpec('ubuntu.5.2.3.v1', 1, IMPLEMENTATION_SHA256, ('5.2.3',), validate_sudo, 60,
                                      propose=propose_sudo, title='Add a dedicated sudo log file (visudo-validated)',
                                      recovery={'kind': 'restore_backup', 'scope': [SUDO_MANAGED]}),
        'ubuntu.5.3.3.2.2.v1': ActionSpec('ubuntu.5.3.3.2.2.v1', 1, IMPLEMENTATION_SHA256, ('5.3.3.2.2',), validate_minlen,
                                          60, propose=propose_minlen,
                                          title='Require passwords of at least 14 characters (new passwords only)',
                                          recovery={'kind': 'restore_backup', 'scope': [PWQ_MANAGED]}),
    }


def _aging_specs():
    """Host specs for account aging 5.4.1.1/5.4.1.3/5.4.1.5; fixture-tested, not validated on the VM.

    The target refuses any change that would leave a changed account's password expired or expiring soon."""
    import json
    from system.contracts import ComplianceStatus
    from vm.ubuntu.family_aging import IMPLEMENTATION_SHA256, SPECS
    titles = {'5.4.1.1': 'Expire passwords after at most 365 days (lockout-guarded)',
              '5.4.1.3': 'Warn 7 days before a password expires',
              '5.4.1.5': 'Lock accounts 45 days after password expiry (lockout-guarded)'}
    specs = {}
    for control_id, spec in SPECS.items():
        params = {spec['param']: spec['target']}

        def propose(cid, evidence, params=params):
            result = next((a for a in evidence.assessments if a.control_id == cid), None)
            if result is None or result.status is not ComplianceStatus.NON_COMPLIANT:
                return None
            facts = json.loads(evidence.raw)['observations'][cid]
            if (facts.get('account_inventory', {}).get('value') != 'complete'
                    or facts.get('accounts', {}).get('state') != 'ok'):
                return None
            return dict(params)

        def validate(candidate, params=params):
            name = next(iter(params))
            if (type(candidate) is not dict or set(candidate) != {name} or type(candidate[name]) is not int
                    or candidate[name] != params[name]):
                raise ValueError('Only the approved site value is managed')
        action_id = 'ubuntu.%s.v1' % control_id
        specs[action_id] = ActionSpec(action_id, 1, IMPLEMENTATION_SHA256, (control_id,), validate, 120,
                                      propose=propose, title=titles[control_id],
                                      recovery={'kind': 'restore_backup', 'scope': [spec['source'], '/etc/shadow']})
    return specs


def _package_specs():
    """Host specs for the supervised package jobs; fixture-tested, not validated on the VM. The target's apt
    simulation decides eligibility (no removals or upgrades on install, no dependent packages on purge)."""
    import json
    from system.contracts import ComplianceStatus
    from vm.ubuntu.family_package import IMPLEMENTATION_SHA256, SPECS
    titles = {'1.3.1.1': 'Install AppArmor and its utilities (supervised apt job)',
              '1.5.4': 'Undo prelinking, then purge prelink (supervised apt job)',
              '2.1.2': 'Stop and purge avahi-daemon when nothing depends on it (supervised apt job)',
              '6.3.1.1': 'Install auditd and audispd-plugins (supervised apt job)'}
    specs = {}
    for control_id, spec in SPECS.items():
        params = {'packages': list(spec['packages'])}

        def propose(cid, evidence, params=params):
            result = next((a for a in evidence.assessments if a.control_id == cid), None)
            if result is None or result.status is not ComplianceStatus.NON_COMPLIANT:
                return None
            facts = json.loads(evidence.raw)['observations'][cid]
            if any(facts.get('package.' + name, {}).get('state') != 'ok' for name in params['packages']):
                return None
            return json.loads(json.dumps(params))

        def validate(candidate, params=params):
            if type(candidate) is not dict or candidate != params:
                raise ValueError('Only the CIS package set for this control is managed')
        action_id = 'ubuntu.%s.v1' % control_id
        specs[action_id] = ActionSpec(action_id, 1, IMPLEMENTATION_SHA256, (control_id,), validate, 900,
                                      propose=propose, title=titles[control_id],
                                      recovery={'kind': 'restore_backup', 'scope': ['dpkg:' + n for n in spec['packages']]})
    return specs


FAMILIES = dict(_sysctl_specs(), **_core_spec(), **_auth_specs(), **_aging_specs(), **_package_specs())


def _restore_spec():
    from backends.ubuntu.catalogue import EXPECTED_IDS
    from vm.ubuntu.family_restore import ACTION_ID, IMPLEMENTATION_SHA256, validate_params
    return ActionSpec(ACTION_ID, 1, IMPLEMENTATION_SHA256, tuple(sorted(EXPECTED_IDS)), validate_params, 60,
                      title='Restore the exact state recorded before an applied fix',
                      recovery={'kind': 'manual_console', 'scope': ['VM console and recovery snapshot']})


# Auxiliary operations: same approval/runner protocol, never counted as CIS control families.
AUXILIARY = {'recovery.restore.v1': _restore_spec()}


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
