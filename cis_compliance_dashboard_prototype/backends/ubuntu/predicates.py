"""Deterministic compound predicates for the selected PDF recommendations.

Inputs are sanitized, typed observations from a separately validated collector bundle.
This module neither runs probes nor approves applicability/site policies. Until that
collector and source-review gate passes, these predicates are fixture-only.
"""
from dataclasses import dataclass
from system.contracts import ComplianceStatus as Status
from vm.ubuntu.spec import SYSCTL, PACKAGES, SSH, IDENTITY_PATHS, SCAP_RULES, SCAP_RULE_PREFIX


@dataclass(frozen=True)
class Check:
    name: str
    state: str
    reason: str = ''


@dataclass(frozen=True)
class Assessment:
    control_id: str
    status: Status
    checks: tuple[Check, ...]


def combine(control_id, checks):
    checks = tuple(checks)
    states = {c.state for c in checks}
    # A confirmed failure establishes NC even if another subcheck could not be collected.
    status = (Status.NON_COMPLIANT if 'fail' in states else Status.ERROR if 'error' in states
              else Status.UNKNOWN if not checks or states & {'missing', 'conflict', 'manual'}
              or states == {'inapplicable'} else Status.COMPLIANT)
    return Assessment(control_id, status, checks)


class Facts:
    def __init__(self, observations):
        self.observations = observations
        self.checks = []

    def read(self, key):
        observation = self.observations.get(key)
        if observation is None:
            self.checks.append(Check(key, 'missing', 'Required observation absent'))
            return None
        state = observation['state']
        if state != 'ok':
            self.checks.append(Check(key, state, 'Observation is unresolved'))
            return None
        return observation['value']

    def test(self, key, predicate):
        value = self.read(key)
        if value is not None:
            self.checks.append(Check(key, 'pass' if predicate(value) else 'fail'))
        return value


def _sysctl(facts, expected):
    ipv6 = facts.read('ipv6_enabled') if any('ipv6' in k for k in expected) else True
    for name, value in expected.items():
        if 'ipv6' in name and ipv6 is not True:
            if ipv6 is False:
                facts.checks.append(Check(name, 'inapplicable', 'IPv6 affirmatively disabled'))
            continue
        facts.test('runtime.'+name, lambda actual, expected=value: actual == expected)
        facts.test('persistent.'+name, lambda actual, expected=value: actual == expected)
    # This is emitted by the resolver only after inspecting all load sources, including UFW.
    supported = facts.read('sysctl_resolution')
    if supported is not None:
        facts.checks.append(Check('sysctl_resolution', 'pass' if supported == 'complete' else 'missing',
                                 'Effective persistence must be fully resolved'))


def _accounts(facts, field, predicate):
    facts.test('default.'+field, predicate)
    complete = facts.read('account_inventory')
    if complete is not None:
        facts.checks.append(Check('account_inventory', 'pass' if complete == 'complete' else 'missing'))
    accounts = facts.read('accounts')
    if accounts is not None:
        for account in accounts:
            if not account['password_bearing']:
                continue
            value = account[field]
            good = predicate(value) and (field != 'maximum' or value > account['minimum'])
            facts.checks.append(Check('account.'+str(account['uid'])+'.'+field, 'pass' if good else 'fail'))
        if not accounts:
            facts.checks.append(Check('accounts', 'pass', 'Complete inventory contains no password-bearing accounts'))


def _rules_cover(rules, *, paths=(), syscalls=(), arch=None, privileged=None, uid_min=None):
    # A semantic normalized rule contains exact tokens; never substring-match a path.
    if privileged is not None:
        return any(r['action'] == 'always,exit' and r['path'] == privileged and 'x' in r['permissions']
                   and r['auid_min'] == uid_min and r['exclude_unset'] for r in rules)
    for path in paths:
        if not any(r['path'] == path and {'w','a'} <= set(r['permissions']) and r['key'] and r['unrestricted']
                   and r['action'] in ('watch', 'always,exit') for r in rules):
            return False
    covered = {s for r in rules if r['action'] == 'always,exit' and r['arch'] == arch and r['key']
               and r['unrestricted'] for s in r['syscalls']}
    return set(syscalls) <= covered


def evaluate(control_id, observations, *, reviewed_avahi_retention=False, ssh_effective_authority=True,
             cis_audit_authority=True, audit_wording=None):
    """Validated observations only; errors never interpolate raw evidence into diagnostics."""
    from .evidence import validate_observations
    observations = validate_observations(control_id, observations)
    f = Facts(observations)
    if control_id in PACKAGES:
        for package in PACKAGES[control_id]:
            f.test('package.'+package, lambda value: value == ('absent' if control_id == '1.5.4' else 'installed'))
    elif control_id in SYSCTL:
        _sysctl(f, SYSCTL[control_id])
    elif control_id == '1.2.2.1':
        fresh = f.read('metadata_fresh')
        updates = f.read('pending_updates')
        f.read('held_packages')
        f.read('reboot_required')
        if fresh is False:
            f.checks.append(Check('metadata_fresh', 'missing', 'Stale package metadata cannot establish current state'))
        if updates is not None and updates > 0:
            f.checks.append(Check('pending_updates', 'fail', 'Outstanding updates require review'))
        f.checks.append(Check('manual_review', 'manual', 'Bound human patch review is required; machine evidence alone cannot pass'))
    elif control_id == '1.5.3':
        _sysctl(f, {'fs.suid_dumpable': 0})
        f.test('hard_core_limits', lambda limits: '*' in limits and all(v == 0 for v in limits.values()))
        installed = f.read('systemd_coredump_installed')
        if installed is True:
            f.test('coredump_storage', lambda value: value == 'none')
            f.test('coredump_process_size_max', lambda value: value == 0)
        elif installed is False:
            f.checks.append(Check('systemd_coredump', 'inapplicable', 'Package absent'))
    elif control_id == '2.1.2':
        package = f.read('package.avahi-daemon')
        if package == 'absent':
            f.checks.append(Check('avahi_absent', 'pass'))
        elif package == 'installed':
            if not reviewed_avahi_retention:
                f.checks.append(Check('avahi_retention', 'manual', 'Dependency need and site-policy exception require review'))
            for unit in ('avahi-daemon.service','avahi-daemon.socket'):
                f.test(unit+'.active', lambda value: value == 'inactive')
                f.test(unit+'.enabled', lambda value: value in ('disabled','masked'))
    elif control_id == '5.3.3.2.2':
        resolution = f.read('pam_resolution')
        if resolution is not None:
            f.checks.append(Check('pam_resolution', 'pass' if resolution == 'complete' else 'missing'))
        f.test('effective_minlen', lambda values: bool(values) and all(v >= 14 for v in values.values()))
    elif control_id in ('5.4.1.1','5.4.1.3','5.4.1.5'):
        field, predicate = {'5.4.1.1': ('maximum', lambda v: 1 <= v <= 365),
                            '5.4.1.3': ('warning', lambda v: v >= 7),
                            '5.4.1.5': ('inactive', lambda v: 0 <= v <= 45)}[control_id]
        _accounts(f, field, predicate)
        if field == 'maximum':
            minimum, maximum = f.read('default.minimum'), f.read('default.maximum')
            if minimum is not None and maximum is not None:
                f.checks.append(Check('default.age_consistency', 'pass' if maximum > minimum else 'fail'))
    elif control_id in ('5.2.2','5.2.3'):
        f.test('sudoers_syntax_valid', lambda v: v)
        resolved = f.read('sudoers_resolution')
        if resolved is not None:
            f.checks.append(Check('sudoers_resolution','pass' if resolved == 'complete' else 'missing'))
        if control_id == '5.2.2':
            f.test('sudoers_use_pty', lambda values: bool(values) and 'enabled' in values and 'negated' not in values)
        else:
            f.test('sudoers_logfiles', lambda paths: bool(paths) and all(p.startswith('/') and '..' not in p.split('/') for p in paths))
    elif control_id == '4.1.3':
        f.test('package.ufw', lambda v: v == 'installed')
        f.test('ufw.service.enabled', lambda v: v == 'enabled')
        f.test('ufw.service.active', lambda v: v == 'active')
        f.test('ufw.active', lambda v: v)
    elif control_id in ('4.1.4','4.1.7'):
        manager = f.read('firewall_manager')
        if manager is not None and manager != 'ufw':
            f.checks.append(Check('firewall_manager', 'missing', 'Registered UFW applicability is not established'))
        f.test('ufw.active', lambda v: v)
        if control_id == '4.1.7':
            for direction in ('incoming','outgoing','routed'):
                f.test('ufw.default.'+direction, lambda v: v in ('deny','reject','disabled'))
        else:
            ipv6 = f.read('ipv6_enabled')
            for family in ('ipv4','ipv6'):
                if family == 'ipv6' and ipv6 is not True:
                    if ipv6 is False:
                        f.checks.append(Check('loopback.ipv6','inapplicable','IPv6 affirmatively disabled'))
                    continue
                # Resolver reports the actual first matching action for the enumerated traffic classes.
                for traffic, action in (('loopback_in','allow'),('loopback_out','allow'),('spoofed_in','deny')):
                    f.test('ufw.'+family+'.'+traffic, lambda v, expected=action: v == expected)
            complete = f.read('ufw_rule_resolution')
            if complete is not None:
                f.checks.append(Check('ufw_rule_resolution','pass' if complete == 'complete' else 'missing'))
    elif control_id == '6.3.1.2':
        f.test('auditd.enabled', lambda v: v == 'enabled')
        f.test('auditd.active', lambda v: v == 'active')
    elif control_id == '6.3.1.3':
        bootloader = f.read('bootloader')
        if bootloader is not None:
            f.checks.append(Check('bootloader','pass' if bootloader == 'grub2' else 'missing'))
        f.test('boot_entries', lambda entries: bool(entries) and all('audit=1' in args and 'audit=0' not in args for args in entries))
        # Current boot is collected and displayed separately, not conflated with generated boot policy.
        f.read('current_audit_argument')
    elif control_id in ('6.3.3.4','6.3.3.8','6.3.3.6'):
        if control_id == '6.3.3.4':
            architectures = f.read('audit_architectures')
            for source in ('persistent_audit_rules','loaded_audit_rules'):
                rules = f.read(source)
                if rules is not None and architectures is not None:
                    good = bool(architectures) and all(_rules_cover(rules, paths=('/etc/localtime',),
                        syscalls=('adjtimex','settimeofday','clock_settime'), arch=arch) for arch in architectures)
                    f.checks.append(Check(source,'pass' if good else 'fail'))
        elif control_id == '6.3.3.8':
            paths = f.read('identity_paths')
            for source in ('persistent_audit_rules','loaded_audit_rules'):
                rules = f.read(source)
                if rules is not None and paths is not None:
                    # No silent optional-file exclusions: initial contract requires all PDF paths.
                    good = set(paths) == IDENTITY_PATHS and _rules_cover(rules, paths=IDENTITY_PATHS)
                    f.checks.append(Check(source,'pass' if good else 'fail'))
        else:
            complete = f.read('privileged_inventory')
            if complete is not None:
                f.checks.append(Check('privileged_inventory','pass' if complete == 'complete' else 'missing'))
            paths, uid_min = f.read('privileged_paths'), f.read('uid_min')
            for source in ('persistent_audit_rules','loaded_audit_rules'):
                rules = f.read(source)
                if rules is not None and paths is not None and uid_min is not None:
                    good = all(_rules_cover(rules, privileged=path, uid_min=uid_min) for path in paths)
                    f.checks.append(Check(source,'pass' if good else 'fail'))
    elif control_id in SSH:
        resolved = f.read('ssh_context_resolution')
        if resolved is not None:
            f.checks.append(Check('ssh_context_resolution','pass' if resolved == 'complete' else 'missing'))
        contexts = f.read('ssh_contexts')
        if contexts is not None:
            if not contexts:
                f.checks.append(Check('ssh_contexts','missing','No audited SSH contexts'))
            for context in contexts:
                for option in SSH[control_id]:
                    value = context[option]
                    good = (1 <= value <= 4 if option == 'maxauthtries' else value > 0
                            if option in ('clientaliveinterval','clientalivecountmax') else value == 'no')
                    f.checks.append(Check('ssh.'+context['context_id']+'.'+option,'pass' if good else 'fail'))
    else:
        raise ValueError('Unregistered Ubuntu control')
    _scap(f, control_id, reviewed_avahi_retention, ssh_effective_authority, cis_audit_authority, audit_wording)
    return combine(control_id, f.checks)


# Reviewed SCAP rules whose wording is narrower than the CIS rule (administrator decision 2026-11-07, "Follow CIS"):
# when the persistent and loaded CIS audit rules both pass, such a rule's failure is advisory, not a conflict.
# Versions are kept so evidence stored under an earlier list still verifies (storage.EARLIER_RULES).
CIS_AUDIT_WORDING_V1 = {'6.3.3.4': {'audit_rules_time_clock_settime': (
    'CIS v2.0.0 audits every clock_settime call (-S adjtimex,settimeofday,clock_settime), which the persistent and '
    'loaded rules contain; this SCAP rule only accepts its narrower form -S clock_settime -F a0=0x0')}}
CIS_AUDIT_WORDING_V2 = {**CIS_AUDIT_WORDING_V1, '6.3.3.8': {'audit_rules_usergroup_modification_pamd': (
    'CIS v2.0.0 watches /etc/pam.d (-w /etc/pam.d -p wa -k identity), which the persistent and loaded rules contain; '
    'this SCAP rule matches the path only with a trailing slash, /etc/pam.d/')}}  # live 11:20, same decision
# Not only audit rules despite the name (kept for stored-evidence compatibility): any reviewed SCAP rule narrower
# than the CIS audit. Live 15:17: CIS recommends pwquality.conf.d and audits both locations.
CIS_AUDIT_WORDING = {**CIS_AUDIT_WORDING_V2, '5.3.3.2.2': {'accounts_password_pam_minlen': (
    'CIS v2.0.0 recommends minlen in a .conf file in /etc/security/pwquality.conf.d and audits both locations; the '
    'effective minlen resolved from them is 14 or more. This SCAP rule reads only /etc/security/pwquality.conf')}}


def _scap(f, control_id, reviewed_avahi_retention, ssh_effective_authority=True, cis_audit_authority=True,
          audit_wording=None):
    """Selected SCAP rule results are corroborating subchecks; direct effective-state probes stay authoritative.

    A SCAP pass never cancels a direct failure. A SCAP failure without a direct failure is a conflict
    (Unknown), not a confirmed finding. Unresolved results never pass; not-applicable is neutral.
    SSH (decided 2026-11-07): CIS 5.1.x audits the effective `sshd -T` value, with `-C` only for Match blocks.
    When context resolution is complete (no Match blocks) and every audited context complies, a SCAP failure,
    which for these rules demands an explicit configuration line CIS does not require, is an advisory
    subcheck instead of a conflict. `ssh_effective_authority=False` is the earlier rule, kept so evidence
    stored under it still verifies.
    """
    observation = f.observations.get('scap_rules')
    if observation is None:
        return  # Direct-only fixture evidence; live envelopes must carry SCAP results (envelope check).
    if observation['state'] != 'ok':
        f.checks.append(Check('scap', observation['state'], 'Selected SCAP evaluation is unresolved'))
        return
    direct_failed = any(c.state == 'fail' for c in f.checks)
    ssh_direct = [c for c in f.checks if c.name.startswith('ssh.')]
    ssh_decided = (ssh_effective_authority and control_id in SSH and bool(ssh_direct)
                   and all(c.state == 'pass' for c in ssh_direct)
                   and any(c.name == 'ssh_context_resolution' and c.state == 'pass' for c in f.checks))
    reviewed = CIS_AUDIT_WORDING if audit_wording is None else audit_wording
    wording = reviewed.get(control_id, {}) if cis_audit_authority else {}
    # Every direct check must pass (for the audit controls: the persistent and loaded rules; for 5.3.3.2.2: a
    # complete PAM resolution and the effective minlen). An unresolved or missing check never becomes advisory.
    audit_decided = bool(wording) and bool(f.checks) and all(c.state == 'pass' for c in f.checks)
    for rule in SCAP_RULES[control_id]:
        name, result = 'scap.' + rule[len(SCAP_RULE_PREFIX):], observation['value'][rule]
        if result == 'pass':
            f.checks.append(Check(name, 'pass', 'Does not cancel the direct failure' if direct_failed else ''))
        elif result == 'fail':
            if direct_failed:
                f.checks.append(Check(name, 'fail', 'Agrees with a direct failure'))
            elif audit_decided and rule[len(SCAP_RULE_PREFIX):] in wording:
                f.checks.append(Check(name, 'advisory', wording[rule[len(SCAP_RULE_PREFIX):]]))
            elif ssh_decided:
                f.checks.append(Check(name, 'advisory', 'CIS audits the effective sshd -T value, which complies in every '
                                      'audited context; this SCAP rule also requires an explicit configuration line'))
            elif reviewed_avahi_retention and control_id == '2.1.2' and rule.endswith('_package_avahi_removed'):
                f.checks.append(Check(name, 'inapplicable', 'Reviewed retention exception supersedes the removal rule'))
            else:
                f.checks.append(Check(name, 'conflict', 'SCAP rule failed without a corroborating direct failure'))
        elif result == 'error':
            f.checks.append(Check(name, 'error', 'SCAP rule evaluation error'))
        elif result == 'notapplicable':
            f.checks.append(Check(name, 'inapplicable', 'SCAP reports not applicable; direct checks decide'))
        else:
            f.checks.append(Check(name, 'missing', 'SCAP result ' + result + ' does not establish current state'))
