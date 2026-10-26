"""Analysis Agent risk engine (report Section 4.6.2). Deterministic; no model input.

R = 6I + 5E + 4P + 3L + 2D. No factor value is assigned by hand: each control records
three attributes taken from its benchmark entry, and fixed rules derived from report
Table 4.15 and the Table 4.14a/4.14c rubrics turn them into I, P and L. E comes from the
control's exposure surface and collected effective context (Table 4.14b); D from
compatible history (Table 4.14e).
"""
from dataclasses import dataclass
import json

from .domain import RiskFactors, Status, comparable, drift_factor

BASELINE_VERSION = 'rules-2026-10-26 (Table 4.15 derivation; category assignments under researcher review)'
PRIORITY = {'Critical': 1, 'High': 2, 'Moderate': 3, 'Low': 4}

# Security Impact (I) from the consequence named in the benchmark Rationale/Impact text (Table 4.15),
# scored with the Table 4.14a wording. Logging-only consequences score lower, as Table 4.15 states.
CONSEQUENCE = {
    'critical_protection_lost': (5, 'credentials recoverable or the network boundary disabled: '
                                    'severe compromise of critical security functions (4.14a score 5)'),
    'protection_weakened': (4, 'authentication or network protection weakened: may significantly affect '
                               'system security (4.14a score 4)'),
    'misuse_easier': (3, 'unauthorised activity or information disclosure made easier: affects an important '
                         'security function (4.14a score 3)'),
    'minor_reduction': (2, 'password ageing only: minor reduction in security posture (4.14a score 2)'),
    'detection_only': (2, 'logging or audit visibility only: minor reduction in security posture (4.14a score 2)'),
}
# Privilege Impact (P) from the accounts, groups or rights the setting governs (Table 4.15), Table 4.14c wording.
PRIVILEGE_SCOPE = {
    'admin_identity_or_stored_credentials': (5, 'exposes the administrator identity or stored credentials: directly '
                                                'affects highly privileged access (4.14c score 5)'),
    'all_local_accounts': (4, 'applies to every local account including the built-in Administrator: may '
                              'contribute to administrative access (4.14c score 4)'),
    'remote_admin_logon': (4, 'protects remote administrative access to the server: may contribute to '
                              'administrative access (4.14c score 4)'),
    'guest_or_anonymous': (2, 'affects only Guest or anonymous access: limited user-level functions (4.14c score 2)'),
    'logging_only': (1, 'governs logging only: minimal implications for privileges (4.14c score 1)'),
}
# Likelihood (L) from Profile Level + Assessment Status (Table 4.15): Level 1 and Automated apply more
# broadly and are more commonly checked/misconfigured, so they score higher.
LIKELIHOOD = {(1, True): 4, (1, False): 3, (2, True): 3, (2, False): 2}


@dataclass(frozen=True)
class ControlAttributes:
    """Attributes read from the benchmark entry; the only per-control input to scoring."""
    consequence: str
    privilege_scope: str
    level: int
    automated: bool
    surface: str
    rationale: str  # Paraphrase of the benchmark Rationale, for the explanation and audit trail.

    def __post_init__(self):
        if self.consequence not in CONSEQUENCE or self.privilege_scope not in PRIVILEGE_SCOPE \
                or (self.level, self.automated) not in LIKELIHOOD or self.surface not in SURFACE_EXPOSURE:
            raise ValueError('Unknown risk attribute')


@dataclass(frozen=True)
class Derivation:
    impact: int
    privilege: int
    likelihood: int
    surface: str
    reasons: dict
    rationale: str


def derive(control_id):
    """I, P and L for a control, with the rule that produced each value."""
    a = ATTRIBUTES[control_id]
    impact, impact_reason = CONSEQUENCE[a.consequence]
    privilege, privilege_reason = PRIVILEGE_SCOPE[a.privilege_scope]
    likelihood = LIKELIHOOD[(a.level, a.automated)]
    return Derivation(impact, privilege, likelihood, a.surface, dict(
        I=f'{a.consequence}: {impact_reason}', P=f'{a.privilege_scope}: {privilege_reason}',
        L=f"Level {a.level}, {'Automated' if a.automated else 'Manual'} (Table 4.15) = {likelihood}"), a.rationale)


# Table 4.14b: 3 = reachable within the network/controlled remote access; 4 = significant
# network exposure. Local NAT lab does not establish internet reachability, so 5 is only
# used when the collected effective firewall state shows the Public profile disabled.
SURFACE_EXPOSURE = {'network_logon': 3, 'network_anonymous': 4, 'network_boundary': 4,
                    'remote_desktop': 4, 'local_account': 3, 'local_secret': 2, 'detection': 2}
FIREWALL_SENSITIVE = {'network_logon', 'network_anonymous', 'remote_desktop', 'local_account'}


def _attrs(consequence, scope, surface, rationale):
    # Every selected control is "Level 1 - Member Server" and "(Automated)" in the Stand-alone v2.0.0
    # entry (see BENCHMARK_MAPPING.md); 1.2.3 (Manual) is not in the catalogue.
    return ControlAttributes(consequence, scope, 1, True, surface, rationale)


ATTRIBUTES = {
    '1.1.1': _attrs('misuse_easier', 'all_local_accounts', 'network_logon',
                    'Password reuse lets a previously exposed password stay valid.'),
    '1.1.2': _attrs('minor_reduction', 'all_local_accounts', 'network_logon',
                    'Passwords that never expire extend the useful life of a stolen credential.'),
    '1.1.3': _attrs('minor_reduction', 'all_local_accounts', 'network_logon',
                    'Without a minimum age, users can cycle through history to reuse a password.'),
    '1.1.4': _attrs('protection_weakened', 'all_local_accounts', 'network_logon',
                    'Short passwords are practical to guess or crack.'),
    '1.1.5': _attrs('protection_weakened', 'all_local_accounts', 'network_logon',
                    'Simple passwords fall quickly to dictionary and spraying attacks.'),
    '1.1.7': _attrs('critical_protection_lost', 'admin_identity_or_stored_credentials', 'local_secret',
                    'Reversible encryption makes stored passwords recoverable, equivalent to plaintext.'),
    '1.2.1': _attrs('misuse_easier', 'all_local_accounts', 'network_logon',
                    'A short lockout duration lets brute-force attempts resume quickly.'),
    '1.2.2': _attrs('protection_weakened', 'all_local_accounts', 'network_logon',
                    'No lockout threshold allows unlimited online password guessing (brute force).'),
    '1.2.4': _attrs('misuse_easier', 'all_local_accounts', 'network_logon',
                    'A short reset window lets attackers pace guesses below the threshold.'),
    '2.3.1.1': _attrs('misuse_easier', 'guest_or_anonymous', 'local_account',
                      'An enabled Guest account allows logon without a personal account.'),
    '2.3.1.2': _attrs('protection_weakened', 'all_local_accounts', 'network_logon',
                      'Accounts with blank passwords could be used from the network.'),
    '2.3.10.1': _attrs('misuse_easier', 'admin_identity_or_stored_credentials', 'network_anonymous',
                       'Anonymous SID/name translation reveals the real Administrator account name.'),
    '2.3.10.2': _attrs('misuse_easier', 'guest_or_anonymous', 'network_anonymous',
                       'Anonymous SAM enumeration lists local account names for targeted attacks.'),
    '2.3.10.3': _attrs('misuse_easier', 'guest_or_anonymous', 'network_anonymous',
                       'Anonymous enumeration of accounts and shares supports reconnaissance.'),
    '9.2.1': _attrs('critical_protection_lost', 'remote_admin_logon', 'network_boundary',
                    'A disabled Private firewall profile exposes every listening service.'),
    '9.3.1': _attrs('critical_protection_lost', 'remote_admin_logon', 'network_boundary',
                    'A disabled Public firewall profile exposes every listening service.'),
    '9.2.2': _attrs('protection_weakened', 'remote_admin_logon', 'network_boundary',
                    'Allowing unsolicited inbound connections exposes services without a matching rule.'),
    '9.3.2': _attrs('protection_weakened', 'remote_admin_logon', 'network_boundary',
                    'Allowing unsolicited inbound connections exposes services without a matching rule.'),
    '9.2.6': _attrs('detection_only', 'logging_only', 'detection', 'Blocked attack traffic is not recorded.'),
    '9.2.7': _attrs('detection_only', 'logging_only', 'detection', 'Successful connections are not recorded.'),
    '9.3.6': _attrs('detection_only', 'logging_only', 'detection', 'Blocked attack traffic is not recorded.'),
    '9.3.7': _attrs('detection_only', 'logging_only', 'detection', 'Successful connections are not recorded.'),
    '17.1.1': _attrs('detection_only', 'logging_only', 'detection', 'Failed credential validation is not audited.'),
    '17.2.2': _attrs('detection_only', 'logging_only', 'detection', 'Security group changes are not audited.'),
    '17.2.3': _attrs('detection_only', 'logging_only', 'detection', 'User account changes are not audited.'),
    '17.5.1': _attrs('detection_only', 'logging_only', 'detection', 'Account lockouts are not audited.'),
    '17.5.4': _attrs('detection_only', 'logging_only', 'detection', 'Logon successes and failures are not audited.'),
    '18.10.57.2.2': _attrs('misuse_easier', 'admin_identity_or_stored_credentials', 'local_secret',
                           'Saved RDP passwords can be recovered from the client profile.'),
    '18.10.57.3.9.1': _attrs('misuse_easier', 'remote_admin_logon', 'remote_desktop',
                             'Saved client credentials allow RDP logon without typing a password.'),
    '18.10.57.3.9.3': _attrs('protection_weakened', 'remote_admin_logon', 'remote_desktop',
                             'Without TLS the RDP server is not authenticated, enabling interception.'),
    '18.10.57.3.9.4': _attrs('protection_weakened', 'remote_admin_logon', 'remote_desktop',
                             'Without NLA the RDP logon screen is exposed before authentication.'),
    '18.10.57.3.9.5': _attrs('misuse_easier', 'remote_admin_logon', 'remote_desktop',
                             'Weaker RDP encryption levels protect the session less.'),
}


@dataclass(frozen=True)
class RankedFinding:
    control_id: str
    title: str
    area: str
    observed: object
    rule: str
    factors: dict
    score: int
    level: str
    priority: int
    exposure_reason: str
    drift_reason: str
    rationale: str
    factor_reasons: dict  # How I, P and L were derived (rule and attribute).


def effective_context(raw):
    """Collected effective state (separate from benchmark policy checks)."""
    try:
        rows = json.loads(raw).get('effective_context', [])
    except (ValueError, AttributeError):
        return {}
    return {r['control_id']: r['value'] for r in rows if isinstance(r, dict) and r.get('state') == 'ok'}


def exposure(surface, context):
    score = SURFACE_EXPOSURE[surface]
    reason = f'Surface {surface}: base exposure {score}.'
    if surface in FIREWALL_SENSITIVE and context.get('firewall_public_enabled') is False:
        score = min(5, score + 1)
        reason += ' Effective Public firewall is disabled: +1.'
    elif surface in FIREWALL_SENSITIVE and context.get('firewall_public_enabled') is True:
        reason += ' Effective Public firewall is enabled: no increase.'
    return score, reason


def rule_text(rule):
    operator, expected = rule.operator.value, rule.expected
    if operator == 'between':
        return f'between {expected[0]} and {expected[1]}'
    if operator == 'has_flags':
        return 'audit includes ' + ' and '.join(n for bit, n in ((1, 'Success'), (2, 'Failure')) if expected & bit)
    return ('at least ' if operator == 'at_least' else 'equals ') + repr(expected)


def analyse(record, previous_records=()):
    """Rank valid non-compliant findings. Unknown/Error results are not scored."""
    context = effective_context(record.raw)
    ranked = []
    for result in record.assessment.results:
        if result.status != Status.NON_COMPLIANT:
            continue
        if result.control.control_id not in ATTRIBUTES:
            continue  # No recorded attributes: never invent a score.
        derivation = derive(result.control.control_id)
        e, e_reason = exposure(derivation.surface, context)
        previous = next((p for older in previous_records for p in older.assessment.results
                         if comparable(p, result)), None)
        d = drift_factor(result, previous)
        d_reason = ('No previous comparable assessment (D=1).' if previous is None else
                    f'Previous comparable value {previous.evidence.value!r} was {previous.status.value} (D={d}).')
        factors = RiskFactors(derivation.impact, e, derivation.privilege, derivation.likelihood, d)
        ranked.append(RankedFinding(result.control.control_id, result.control.title, result.control.area,
            result.evidence.value, rule_text(result.control.rule), factors.as_dict(), factors.score,
            factors.level, PRIORITY[factors.level], e_reason, d_reason, derivation.rationale,
            derivation.reasons))
    # Highest score first; stable tie rule: control ID.
    return sorted(ranked, key=lambda f: (-f.score, f.control_id))
