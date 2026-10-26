"""Analysis Agent risk engine (report Section 4.6.2). Deterministic; no model input.

R = 6I + 5E + 4P + 3L + 2D. I/P/L are per-control baselines assigned once during
catalogue design (Table 4.15); E is derived from the control's exposure surface and
collected effective context (Table 4.14b); D comes from compatible history (Table 4.14e).
"""
from dataclasses import dataclass
import json

from .domain import RiskFactors, Status, comparable, drift_factor

BASELINE_VERSION = 'draft-2026-10-26 (researcher review required)'
PRIORITY = {'Critical': 1, 'High': 2, 'Moderate': 3, 'Low': 4}


@dataclass(frozen=True)
class Baseline:
    impact: int
    privilege: int
    likelihood: int
    surface: str
    rationale: str


# Likelihood: every current control is Level 1 and Automated, so Table 4.15 places them
# at 3-4; 4 is used where the rationale names a common, tool-assisted attack.
BASELINES = {
    '1.1.1': Baseline(3, 3, 3, 'network_logon', 'Password reuse lets a previously exposed password stay valid.'),
    '1.1.2': Baseline(2, 3, 2, 'network_logon', 'Passwords that never expire extend the useful life of a stolen credential.'),
    '1.1.3': Baseline(2, 2, 2, 'network_logon', 'Without a minimum age, users can cycle through history to reuse a password.'),
    '1.1.4': Baseline(4, 3, 4, 'network_logon', 'Short passwords are practical to guess or crack, including for administrative accounts.'),
    '1.1.5': Baseline(4, 3, 4, 'network_logon', 'Simple passwords fall quickly to dictionary and spraying attacks.'),
    '1.1.7': Baseline(5, 4, 3, 'local_secret', 'Reversible encryption makes stored passwords recoverable, equivalent to plaintext.'),
    '1.2.1': Baseline(3, 3, 3, 'network_logon', 'A short lockout duration lets brute-force attempts resume quickly.'),
    '1.2.2': Baseline(4, 3, 3, 'network_logon', 'No lockout threshold allows unlimited online password guessing (brute force).'),
    '1.2.4': Baseline(2, 3, 3, 'network_logon', 'A short reset window lets attackers pace guesses below the threshold.'),
    '2.3.1.1': Baseline(3, 2, 3, 'local_account', 'An enabled Guest account provides unauthenticated-style access to the server.'),
    '2.3.1.2': Baseline(4, 3, 3, 'network_logon', 'Accounts with blank passwords could be used from the network.'),
    '2.3.10.1': Baseline(3, 4, 3, 'network_anonymous', 'Anonymous SID/name translation reveals the real Administrator account name.'),
    '2.3.10.2': Baseline(3, 3, 3, 'network_anonymous', 'Anonymous SAM enumeration lists local account names for targeted attacks.'),
    '2.3.10.3': Baseline(3, 3, 3, 'network_anonymous', 'Anonymous enumeration of accounts and shares supports reconnaissance.'),
    '9.3.1': Baseline(5, 3, 4, 'network_boundary', 'A disabled Public firewall profile exposes every listening service.'),
    '18.10.57.3.9.4': Baseline(4, 4, 3, 'remote_desktop', 'Without NLA the RDP logon screen is exposed before authentication.'),
    '9.2.1': Baseline(5, 3, 4, 'network_boundary', 'A disabled Private firewall profile exposes every listening service.'),
    '9.2.2': Baseline(4, 3, 4, 'network_boundary', 'Allowing unsolicited inbound connections exposes services without a matching rule.'),
    '9.3.2': Baseline(4, 3, 4, 'network_boundary', 'Allowing unsolicited inbound connections exposes services without a matching rule.'),
    # Table 4.15: consequences that are "mainly logging visibility" score lower on Impact.
    '9.2.6': Baseline(2, 1, 2, 'detection', 'Without dropped-packet logs, blocked attack traffic is not recorded.'),
    '9.2.7': Baseline(2, 1, 2, 'detection', 'Without connection logs, successful intrusions are harder to reconstruct.'),
    '9.3.6': Baseline(2, 1, 2, 'detection', 'Without dropped-packet logs, blocked attack traffic is not recorded.'),
    '9.3.7': Baseline(2, 1, 2, 'detection', 'Without connection logs, successful intrusions are harder to reconstruct.'),
    '17.1.1': Baseline(2, 3, 3, 'detection', 'Failed credential validation (password guessing) is not audited.'),
    '17.2.2': Baseline(2, 4, 3, 'detection', 'Changes to security groups such as Administrators are not audited.'),
    '17.2.3': Baseline(2, 3, 3, 'detection', 'Creation, change or deletion of user accounts is not audited.'),
    '17.5.1': Baseline(2, 2, 3, 'detection', 'Accounts locked out by repeated failures are not audited.'),
    '17.5.4': Baseline(2, 3, 3, 'detection', 'Logon successes and failures are not audited.'),
    '18.10.57.2.2': Baseline(3, 3, 3, 'local_secret', 'Saved RDP passwords can be recovered from the client profile.'),
    '18.10.57.3.9.1': Baseline(3, 3, 3, 'remote_desktop', 'Saved client credentials allow RDP logon without typing a password.'),
    '18.10.57.3.9.3': Baseline(4, 3, 3, 'remote_desktop', 'Without TLS the RDP server is not authenticated, enabling interception.'),
    '18.10.57.3.9.5': Baseline(3, 3, 3, 'remote_desktop', 'Weaker RDP encryption levels protect the session less.'),
}

# Table 4.14b: 3 = reachable within the network/controlled remote access; 4 = significant
# network exposure. Local NAT lab does not establish internet reachability, so 5 is only
# used when the collected effective firewall state shows the Public profile disabled.
SURFACE_EXPOSURE = {'network_logon': 3, 'network_anonymous': 4, 'network_boundary': 4,
                    'remote_desktop': 4, 'local_account': 3, 'local_secret': 2, 'detection': 2}
FIREWALL_SENSITIVE = {'network_logon', 'network_anonymous', 'remote_desktop', 'local_account'}


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


def effective_context(raw):
    """Collected effective state (separate from benchmark policy checks)."""
    try:
        rows = json.loads(raw).get('effective_context', [])
    except (ValueError, AttributeError):
        return {}
    return {r['control_id']: r['value'] for r in rows if isinstance(r, dict) and r.get('state') == 'ok'}


def exposure(baseline, context):
    score = SURFACE_EXPOSURE[baseline.surface]
    reason = f'Surface {baseline.surface}: base exposure {score}.'
    if baseline.surface in FIREWALL_SENSITIVE and context.get('firewall_public_enabled') is False:
        score = min(5, score + 1)
        reason += ' Effective Public firewall is disabled: +1.'
    elif baseline.surface in FIREWALL_SENSITIVE and context.get('firewall_public_enabled') is True:
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
        baseline = BASELINES.get(result.control.control_id)
        if baseline is None:
            continue  # No reviewed baseline: never invent a score.
        e, e_reason = exposure(baseline, context)
        previous = next((p for older in previous_records for p in older.assessment.results
                         if comparable(p, result)), None)
        d = drift_factor(result, previous)
        d_reason = ('No previous comparable assessment (D=1).' if previous is None else
                    f'Previous comparable value {previous.evidence.value!r} was {previous.status.value} (D={d}).')
        factors = RiskFactors(baseline.impact, e, baseline.privilege, baseline.likelihood, d)
        ranked.append(RankedFinding(result.control.control_id, result.control.title, result.control.area,
            result.evidence.value, rule_text(result.control.rule), factors.as_dict(), factors.score,
            factors.level, PRIORITY[factors.level], e_reason, d_reason, baseline.rationale))
    # Highest score first; stable tie rule: control ID.
    return sorted(ranked, key=lambda f: (-f.score, f.control_id))
