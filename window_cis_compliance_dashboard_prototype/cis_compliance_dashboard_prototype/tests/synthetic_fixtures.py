"""Synthetic evidence for the domain rule tests; these are not verified CIS rules and inspect no server."""

from datetime import datetime, timezone, timedelta

from hardening.domain import Control, Evidence, EvidenceMode, Operator, Rule, Status, assess, prioritise


TARGET_ID = "DEMO-SERVER-2022"
PROFILE = "Unvalidated demonstration profile"
CATALOGUE_VERSION = "demo-v1"
TIMEZONE = timezone(timedelta(hours=8))
CURRENT_TIME = datetime(2026, 8, 12, 9, 18, 42, tzinfo=TIMEZONE)
PREVIOUS_TIME = datetime(2026, 8, 5, 11, 35, tzinfo=TIMEZONE)


def control(control_id: str, title: str, area: str, rule: Rule, reference: str) -> Control:
    return Control(control_id, title, area, rule, CATALOGUE_VERSION, PROFILE,
                   f"Report Table 3.2 candidate: {reference}; benchmark not independently verified")


CATALOGUE = (
    control("DEMO-LOCKOUT", "Account lockout threshold", "Account Policies",
            Rule(Operator.BETWEEN, (1, 10)), "1.2.2"),
    control("DEMO-PASSWORD", "Minimum password length", "Account Policies",
            Rule(Operator.AT_LEAST, 14), "1.1.4"),
    control("DEMO-GUEST", "Guest account status", "Local Security Options",
            Rule(Operator.EQUALS, False), "2.3.1.1"),
    control("DEMO-FIREWALL", "Windows Firewall (Domain) state", "Windows Defender Firewall",
            Rule(Operator.EQUALS, True), "9.1.1"),
    control("DEMO-NLA", "Remote Desktop network authentication", "Remote Desktop Services",
            Rule(Operator.EQUALS, True), "18.10.57.3.9.4"),
)


def make_results(values: tuple, assessment_id: str, timestamp: datetime):
    if len(values) != len(CATALOGUE):
        raise ValueError("Each selected demo control needs evidence, even if its value is missing")
    return tuple(
        assess(assessment_id, definition, Evidence(
            TARGET_ID, definition.control_id, value, timestamp,
            EvidenceMode.SYNTHETIC, "Built-in preview fixture; no server inspected",
        )) for definition, value in zip(CATALOGUE, values)
    )


CURRENT_RESULTS = make_results((0, 8, False, True, False), "1042", CURRENT_TIME)
PREVIOUS_RESULTS = make_results((10, 8, False, False, True), "1041", PREVIOUS_TIME)

# I/P/L are illustrative baselines; E is explicitly supplied synthetic context.
RISK_INPUTS = {
    "DEMO-LOCKOUT": (4, 3, 3, 3),
    "DEMO-PASSWORD": (4, 3, 2, 1),
    "DEMO-NLA": (5, 4, 4, 3),
}

RISKS = {}
for current, previous in zip(CURRENT_RESULTS, PREVIOUS_RESULTS):
    if current.status != Status.NON_COMPLIANT:
        continue
    impact, exposure, privilege, likelihood = RISK_INPUTS[current.control.control_id]
    factors = prioritise(current, impact=impact, exposure=exposure, privilege=privilege,
                         likelihood=likelihood, previous=previous)
    RISKS[current.control.control_id] = {"score": factors.score, "level": factors.level, "factors": factors.as_dict()}
