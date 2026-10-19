"""Synthetic evidence and UI projections; these are not verified CIS rules."""

from datetime import datetime, timezone, timedelta

from .domain import (
    Control, Evidence, EvidenceMode, Operator, Rule, Status, assess,
    change_kind, prioritise, summarise,
)


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
SUMMARY = summarise(CURRENT_RESULTS)

# I/P/L are illustrative baselines; E is explicitly supplied synthetic context.
# These inputs are not AI-generated or claims about the actual laptop/server.
RISK_INPUTS = {
    "DEMO-LOCKOUT": (4, 3, 3, 3),
    "DEMO-PASSWORD": (4, 3, 2, 1),
    "DEMO-NLA": (5, 4, 4, 3),
}
EXPLANATIONS = {
    "DEMO-NLA": "The sample does not require Network Level Authentication for Remote Desktop.",
    "DEMO-LOCKOUT": "A zero lockout threshold in this sample leaves password attempts unrestricted by account lockout.",
    "DEMO-PASSWORD": "The sample password-length policy falls below the demonstration minimum.",
}


def display_value(control_id: str, value) -> str:
    if value is None:
        return "Not collected"
    if control_id == "DEMO-LOCKOUT":
        return f"{value} invalid attempts"
    if control_id == "DEMO-PASSWORD":
        return f"{value} characters"
    labels = {
        "DEMO-GUEST": ("Disabled", "Enabled"),
        "DEMO-FIREWALL": ("Off", "On"),
        "DEMO-NLA": ("Not required", "Required"),
    }
    return labels[control_id][int(value)] if type(value) is bool else str(value)


def display_rule(definition: Control) -> str:
    rule = definition.rule
    if rule.operator == Operator.BETWEEN:
        return f"{rule.expected[0]} to {rule.expected[1]} invalid attempts"
    if rule.operator == Operator.AT_LEAST:
        return f"At least {display_value(definition.control_id, rule.expected)}"
    return display_value(definition.control_id, rule.expected)


CONTROLS = [
    {"id": result.control.control_id, "title": result.control.title,
     "observed": display_value(result.control.control_id, result.evidence.value),
     "expected": display_rule(result.control), "status": result.status.value,
     "source": result.evidence.source, "assessed_at": result.evidence.collected_at.isoformat(),
     "reference": result.control.source_reference}
    for result in CURRENT_RESULTS
]

RISKS = {}
for current, previous in zip(CURRENT_RESULTS, PREVIOUS_RESULTS):
    if current.status != Status.NON_COMPLIANT:
        continue
    impact, exposure, privilege, likelihood = RISK_INPUTS[current.control.control_id]
    factors = prioritise(current, impact=impact, exposure=exposure, privilege=privilege,
                         likelihood=likelihood, previous=previous)
    RISKS[current.control.control_id] = {
        "title": current.control.title, "score": factors.score, "level": factors.level,
        "factors": factors.as_dict(), "explanation": EXPLANATIONS[current.control.control_id],
    }
RISKS = dict(sorted(RISKS.items(), key=lambda pair: (-pair[1]["score"], pair[0])))

DRIFT = [
    {"Control": current.control.control_id,
     "Previous value": display_value(previous.control.control_id, previous.evidence.value),
     "Current value": display_value(current.control.control_id, current.evidence.value),
     "Description": change_kind(previous, current),
     "Detected at": current.evidence.collected_at.isoformat()}
    for current, previous in zip(CURRENT_RESULTS, PREVIOUS_RESULTS)
    if change_kind(previous, current) not in ("Unchanged", "No comparable evidence")
]

HISTORY = [
    {"Assessment": "1042", "Initiated by": "demo-admin", "Started": CURRENT_TIME.isoformat(), "Status": "Completed snapshot"},
    {"Assessment": "1041", "Initiated by": "demo-admin", "Started": PREVIOUS_TIME.isoformat(), "Status": "Completed snapshot"},
]
