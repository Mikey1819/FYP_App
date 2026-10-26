"""Pure assessment rules. No UI, model, database, or operating-system access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    COMPLIANT = "Compliant"
    NON_COMPLIANT = "Non-Compliant"
    ERROR = "Error"
    UNKNOWN = "Unknown"


class EvidenceMode(str, Enum):
    SYNTHETIC = "Synthetic"
    IMPORTED = "Imported"
    LIVE = "Live"


class Operator(str, Enum):
    EQUALS = "equals"
    AT_LEAST = "at_least"
    BETWEEN = "between"
    HAS_FLAGS = "has_flags"  # Audit policy: 1=Success, 2=Failure; "include Success" passes 1 and 3.


Scalar = bool | int | str


@dataclass(frozen=True)
class Rule:
    operator: Operator
    expected: Scalar | tuple[int, int]

    def __post_init__(self) -> None:
        if not isinstance(self.operator, Operator):
            raise ValueError("A supported comparison operator is required")
        if self.operator == Operator.EQUALS:
            valid = type(self.expected) in (bool, int, str)
        elif self.operator == Operator.AT_LEAST:
            valid = type(self.expected) is int
        elif self.operator == Operator.HAS_FLAGS:
            valid = type(self.expected) is int and self.expected > 0
        else:
            valid = (
                type(self.expected) is tuple
                and len(self.expected) == 2
                and all(type(value) is int for value in self.expected)
                and self.expected[0] <= self.expected[1]
            )
        if not valid:
            raise ValueError("Expected value does not match the comparison operator")

    def matches(self, observed: Scalar) -> bool:
        expected_type = type(self.expected) if self.operator == Operator.EQUALS else int
        # bool is a subclass of int in Python: do not accept True as a count of 1.
        if type(observed) is not expected_type:
            raise ValueError(f"Expected {expected_type.__name__} evidence, received {type(observed).__name__}")
        if self.operator == Operator.EQUALS:
            return observed == self.expected
        if self.operator == Operator.AT_LEAST:
            return observed >= self.expected
        if self.operator == Operator.HAS_FLAGS:
            return observed & self.expected == self.expected
        lower, upper = self.expected
        return lower <= observed <= upper


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    area: str
    rule: Rule
    catalogue_version: str
    profile: str
    source_reference: str
    source_verified: bool = False
    # Decision D5: a Group Policy setting that is absent ("Not configured") fails the CIS
    # recommendation, which requires it to be set. Other absent values stay Unknown.
    not_configured_fails: bool = False

    def __post_init__(self) -> None:
        if any(not value.strip() for value in (
            self.control_id, self.title, self.area, self.catalogue_version,
            self.profile, self.source_reference,
        )):
            raise ValueError("Control identity and source metadata must not be empty")


@dataclass(frozen=True)
class Evidence:
    target_id: str
    control_id: str
    value: Scalar | None
    collected_at: datetime
    mode: EvidenceMode
    source: str
    error: str | None = None

    def __post_init__(self) -> None:
        if not self.target_id.strip() or not self.control_id.strip() or not self.source.strip():
            raise ValueError("Evidence must identify its target, control and source")
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("Evidence timestamps must include a timezone")
        if not isinstance(self.mode, EvidenceMode):
            raise ValueError("Evidence mode must be explicit")


@dataclass(frozen=True)
class AssessmentResult:
    assessment_id: str
    control: Control
    evidence: Evidence
    status: Status
    detail: str


def assess(assessment_id: str, control: Control, evidence: Evidence) -> AssessmentResult:
    if not assessment_id.strip():
        raise ValueError("Assessment identifier is required")
    if evidence.control_id != control.control_id:
        raise ValueError("Evidence belongs to a different control")
    if evidence.error is not None:
        status, detail = Status.ERROR, evidence.error or "Collection failed"
    elif evidence.value is None and control.not_configured_fails:
        status, detail = Status.NON_COMPLIANT, "Not configured: the benchmark requires this policy to be set"
    elif evidence.value is None:
        status, detail = Status.UNKNOWN, "No configuration value was collected"
    else:
        try:
            passed = control.rule.matches(evidence.value)
            status = Status.COMPLIANT if passed else Status.NON_COMPLIANT
            detail = "Observed value satisfies the rule" if passed else "Observed value does not satisfy the rule"
        except ValueError as error:
            status, detail = Status.ERROR, str(error)
    return AssessmentResult(assessment_id, control, evidence, status, detail)


@dataclass(frozen=True)
class AssessmentSummary:
    selected: int
    compliant: int
    non_compliant: int
    errors: int
    unknown: int

    @property
    def evaluated(self) -> int:
        return self.compliant + self.non_compliant

    @property
    def compliance_percent(self) -> float | None:
        return 100 * self.compliant / self.evaluated if self.evaluated else None


def summarise(results: tuple[AssessmentResult, ...]) -> AssessmentSummary:
    if len({result.control.control_id for result in results}) != len(results):
        raise ValueError("An assessment cannot count the same control twice")
    if len({(r.assessment_id, r.evidence.target_id, r.evidence.mode) for r in results}) > 1:
        raise ValueError("Do not combine different assessments, targets or evidence modes")
    return AssessmentSummary(
        len(results),
        sum(r.status == Status.COMPLIANT for r in results),
        sum(r.status == Status.NON_COMPLIANT for r in results),
        sum(r.status == Status.ERROR for r in results),
        sum(r.status == Status.UNKNOWN for r in results),
    )


VALID_STATUSES = (Status.COMPLIANT, Status.NON_COMPLIANT)


def same_measurement(a: Control, b: Control) -> bool:
    """Same control, benchmark citation (edition, section, pages), profile and rule.

    The catalogue version labels a catalogue's scope (5, 12, 16 or 32 controls); a control
    whose source, profile and rule are unchanged is the same measurement in every scope.
    """
    return (a.control_id == b.control_id and a.rule == b.rule and a.profile == b.profile
            and a.source_reference == b.source_reference)


def comparable(previous: AssessmentResult | None, current: AssessmentResult) -> bool:
    return bool(
        previous is not None
        and previous.assessment_id != current.assessment_id
        and same_measurement(previous.control, current.control)
        and previous.evidence.source == current.evidence.source
        and previous.evidence.target_id == current.evidence.target_id
        and previous.evidence.mode == current.evidence.mode
        and previous.evidence.collected_at < current.evidence.collected_at
        and previous.status in VALID_STATUSES
        and current.status in VALID_STATUSES
    )


def change_kind(previous: AssessmentResult | None, current: AssessmentResult) -> str:
    if not comparable(previous, current):
        return "No comparable evidence"
    if previous.evidence.value == current.evidence.value:
        return "Unchanged"
    if previous.status == Status.COMPLIANT and current.status == Status.NON_COMPLIANT:
        return "Regression"
    if previous.status == Status.NON_COMPLIANT and current.status == Status.COMPLIANT:
        return "Improvement"
    return "Changed; compliance unchanged"


def drift_factor(current: AssessmentResult, previous: AssessmentResult | None = None) -> int:
    if current.status != Status.NON_COMPLIANT:
        raise ValueError("Only non-compliant findings receive a drift risk factor")
    if not comparable(previous, current):
        return 1
    # Preview decision: all persistent non-compliance is D=3, even if its value changed.
    return 5 if previous.status == Status.COMPLIANT else 3


@dataclass(frozen=True)
class RiskFactors:
    impact: int
    exposure: int
    privilege: int
    likelihood: int
    drift: int

    def __post_init__(self) -> None:
        if any(type(value) is not int or not 1 <= value <= 5 for value in self.as_dict().values()):
            raise ValueError("All risk factors must be integers between 1 and 5")
        if self.drift not in (1, 3, 5):
            raise ValueError("Drift must follow the defined 1/3/5 history rubric")

    def as_dict(self) -> dict[str, int]:
        return {"I": self.impact, "E": self.exposure, "P": self.privilege,
                "L": self.likelihood, "D": self.drift}

    @property
    def score(self) -> int:
        return 6 * self.impact + 5 * self.exposure + 4 * self.privilege + 3 * self.likelihood + 2 * self.drift

    @property
    def level(self) -> str:
        return risk_level(self.score)


def risk_level(score: int) -> str:
    if type(score) is not int or not 20 <= score <= 100:
        raise ValueError("Risk scores must be integers between 20 and 100")
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def prioritise(
    current: AssessmentResult, *, impact: int, exposure: int,
    privilege: int, likelihood: int, previous: AssessmentResult | None = None,
) -> RiskFactors:
    return RiskFactors(impact, exposure, privilege, likelihood, drift_factor(current, previous))
