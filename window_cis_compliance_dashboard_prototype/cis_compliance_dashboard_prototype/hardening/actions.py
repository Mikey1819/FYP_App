"""Reviewed action metadata used for remediation eligibility.

Registering metadata does not grant the runner a new executable capability.
"""
from dataclasses import dataclass
from types import MappingProxyType

from .domain import AssessmentResult, Status


@dataclass(frozen=True)
class ActionDefinition:
    action_id: str
    control_id: str
    minimum_length: int
    impact: str

    @property
    def parameters(self):
        return {"minimum_length": self.minimum_length}

    def eligible(self, result: AssessmentResult) -> bool:
        return (result.control.control_id == self.control_id
                and result.status == Status.NON_COMPLIANT
                and type(result.evidence.value) is int
                and 0 <= result.evidence.value < self.minimum_length)


PASSWORD_LENGTH = ActionDefinition(
    "SET-MINIMUM-PASSWORD-LENGTH-14", "1.1.4", 14,
    "Requires at least 14 characters when local passwords are next set or changed. "
    "Does not rotate existing passwords. Check provisioning scripts and operational requirements.",
)
ACTION_REGISTRY = MappingProxyType({PASSWORD_LENGTH.action_id: PASSWORD_LENGTH})
