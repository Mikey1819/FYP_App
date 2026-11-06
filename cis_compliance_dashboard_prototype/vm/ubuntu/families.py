"""Target-side registry of implemented remediation families, bound to a target I/O system.

Implemented (fixture-tested only; not yet validated on the VM): the sysctl family for 1.5.1, 3.3.1,
3.3.2 and 3.3.8. Every other selected control has no family, so the runner refuses its action ID.
Test-only fixture families live under tests/ and are never registered here.
"""
from .family_sysctl import REQUIRED, SysctlFamily


def build(system):
    families = {}
    for control_id in sorted(REQUIRED):
        family = SysctlFamily(control_id, system)
        families[family.action_id] = family
    return families
