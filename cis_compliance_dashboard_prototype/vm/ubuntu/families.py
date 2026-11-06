"""Target-side registry of implemented remediation families, bound to a target I/O system.

Implemented (fixture-tested only; not yet validated on the VM): the sysctl family for 1.5.1, 3.3.1,
3.3.2 and 3.3.8, the core-dump family for 1.5.3, sudo logfile 5.2.3, password minlen 5.3.3.2.2 and account aging 5.4.1.1/5.4.1.3/5.4.1.5. Every other selected control has no family, so the runner refuses its action ID.
Test-only fixture families live under tests/ and are never registered here.
"""
from .family_aging import AgingFamily, LinuxAgingIO, SPECS as AGING
from .family_auth import LinuxAuthIO, PasswordMinlenFamily, SudoLogfileFamily
from .family_core import CoreDumpFamily, LinuxCoreDumpIO
from .family_sysctl import LinuxSysctlSystem, REQUIRED, SysctlFamily


class LinuxTargetSystem(LinuxAgingIO, LinuxAuthIO, LinuxCoreDumpIO, LinuxSysctlSystem):
    """Fixed, bounded target I/O shared by the implemented families (unvalidated on the VM)."""


def build(system):
    families = {}
    for control_id in sorted(REQUIRED):
        family = SysctlFamily(control_id, system)
        families[family.action_id] = family
    fixed = [CoreDumpFamily(system), SudoLogfileFamily(system), PasswordMinlenFamily(system)]
    for family in fixed + [AgingFamily(control_id, system) for control_id in sorted(AGING)]:
        families[family.action_id] = family
    return families
