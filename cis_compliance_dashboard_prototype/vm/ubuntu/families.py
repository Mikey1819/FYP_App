"""Target-side registry of implemented remediation families, bound to a target I/O system.

Implemented (fixture-tested only; not yet validated on the VM): the sysctl family for 1.5.1, 3.3.1,
3.3.2 and 3.3.8, the core-dump family for 1.5.3, sudo logfile 5.2.3, password minlen 5.3.3.2.2 account aging 5.4.1.1/5.4.1.3/5.4.1.5 supervised package jobs 1.3.1.1/1.5.4/2.1.2/6.3.1.1 commit-confirm SSH 5.1.x and UFW default deny 4.1.7. Every other selected control has no family, so the runner refuses its action ID.
Test-only fixture families live under tests/ and are never registered here.
"""
from .family_aging import AgingFamily, LinuxAgingIO, SPECS as AGING
from .family_auth import LinuxAuthIO, PasswordMinlenFamily, SudoLogfileFamily, SudoUsePtyFamily
from .family_service import LinuxServiceIO, ServiceFamily, SPECS as SERVICE_SPECS
from .family_audit import AuditRulesFamily, FILES as AUDIT_FILES, LinuxAuditIO
from .family_grub import GrubAuditFamily, LinuxGrubIO
from .family_package import LinuxPackageIO, PackageFamily, SPECS as PACKAGE_SPECS
from .family_ssh import LinuxSshIO, SETTINGS as SSH_SETTINGS, SshFamily
from .family_ufw import LinuxUfwIO, UfwDefaultDenyFamily
from .family_core import CoreDumpFamily, LinuxCoreDumpIO
from .family_sysctl import LinuxSysctlSystem, REQUIRED, SysctlFamily


class LinuxTargetSystem(LinuxGrubIO, LinuxAuditIO, LinuxServiceIO, LinuxUfwIO, LinuxSshIO, LinuxPackageIO, LinuxAgingIO, LinuxAuthIO, LinuxCoreDumpIO, LinuxSysctlSystem):
    """Fixed, bounded target I/O shared by the implemented families (unvalidated on the VM)."""


def build(system):
    families = {}
    for control_id in sorted(REQUIRED):
        family = SysctlFamily(control_id, system)
        families[family.action_id] = family
    fixed = [CoreDumpFamily(system), SudoLogfileFamily(system), SudoUsePtyFamily(system), PasswordMinlenFamily(system)]
    fixed += [ServiceFamily(control_id, system) for control_id in sorted(SERVICE_SPECS)]
    fixed += [AuditRulesFamily(control_id, system) for control_id in sorted(AUDIT_FILES)] + [GrubAuditFamily(system)]
    fixed += [AgingFamily(control_id, system) for control_id in sorted(AGING)]
    fixed += [PackageFamily(control_id, system) for control_id in sorted(PACKAGE_SPECS)]
    fixed += [SshFamily(control_id, system) for control_id in sorted(SSH_SETTINGS)]
    for family in fixed + [UfwDefaultDenyFamily(system)]:
        families[family.action_id] = family
    return families
