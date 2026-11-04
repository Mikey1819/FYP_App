"""Pre-approved remediation library (report Section 4.6.3).

Python holds only metadata: which control an action fixes, the fixed target value,
its prerequisites and impact. The implementation lives in a fixed table inside
scripts/vm/Invoke-RemediationAction.ps1; a request carries an action ID and value, never
a command. LibraryParityTests (tests/test_agentic.py) checks the two tables agree.
"""
from dataclasses import dataclass
from types import MappingProxyType

from .domain import AssessmentResult, Status


@dataclass(frozen=True)
class LibraryAction:
    action_id: str
    control_id: str
    title: str
    target_value: int | bool
    impact: str
    requires_compliant: tuple[str, ...] = ()

    def eligible(self, result: AssessmentResult) -> bool:
        observed = result.evidence.value
        # A "Not configured" policy (value absent, decision D5) may be set; any other absent value may not.
        typed = (observed is None and result.control.not_configured_fails) or type(observed) is type(self.target_value)
        return (result.control.control_id == self.control_id
                and result.status == Status.NON_COMPLIANT
                and typed
                and result.control.rule.matches(self.target_value))

# Do other control need fixing first? 1.2.1 and 1.2.4 require 1.2.2 to be compliant first, otherwise the lockout policy is not fully applied.
    def blocked_by(self, results) -> list[str]:
        """Prerequisite controls that are not yet compliant in the same assessment."""
        status = {r.control.control_id: r.status for r in results}
        return [c for c in self.requires_compliant if status.get(c) != Status.COMPLIANT]


_ACCOUNT = 'Applies when local passwords are next set or changed; existing passwords are not rotated. '
_AUDIT = 'Adds Security event log entries for this subcategory; increases log volume slightly. Nothing is disabled.'
_RDP = 'Sets the local Remote Desktop policy value; existing sessions are unaffected until reconnect. '
LIBRARY = MappingProxyType({a.action_id: a for a in (
    LibraryAction('REM-1.1.1', '1.1.1', 'Enforce password history: 24', 24,
                  _ACCOUNT + 'Users cannot reuse their previous 24 passwords.'),
    LibraryAction('REM-1.1.2', '1.1.2', 'Maximum password age: 365 days', 365,
                  _ACCOUNT + 'Passwords older than 365 days must be changed at next logon.'),
    LibraryAction('REM-1.1.3', '1.1.3', 'Minimum password age: 1 day', 1,
                  _ACCOUNT + 'A new password cannot be changed again for one day.'),
    LibraryAction('REM-1.1.4', '1.1.4', 'Minimum password length: 14', 14,
                  _ACCOUNT + 'Provisioning scripts must generate passwords of at least 14 characters.'),
    LibraryAction('REM-1.2.2', '1.2.2', 'Account lockout threshold: 5', 5,
                  'Accounts lock after 5 failed logons. Windows also enables a default lockout duration and '
                  'reset window, which usually resolves 1.2.1 and 1.2.4 (rescan to confirm).'),
    LibraryAction('REM-1.2.1', '1.2.1', 'Account lockout duration: 15 minutes', 15,
                  'Locked accounts unlock after 15 minutes.', requires_compliant=('1.2.2',)),
    LibraryAction('REM-1.2.4', '1.2.4', 'Reset lockout counter after: 15 minutes', 15,
                  'Failed-logon counter resets after 15 minutes.', requires_compliant=('1.2.2', '1.2.1')),
    LibraryAction('REM-2.3.1.1', '2.3.1.1', 'Disable the built-in Guest account', False,
                  'The Guest account (SID RID 501) can no longer log on.'),
    LibraryAction('REM-2.3.1.2', '2.3.1.2', 'Limit blank-password accounts to console logon', 1,
                  'Local accounts with blank passwords cannot log on over the network.'),
    LibraryAction('REM-2.3.10.2', '2.3.10.2', 'Block anonymous enumeration of SAM accounts', 1,
                  'Anonymous users can no longer list local account names.'),
    LibraryAction('REM-2.3.10.3', '2.3.10.3', 'Block anonymous enumeration of SAM accounts and shares', 1,
                  'Anonymous users can no longer list accounts or shares; legacy anonymous tools may stop working.'),
    # Audit actions only enable the required flags (auditpol /set ... :enable); they never disable auditing.
    LibraryAction('REM-17.1.1', '17.1.1', 'Audit Credential Validation: Success and Failure', 3, _AUDIT),
    LibraryAction('REM-17.2.2', '17.2.2', 'Audit Security Group Management: enable Success', 1, _AUDIT),
    LibraryAction('REM-17.2.3', '17.2.3', 'Audit User Account Management: Success and Failure', 3, _AUDIT),
    LibraryAction('REM-17.5.1', '17.5.1', 'Audit Account Lockout: enable Failure', 2, _AUDIT),
    LibraryAction('REM-17.5.4', '17.5.4', 'Audit Logon: Success and Failure', 3, _AUDIT),
    LibraryAction('REM-18.10.57.2.2', '18.10.57.2.2', 'RDP: do not allow passwords to be saved', 1,
                  _RDP + 'Remote Desktop clients on this server can no longer save passwords.'),
    LibraryAction('REM-18.10.57.3.9.1', '18.10.57.3.9.1', 'RDP: always prompt for password', 1,
                  _RDP + 'Users must type their password at every RDP connection.'),
    LibraryAction('REM-18.10.57.3.9.3', '18.10.57.3.9.3', 'RDP: require SSL (TLS) security layer', 2,
                  _RDP + 'Clients that cannot negotiate TLS can no longer connect.'),
    LibraryAction('REM-18.10.57.3.9.4', '18.10.57.3.9.4', 'RDP: require Network Level Authentication', 1,
                  _RDP + 'RDP clients must authenticate before a session is created; very old clients cannot connect.'),
    LibraryAction('REM-18.10.57.3.9.5', '18.10.57.3.9.5', 'RDP: High client connection encryption', 3,
                  _RDP + 'Clients that cannot use 128-bit encryption can no longer connect.'),
)})


def actions_for(control_id):
    return [a for a in LIBRARY.values() if a.control_id == control_id]
