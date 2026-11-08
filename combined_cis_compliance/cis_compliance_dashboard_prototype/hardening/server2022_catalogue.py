"""The assessed CIS controls: CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0, Level 1.

One catalogue of 32 controls, each with its rule, benchmark pages and the fixed place on the server its
value is read from. The collector (scripts/vm/Collect-Server2022Evidence.ps1) reports exactly these.
"""

from .domain import Control, Operator, Rule

BENCHMARK = "CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0"
# Fingerprint of the one reviewed PDF file (catalogue-level provenance, see docs/design/BENCHMARK_MAPPING.md).
# Evidence files carry it so the importer can reject evidence made for another benchmark's catalogue.
BENCHMARK_SHA256 = "474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d"
PROFILE = "Level 1 - Member Server"  # Exact label in the Stand-alone PDF, printed p28.

# The evidence format the collector writes. These identifiers are stored in every saved scan, so they stay fixed.
SCHEMA_VERSION = 5
COLLECTOR_ID = "server2022-readonly-v5"
CATALOGUE_ID = "cis-server2022-standalone-2.0.0-full1"


def _control(identifier, title, area, rule, pages):
    # Firewall (9.x) and Remote Desktop (18.x) controls are Group Policy values under
    # HKLM\SOFTWARE\Policies: "Not configured" fails them (decision D5). Tests check this
    # matches the registered evidence sources.
    return Control(identifier, title, area, rule, CATALOGUE_ID, PROFILE,
                   f"{BENCHMARK}, section {identifier}, pp. {pages}", True,
                   not_configured_fails=identifier.startswith(("9.", "18.")))


_ACCOUNT, _LOCAL = "Account Policies", "Local Security Options"
_FIREWALL, _AUDIT, _RDP = "Windows Defender Firewall", "Advanced Audit Policy", "Remote Desktop Services"
# Audit policy values are flags: 1 = Success, 2 = Failure.
SUCCESS, FAILURE = 1, 2

CATALOGUE = (
    _control("1.1.1", "Enforce password history", _ACCOUNT, Rule(Operator.AT_LEAST, 24), "31-33"),
    _control("1.1.2", "Maximum password age (days)", _ACCOUNT, Rule(Operator.BETWEEN, (1, 365)), "34-35"),
    _control("1.1.3", "Minimum password age (days)", _ACCOUNT, Rule(Operator.AT_LEAST, 1), "36-37"),
    _control("1.1.4", "Minimum password length", _ACCOUNT, Rule(Operator.AT_LEAST, 14), "38-39"),
    _control("1.1.5", "Password complexity enabled", _ACCOUNT, Rule(Operator.EQUALS, 1), "41-43"),
    _control("1.1.7", "Reversible password encryption enabled", _ACCOUNT, Rule(Operator.EQUALS, 0), "46-47"),
    _control("1.2.1", "Account lockout duration (minutes)", _ACCOUNT, Rule(Operator.AT_LEAST, 15), "49-50"),
    _control("1.2.2", "Account lockout threshold", _ACCOUNT, Rule(Operator.BETWEEN, (1, 5)), "51-52"),
    _control("1.2.4", "Reset lockout counter after (minutes)", _ACCOUNT, Rule(Operator.AT_LEAST, 15), "55-56"),
    _control("2.3.1.1", "Guest account enabled", _LOCAL, Rule(Operator.EQUALS, False), "132-133"),
    _control("2.3.1.2", "Restrict blank local passwords to console logon", _LOCAL, Rule(Operator.EQUALS, 1), "134-135"),
    _control("2.3.10.1", "Anonymous SID/name translation enabled", _LOCAL, Rule(Operator.EQUALS, 0), "179-180"),
    _control("2.3.10.2", "Block anonymous enumeration of SAM accounts", _LOCAL, Rule(Operator.EQUALS, 1), "181-182"),
    _control("2.3.10.3", "Block anonymous enumeration of SAM accounts and shares", _LOCAL,
             Rule(Operator.EQUALS, 1), "183-184"),
    _control("9.2.1", "Private firewall policy EnableFirewall", _FIREWALL, Rule(Operator.EQUALS, 1), "260-261"),
    _control("9.2.2", "Private firewall policy inbound connections: Block", _FIREWALL, Rule(Operator.EQUALS, 1), "262-263"),
    _control("9.2.6", "Private firewall policy log dropped packets", _FIREWALL, Rule(Operator.EQUALS, 1), "270-271"),
    _control("9.2.7", "Private firewall policy log successful connections", _FIREWALL, Rule(Operator.EQUALS, 1), "272-274"),
    _control("9.3.1", "Public firewall policy EnableFirewall", _FIREWALL, Rule(Operator.EQUALS, 1), "275-276"),
    _control("9.3.2", "Public firewall policy inbound connections: Block", _FIREWALL, Rule(Operator.EQUALS, 1), "277-278"),
    _control("9.3.6", "Public firewall policy log dropped packets", _FIREWALL, Rule(Operator.EQUALS, 1), "285-286"),
    _control("9.3.7", "Public firewall policy log successful connections", _FIREWALL, Rule(Operator.EQUALS, 1), "287-288"),
    _control("17.1.1", "Audit Credential Validation: Success and Failure", _AUDIT,
             Rule(Operator.HAS_FLAGS, SUCCESS | FAILURE), "291-293"),
    _control("17.2.2", "Audit Security Group Management: include Success", _AUDIT,
             Rule(Operator.HAS_FLAGS, SUCCESS), "296-297"),
    _control("17.2.3", "Audit User Account Management: Success and Failure", _AUDIT,
             Rule(Operator.HAS_FLAGS, SUCCESS | FAILURE), "298-299"),
    _control("17.5.1", "Audit Account Lockout: include Failure", _AUDIT, Rule(Operator.HAS_FLAGS, FAILURE), "306-307"),
    _control("17.5.4", "Audit Logon: Success and Failure", _AUDIT, Rule(Operator.HAS_FLAGS, SUCCESS | FAILURE), "312-313"),
    _control("18.10.57.2.2", "Do not allow RDP passwords to be saved", _RDP, Rule(Operator.EQUALS, 1), "705-706"),
    _control("18.10.57.3.9.1", "Always prompt for password upon RDP connection", _RDP, Rule(Operator.EQUALS, 1), "727-728"),
    _control("18.10.57.3.9.3", "RDP security layer: SSL", _RDP, Rule(Operator.EQUALS, 2), "731-732"),
    _control("18.10.57.3.9.4", "NLA policy UserAuthentication", _RDP, Rule(Operator.EQUALS, 1), "733-734"),
    _control("18.10.57.3.9.5", "RDP client connection encryption level: High", _RDP, Rule(Operator.EQUALS, 3), "735-736"),
)

_SECEDIT = "secedit-export:System Access/"
_LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
_FW = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
_TS = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# Audit subcategory GUIDs exactly as printed in each recommendation's auditpol audit step.
AUDIT_GUIDS = {"17.1.1": "0cce923f-69ae-11d9-bed3-505054503030", "17.2.2": "0cce9237-69ae-11d9-bed3-505054503030",
               "17.2.3": "0cce9235-69ae-11d9-bed3-505054503030", "17.5.1": "0cce9217-69ae-11d9-bed3-505054503030",
               "17.5.4": "0cce9215-69ae-11d9-bed3-505054503030"}

# Where each value is read from on the server. Fixed source names are part of the evidence format,
# never executable instructions.
SOURCES = {
    "1.1.1": _SECEDIT + "PasswordHistorySize",
    "1.1.2": _SECEDIT + "MaximumPasswordAge",
    "1.1.3": _SECEDIT + "MinimumPasswordAge",
    "1.1.4": _SECEDIT + "MinimumPasswordLength",
    "1.1.5": _SECEDIT + "PasswordComplexity",
    "1.1.7": _SECEDIT + "ClearTextPassword",
    "1.2.1": _SECEDIT + "LockoutDuration",
    "1.2.2": _SECEDIT + "LockoutBadCount",
    "1.2.4": _SECEDIT + "ResetLockoutCount",
    "2.3.1.1": "Win32_UserAccount:LocalAccount=True,SID-RID=501/Disabled",
    "2.3.1.2": _LSA + ":LimitBlankPasswordUse",
    "2.3.10.1": _SECEDIT + "LSAAnonymousNameLookup",
    "2.3.10.2": _LSA + ":RestrictAnonymousSAM",
    "2.3.10.3": _LSA + ":RestrictAnonymous",
    "9.2.1": _FW + r"\PrivateProfile:EnableFirewall",
    "9.2.2": _FW + r"\PrivateProfile:DefaultInboundAction",
    "9.2.6": _FW + r"\PrivateProfile\Logging:LogDroppedPackets",
    "9.2.7": _FW + r"\PrivateProfile\Logging:LogSuccessfulConnections",
    "9.3.1": _FW + r"\PublicProfile:EnableFirewall",
    "9.3.2": _FW + r"\PublicProfile:DefaultInboundAction",
    "9.3.6": _FW + r"\PublicProfile\Logging:LogDroppedPackets",
    "9.3.7": _FW + r"\PublicProfile\Logging:LogSuccessfulConnections",
    **{cid: "auditpol-backup:{" + guid + "}/Setting Value" for cid, guid in AUDIT_GUIDS.items()},
    "18.10.57.2.2": _TS + ":DisablePasswordSaving",
    "18.10.57.3.9.1": _TS + ":fPromptForPassword",
    "18.10.57.3.9.3": _TS + ":SecurityLayer",
    "18.10.57.3.9.4": _TS + ":UserAuthentication",
    "18.10.57.3.9.5": _TS + ":MinEncryptionLevel",
}
