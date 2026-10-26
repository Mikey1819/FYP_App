"""Versioned reviewed subsets; historical catalogues keep their original rules."""

from dataclasses import replace
from .domain import Control, Operator, Rule

CATALOGUE_ID = "cis-server2022-standalone-2.0.0-preview1"
BENCHMARK_SHA256 = "474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d"
PROFILE = "Level 1 - Member Server"  # Exact label in the Stand-alone PDF, printed p28.
COLLECTOR_ID = "server2022-readonly-v1"


def _control(identifier, title, area, rule, pages):
    return Control(identifier, title, area, rule, CATALOGUE_ID, PROFILE,
                   f"CIS Windows Server 2022 Stand-alone v2.0.0, section {identifier}, "
                   f"printed pages {pages}; SHA256 {BENCHMARK_SHA256}", True)


CATALOGUE = (
    _control("1.1.4", "Minimum password length", "Account Policies",
             Rule(Operator.AT_LEAST, 14), "38-39"),
    _control("1.2.2", "Account lockout threshold", "Account Policies",
             Rule(Operator.BETWEEN, (1, 5)), "51-52"),
    _control("2.3.1.1", "Guest account enabled", "Local Security Options",
             Rule(Operator.EQUALS, False), "132-133"),
    _control("9.3.1", "Public firewall policy EnableFirewall", "Windows Defender Firewall",
             Rule(Operator.EQUALS, 1), "275-276"),
    _control("18.10.57.3.9.4", "NLA policy UserAuthentication", "Remote Desktop Services",
             Rule(Operator.EQUALS, 1), "733-734"),
)

# Fixed source names are part of the export contract, never executable instructions.
SOURCES = {
    "1.1.4": "secedit-export:System Access/MinimumPasswordLength",
    "1.2.2": "secedit-export:System Access/LockoutBadCount",
    "2.3.1.1": "Win32_UserAccount:LocalAccount=True,SID-RID=501/Disabled",
    "9.3.1": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile:EnableFirewall",
    "18.10.57.3.9.4": r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services:UserAuthentication",
}

# Schema 3 extends assessment coverage without reinterpreting v1/v2 snapshots.
EXPANDED_CATALOGUE_ID = "cis-server2022-standalone-2.0.0-account1"
EXPANDED_COLLECTOR_ID = "server2022-readonly-v3"
ACCOUNT_EXTENSIONS = (
    _control("1.1.1", "Enforce password history", "Account Policies",
             Rule(Operator.AT_LEAST, 24), "31-33"),
    _control("1.1.2", "Maximum password age (days)", "Account Policies",
             Rule(Operator.BETWEEN, (1, 365)), "34-35"),
    _control("1.1.3", "Minimum password age (days)", "Account Policies",
             Rule(Operator.AT_LEAST, 1), "36-37"),
    _control("1.1.5", "Password complexity enabled", "Account Policies",
             Rule(Operator.EQUALS, 1), "41-43"),
    _control("1.1.7", "Reversible password encryption enabled", "Account Policies",
             Rule(Operator.EQUALS, 0), "46-47"),
    _control("1.2.1", "Account lockout duration (minutes)", "Account Policies",
             Rule(Operator.AT_LEAST, 15), "49-50"),
    _control("1.2.4", "Reset lockout counter after (minutes)", "Account Policies",
             Rule(Operator.AT_LEAST, 15), "55-56"),
)
EXPANDED_CATALOGUE = tuple(replace(c, catalogue_version=EXPANDED_CATALOGUE_ID)
                           for c in CATALOGUE + ACCOUNT_EXTENSIONS)
EXPANDED_SOURCES = {
    **SOURCES,
    **{identifier: "secedit-export:System Access/" + key for identifier, key in (
        ("1.1.1", "PasswordHistorySize"), ("1.1.2", "MaximumPasswordAge"),
        ("1.1.3", "MinimumPasswordAge"), ("1.1.5", "PasswordComplexity"),
        ("1.1.7", "ClearTextPassword"), ("1.2.1", "LockoutDuration"),
        ("1.2.4", "ResetLockoutCount"),
    )},
}


LOCAL_SECURITY_CATALOGUE_ID = "cis-server2022-standalone-2.0.0-local1"
LOCAL_SECURITY_EXTENSIONS = (
    _control("2.3.1.2", "Restrict blank local passwords to console logon", "Local Security Options",
             Rule(Operator.EQUALS, 1), "134-135"),
    _control("2.3.10.1", "Anonymous SID/name translation enabled", "Local Security Options",
             Rule(Operator.EQUALS, 0), "179-180"),
    _control("2.3.10.2", "Block anonymous enumeration of SAM accounts", "Local Security Options",
             Rule(Operator.EQUALS, 1), "181-182"),
    _control("2.3.10.3", "Block anonymous enumeration of SAM accounts and shares", "Local Security Options",
             Rule(Operator.EQUALS, 1), "183-184"),
)
LATEST_CATALOGUE = tuple(replace(c, catalogue_version=LOCAL_SECURITY_CATALOGUE_ID)
                         for c in EXPANDED_CATALOGUE + LOCAL_SECURITY_EXTENSIONS)
LATEST_SOURCES = {
    **EXPANDED_SOURCES,
    "2.3.1.2": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:LimitBlankPasswordUse",
    "2.3.10.1": "secedit-export:System Access/LSAAnonymousNameLookup",
    "2.3.10.2": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymousSAM",
    "2.3.10.3": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa:RestrictAnonymous",
}


FULL_CATALOGUE_ID = "cis-server2022-standalone-2.0.0-full1"
_FW = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
_TS = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
# Audit subcategory GUIDs exactly as printed in each recommendation's auditpol audit step.
AUDIT_GUIDS = {"17.1.1": "0cce923f-69ae-11d9-bed3-505054503030", "17.2.2": "0cce9237-69ae-11d9-bed3-505054503030",
               "17.2.3": "0cce9235-69ae-11d9-bed3-505054503030", "17.5.1": "0cce9217-69ae-11d9-bed3-505054503030",
               "17.5.4": "0cce9215-69ae-11d9-bed3-505054503030"}
SUCCESS, FAILURE = 1, 2
FULL_EXTENSIONS = (
    _control("9.2.1", "Private firewall policy EnableFirewall", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "260-261"),
    _control("9.2.2", "Private firewall policy inbound connections: Block", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "262-263"),
    _control("9.2.6", "Private firewall policy log dropped packets", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "270-271"),
    _control("9.2.7", "Private firewall policy log successful connections", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "272-274"),
    _control("9.3.2", "Public firewall policy inbound connections: Block", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "277-278"),
    _control("9.3.6", "Public firewall policy log dropped packets", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "285-286"),
    _control("9.3.7", "Public firewall policy log successful connections", "Windows Defender Firewall", Rule(Operator.EQUALS, 1), "287-288"),
    _control("17.1.1", "Audit Credential Validation: Success and Failure", "Advanced Audit Policy",
             Rule(Operator.HAS_FLAGS, SUCCESS | FAILURE), "291-293"),
    _control("17.2.2", "Audit Security Group Management: include Success", "Advanced Audit Policy",
             Rule(Operator.HAS_FLAGS, SUCCESS), "296-297"),
    _control("17.2.3", "Audit User Account Management: Success and Failure", "Advanced Audit Policy",
             Rule(Operator.HAS_FLAGS, SUCCESS | FAILURE), "298-299"),
    _control("17.5.1", "Audit Account Lockout: include Failure", "Advanced Audit Policy",
             Rule(Operator.HAS_FLAGS, FAILURE), "306-307"),
    _control("17.5.4", "Audit Logon: Success and Failure", "Advanced Audit Policy",
             Rule(Operator.HAS_FLAGS, SUCCESS | FAILURE), "312-313"),
    _control("18.10.57.2.2", "Do not allow RDP passwords to be saved", "Remote Desktop Services", Rule(Operator.EQUALS, 1), "705-706"),
    _control("18.10.57.3.9.1", "Always prompt for password upon RDP connection", "Remote Desktop Services", Rule(Operator.EQUALS, 1), "727-728"),
    _control("18.10.57.3.9.3", "RDP security layer: SSL", "Remote Desktop Services", Rule(Operator.EQUALS, 2), "731-732"),
    _control("18.10.57.3.9.5", "RDP client connection encryption level: High", "Remote Desktop Services", Rule(Operator.EQUALS, 3), "735-736"),
)
FULL_CATALOGUE = tuple(replace(c, catalogue_version=FULL_CATALOGUE_ID)
                       for c in LATEST_CATALOGUE + FULL_EXTENSIONS)
FULL_SOURCES = {
    **LATEST_SOURCES,
    "9.2.1": _FW + r"\PrivateProfile:EnableFirewall",
    "9.2.2": _FW + r"\PrivateProfile:DefaultInboundAction",
    "9.2.6": _FW + r"\PrivateProfile\Logging:LogDroppedPackets",
    "9.2.7": _FW + r"\PrivateProfile\Logging:LogSuccessfulConnections",
    "9.3.2": _FW + r"\PublicProfile:DefaultInboundAction",
    "9.3.6": _FW + r"\PublicProfile\Logging:LogDroppedPackets",
    "9.3.7": _FW + r"\PublicProfile\Logging:LogSuccessfulConnections",
    **{cid: "auditpol-backup:{" + guid + "}/Setting Value" for cid, guid in AUDIT_GUIDS.items()},
    "18.10.57.2.2": _TS + ":DisablePasswordSaving",
    "18.10.57.3.9.1": _TS + ":fPromptForPassword",
    "18.10.57.3.9.3": _TS + ":SecurityLayer",
    "18.10.57.3.9.5": _TS + ":MinEncryptionLevel",
}


def evidence_contract(version):
    """Return the exact collector/catalogue contract for a supported schema."""
    if version == 5:
        return ("server2022-readonly-v5", FULL_CATALOGUE_ID, FULL_CATALOGUE, FULL_SOURCES)
    if version == 4:
        return ("server2022-readonly-v4", LOCAL_SECURITY_CATALOGUE_ID,
                LATEST_CATALOGUE, LATEST_SOURCES)
    if version == 3:
        return (EXPANDED_COLLECTOR_ID, EXPANDED_CATALOGUE_ID,
                EXPANDED_CATALOGUE, EXPANDED_SOURCES)
    if version in (1, 2):
        return (COLLECTOR_ID if version == 1 else "server2022-readonly-v2",
                CATALOGUE_ID, CATALOGUE, SOURCES)
    raise ValueError("Unsupported evidence schema")
