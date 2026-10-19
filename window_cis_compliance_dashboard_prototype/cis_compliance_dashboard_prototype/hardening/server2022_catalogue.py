"""Reviewed five-control subset; never replaces historical demo-v1 rules."""

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
