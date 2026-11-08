"""Which operating system a server runs, worked out from what the server says about itself.

The administrator never has to say which system a server runs. The server access helper reports it in its signed
pairing answer (pairing.py: `os`, `os_name`, `os_version`), and this module sorts that report into one of a few kinds,
with a short plain note for the Servers page.

Two systems are checked: Windows Server 2022 (CIS Microsoft Windows Server 2022 Stand-alone v2.0.0) and Ubuntu
22.04 LTS (CIS Ubuntu Linux 22.04 LTS v2.0.0; built and tested on 22.04.5 LTS). The Ubuntu pairing helper
(scripts/server_access/fyp-pair-ubuntu.py) answers with os = "ubuntu" and os_version = the VERSION_ID line of
/etc/os-release. Every 22.04 point release reports VERSION_ID 22.04 and has the same benchmark, so all are accepted.

The report comes from the network, so it is only used to choose a note. It never decides on its own that a server
may be checked: after login the connection reads the system again and must agree (system/connection.py: a
stand-alone Server 2022 over WinRM, or Ubuntu 22.04 over SSH with the same machine identity and host key).
"""
from dataclasses import dataclass

WINDOWS_SERVER_2022_BUILD = '20348'
UBUNTU_VERSION = '22.04'
# Shown on the Servers page and in every "not supported" note.
SUPPORTED_SYSTEMS = 'Windows Server 2022 (stand-alone) and Ubuntu 22.04.5 LTS'


@dataclass(frozen=True)
class DetectedSystem:
    kind: str        # windows_server_2022 | windows_server | windows_desktop | ubuntu_2204 | ubuntu | other | unknown
    label: str       # A short name for the page, for example "Windows Server 2022" or "Ubuntu 22.04".
    reported: str    # The full name as the server reported it.
    supported: bool  # True only when this program has checks for this system.
    note: str        # One plain sentence for the administrator.


def _build(version):
    """The build number from a Windows version such as 10.0.20348."""
    parts = str(version).split('.')
    return parts[2] if len(parts) >= 3 else ''


def detect(os_id, os_name, os_version):
    """Sort a server's own report of its operating system into a DetectedSystem."""
    os_id, os_name, os_version = str(os_id or '').lower(), str(os_name or '').strip(), str(os_version or '').strip()
    if os_id == 'windows':
        if 'server' not in os_name.lower():
            return DetectedSystem('windows_desktop', 'Windows (desktop)', os_name, False,
                                  'This is a Windows desktop, not a server. Run the helper on the server you want '
                                  'checked.')
        if '2022' in os_name and _build(os_version) == WINDOWS_SERVER_2022_BUILD:
            return DetectedSystem('windows_server_2022', 'Windows Server 2022', os_name, True,
                                  'Supported: this program checks Windows Server 2022 against the CIS Stand-alone '
                                  'benchmark.')
        return DetectedSystem('windows_server', 'Windows Server (not 2022)', os_name, False,
                              'This Windows Server version is not checked. This program supports only '
                              + SUPPORTED_SYSTEMS + '.')
    if os_id == 'ubuntu':
        if os_version == UBUNTU_VERSION:
            return DetectedSystem('ubuntu_2204', 'Ubuntu 22.04 LTS', os_name, True,
                                  'Supported: this program checks Ubuntu 22.04 LTS against the CIS Ubuntu Linux 22.04 '
                                  'LTS benchmark.')
        return DetectedSystem('ubuntu', f'Ubuntu {os_version}'.strip(), os_name, False,
                              'This Ubuntu version is not checked. This program supports only ' + SUPPORTED_SYSTEMS
                              + '.')
    if os_id:
        return DetectedSystem('other', os_name or os_id, os_name, False,
                              'This system is not checked. This program supports only ' + SUPPORTED_SYSTEMS + '.')
    return DetectedSystem('unknown', 'Unknown system', os_name, False,
                          'The server did not say which system it runs, so it cannot be checked.')
