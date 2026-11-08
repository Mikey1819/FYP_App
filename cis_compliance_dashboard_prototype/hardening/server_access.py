"""Server helpers offered for download on the Servers page (scripts/server_access/).

Every server is added by pairing, so every server needs its helper. It runs on the server, not here, and shows the
pairing code:
  - Windows Server 2022: FYP-ServerAccess.ps1 (in a .zip). It also lets only paired laptops reach WinRM, and reverts
    that afterwards.
  - Ubuntu 22.04: fyp-pair-ubuntu.py. SSH is already reachable, so it only answers the pairing question (with the SSH
    host key fingerprint) and removes its temporary UFW rule when it stops.
The Windows bundle is built byte-for-byte the same every time, so its published SHA-256 stays checkable.
"""
from io import BytesIO
import hashlib
from pathlib import Path
import zipfile

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts' / 'server_access'
FILES = ('FYP-ServerAccess.ps1', 'Start-ServerAccess.cmd', 'FYP-ServerAccess-README.txt')
UBUNTU_HELPER = SCRIPTS / 'fyp-pair-ubuntu.py'


def helper_sha256():
    """SHA-256 of the PowerShell helper, for Get-FileHash on the server."""
    return hashlib.sha256((SCRIPTS / FILES[0]).read_bytes()).hexdigest()


def helper_bundle():
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name in FILES:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))  # Fixed time: identical bytes each build.
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, (SCRIPTS / name).read_bytes())
    return buffer.getvalue()


def ubuntu_helper():
    """The Ubuntu pairing helper, exactly as stored, with Unix line endings (it runs under python3 on the server)."""
    return UBUNTU_HELPER.read_bytes().replace(b'\r\n', b'\n')


def ubuntu_helper_sha256():
    """SHA-256 of the downloaded Ubuntu helper, for sha256sum on the server."""
    return hashlib.sha256(ubuntu_helper()).hexdigest()
