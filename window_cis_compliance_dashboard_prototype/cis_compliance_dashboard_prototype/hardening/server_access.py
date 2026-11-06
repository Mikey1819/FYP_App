"""Server access helper offered for download on the Servers page (scripts/server_access/).

Every server is added by pairing, so every server needs the helper. It runs on the server, not here: it shows the
pairing code, lets only paired laptops reach WinRM, and reverts that afterwards.
The bundle is built byte-for-byte the same every time, so its published SHA-256 stays checkable.
"""
from io import BytesIO
import hashlib
from pathlib import Path
import zipfile

SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts' / 'server_access'
FILES = ('FYP-ServerAccess.ps1', 'Start-ServerAccess.cmd', 'FYP-ServerAccess-README.txt')


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
