"""Target-side Windows paths and literal PowerShell command formatting; never executes."""
import hashlib
import json
from pathlib import PureWindowsPath
import re


def workspace_path(value):
    if type(value) is not str or not value or len(value) > 200 or any(ord(c) < 32 for c in value):
        raise ValueError("Enter an absolute local Windows working directory for this VM")
    path = PureWindowsPath(value)
    if not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive):
        raise ValueError("Use a local drive path inside the VM, such as D:\\Lab Workspace")
    for part in path.parts[1:]:
        if (part in (".", "..") or part.endswith((" ", ".")) or
                any(c in part for c in '<>:"|?*') or
                re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part)):
            raise ValueError("Invalid Windows directory component")
    return str(path)


def ps_literal(value):
    if type(value) is not str or any(ord(c) < 32 for c in value):
        raise ValueError("Invalid PowerShell argument")
    # Single quotes prevent interpolation of $, backticks and subexpressions.
    return "'" + value.replace("'", "''") + "'"


def runner_command(raw_request, directory):
    directory = PureWindowsPath(workspace_path(directory))
    request = json.loads(raw_request)
    identifier = request["request_id"]
    if type(identifier) is not str or not re.fullmatch(r"[a-f0-9]{32}", identifier):
        raise ValueError("Invalid request ID")
    arguments = {
        "-File": str(directory / "Invoke-ApprovedVmAction.ps1"),
        "-RequestPath": str(directory / (identifier + "-request.json")),
        "-ExpectedRequestSha256": hashlib.sha256(raw_request).hexdigest(),
        "-ExpectedComputerName": request["hostname"],
        "-ExpectedMachineUuid": request["machine_uuid"],
        "-OutputDirectory": str(directory),
    }
    return "powershell.exe -NoProfile -ExecutionPolicy Bypass " + " ".join(
        key + " " + ps_literal(value) for key, value in arguments.items())


def scan_worker_command(hostname, machine_uuid, collector_hash, directory, queue_directory):
    """Format a fixed VM-only worker command; strings are literal, never executed."""
    from .evidence_import import _uuid
    if type(hostname) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,62}', hostname):
        raise ValueError('Supply the exact VM computer name')
    if type(collector_hash) is not str or not re.fullmatch(r'[a-f0-9]{64}', collector_hash):
        raise ValueError('Invalid collector hash')
    arguments = {
        '-File': str(PureWindowsPath(workspace_path(directory)) / 'Watch-ScanRequests.ps1'),
        '-ExchangeDirectory': workspace_path(queue_directory),
        '-ExpectedComputerName': hostname, '-ExpectedMachineUuid': _uuid(machine_uuid),
        '-ExpectedCollectorSha256': collector_hash,
    }
    return ('powershell.exe -NoProfile -ExecutionPolicy Bypass ' + ' '.join(
        key + ' ' + ps_literal(value) for key, value in arguments.items()) + ' -WatchSeconds 900 -MaxRequests 5')
