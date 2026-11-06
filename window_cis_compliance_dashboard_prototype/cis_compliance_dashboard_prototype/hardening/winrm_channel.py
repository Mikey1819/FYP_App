"""Scanner Agent's own channel to a saved server over PowerShell Remoting.

The agent invokes collection itself; nobody carries scripts or evidence files.
Only repository-registered scripts are sent, with typed parameters (never
string-built commands or model text). Credentials stay in the caller's memory.
"""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import ClassVar
from uuid import UUID, uuid4

from .domain import EvidenceMode
from .evidence_import import load_evidence

COLLECTOR = Path(__file__).resolve().parents[2] / 'scripts' / 'vm' / 'Collect-Server2022Evidence.ps1'

# WinRM over HTTP. Servers are found by pairing (pairing_client.py), which also gives their address and port.
DEFAULT_PORT = 5985
IDENTITY_SCRIPT = r'''
$os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 15
$cs = Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 15
$product = Get-CimInstance Win32_ComputerSystemProduct -OperationTimeoutSec 15
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
[ordered]@{
    hostname = [string]$cs.Name; machine_uuid = ([guid]::Parse($product.UUID)).ToString()
    os_caption = [string]$os.Caption; build_number = [string]$os.BuildNumber
    part_of_domain = [bool]$cs.PartOfDomain; domain_role = [int]$cs.DomainRole
    is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} | ConvertTo-Json -Compress
'''


class ChannelError(Exception):
    """A classified channel failure; `state` is safe to show and to record."""

    def __init__(self, state, detail):
        super().__init__(state + ': ' + detail)
        self.state, self.detail = state, detail


def _check_login(login, names):
    for name in names:
        if type(getattr(login, name)) is not str or not getattr(login, name).strip():
            raise ValueError('WinRM connection requires ' + name.replace('_', ' '))
    if type(login.port) is not int or not 1 <= login.port <= 65535:
        raise ValueError('Invalid WinRM port')


@dataclass(frozen=True)
class WinRmLogin:
    """An address and account before the server behind it is known: used only to ask who answers there."""
    username: str
    password: str = field(repr=False)
    host: str = ''
    port: int = DEFAULT_PORT

    def __post_init__(self):
        _check_login(self, ('username', 'password', 'host'))


@dataclass(frozen=True)
class WinRmTarget:
    """A known server: every call checks that the machine answering is this hostname and UUID."""
    # Which workspace pages open once it is connected (app.py). A future Ubuntu target will say 'ubuntu'.
    workspace: ClassVar[str] = 'windows'
    hostname: str
    machine_uuid: str
    username: str
    password: str = field(repr=False)
    host: str = ''
    port: int = DEFAULT_PORT

    def __post_init__(self):
        _check_login(self, ('hostname', 'machine_uuid', 'username', 'password', 'host'))


class PsrpSession:
    """Runs one fixed script per call in a fresh NTLM-encrypted runspace."""

    def __init__(self, target):
        self.target = target

    def run(self, script, parameters=None):
        from pypsrp.powershell import PowerShell, RunspacePool
        from pypsrp.wsman import WSMan
        wsman = WSMan(self.target.host, port=self.target.port, username=self.target.username,
                      password=self.target.password, ssl=False, auth='ntlm', encryption='always',
                      connection_timeout=15, operation_timeout=20, read_timeout=30)
        with wsman, RunspacePool(wsman) as pool:
            shell = PowerShell(pool)
            shell.add_script(script)
            for name, value in (parameters or {}).items():
                shell.add_parameter(name, value)
            output = shell.invoke()
            return [str(item) for item in output], shell.had_errors, [str(e) for e in shell.streams.error]


def _classify(exc):
    name = type(exc).__name__
    text = str(exc)
    if name == 'AuthenticationError' or '401' in text:
        return ChannelError('auth_failed', 'The server rejected the username or password.')
    if name in ('ConnectionError', 'ConnectTimeout', 'ReadTimeout', 'Timeout') or 'refused' in text.lower():
        return ChannelError('unreachable', 'No WinRM listener answered. Check the server is on, the address and '
                            'port are right, and the server access helper has allowed this laptop.')
    return ChannelError('channel_error', name + ' while talking to the server.')


def _run_script(login, session_factory, script, parameters=None):
    # Looked up at call time, so tests can stand in for the remoting library.
    try:
        return (session_factory or PsrpSession)(login).run(script, parameters)
    except ChannelError:
        raise
    except Exception as exc:  # Network/auth libraries raise many unrelated types.
        raise _classify(exc) from None


def _identity(output, had_errors):
    """The identity probe's answer, type-checked; it is data from the server, not trusted beyond its shape."""
    if had_errors or len(output) != 1:
        raise ChannelError('channel_error', 'Identity probe failed on the server.')
    try:
        found = json.loads(output[0])
    except json.JSONDecodeError:
        raise ChannelError('channel_error', 'Identity probe returned malformed output.') from None
    texts = ('hostname', 'machine_uuid', 'os_caption', 'build_number')
    if (type(found) is not dict or any(type(found.get(k)) is not str or not found[k].strip() for k in texts)
            or len(found['hostname']) > 63 or len(found['os_caption']) > 200 or type(found.get('is_admin')) is not bool
            or type(found.get('part_of_domain')) is not bool or type(found.get('domain_role')) is not int):
        raise ChannelError('channel_error', 'Identity probe returned unexpected fields.')
    try:
        found['machine_uuid'] = str(UUID(found['machine_uuid']))
    except ValueError:
        raise ChannelError('channel_error', 'Identity probe returned an invalid machine UUID.') from None
    if found['is_admin'] is not True:
        raise ChannelError('not_admin', 'Connected account lacks an administrator token; '
                           'use the built-in Administrator account.')
    return found


def supported(found):
    """The assessed scope: a stand-alone Windows Server 2022 (the collector checks the same before reading)."""
    return ('Windows Server 2022' in found['os_caption'] and found['build_number'] == '20348'
            and found['part_of_domain'] is False and found['domain_role'] == 2)


def probe_identity(login, *, session_factory=None):
    """Who answers at this address? Used when a server is added; nothing is collected or changed. Raises
    ChannelError, including `unsupported_target` for anything other than a stand-alone Server 2022."""
    output, had_errors, _ = _run_script(login, session_factory, IDENTITY_SCRIPT)
    found = _identity(output, had_errors)
    if not supported(found):
        raise ChannelError('unsupported_target', 'This program assesses stand-alone Windows Server 2022 only. '
                           'The server reports: ' + found['os_caption'] + (', joined to a domain'
                           if found['part_of_domain'] else '') + '.')
    return found


class LiveScanner:
    """Collection tool owned by the Scanner Agent; creates a new assessed run per scan."""
    channel = 'winrm'

    def __init__(self, runtime, target, *, session_factory=None):
        self.runtime, self.target = runtime, target
        self.session_factory = session_factory

    def _run(self, script, parameters=None):
        return _run_script(self.target, self.session_factory, script, parameters)

    def _same_target(self, hostname, machine_uuid):
        if (hostname.casefold() != self.target.hostname.casefold()
                or machine_uuid.casefold() != self.target.machine_uuid.casefold()):
            raise ChannelError('wrong_target', 'Requested target differs from the connected server.')

    def identity(self):
        found = _identity(*self._run(IDENTITY_SCRIPT)[:2])
        if (found['hostname'].casefold() != self.target.hostname.casefold()
                or found['machine_uuid'].casefold() != self.target.machine_uuid.casefold()):
            raise ChannelError('wrong_target', 'A different machine answered at ' + self.target.host + ':'
                               + str(self.target.port) + ' (' + found['hostname'] + '), not the saved server.')
        return found

    def worker_status(self, hostname, machine_uuid):
        """Read-only readiness check; never evidence of any setting."""
        try:
            self._same_target(hostname, machine_uuid)
            found = self.identity()
        except ChannelError as exc:
            return dict(state=exc.state, detail=exc.detail, channel=self.channel)
        return dict(state='ready', channel=self.channel, detail='Connected over WinRM to '
                    + found['hostname'] + ' (' + found['os_caption'] + ', build ' + found['build_number'] + ').')

    @staticmethod
    def collector_text():
        return COLLECTOR.read_text(encoding='utf-8-sig')

    def _collect(self):
        self.identity()
        output, had_errors, errors = self._run(self.collector_text(), {'ExpectedComputerName': self.target.hostname,
                                                                       'EmitJson': True})
        if had_errors or len(output) != 1:
            detail = (errors[0] if errors else 'Collector returned no evidence.')[:300]
            raise ChannelError('collection_failed', detail)
        return output[0]

    def observe(self):
        """Read-only collection that is evaluated but not stored (Remediation Agent precheck)."""
        try:
            return load_evidence(self._collect().encode('utf-8'), expected_hostname=self.target.hostname,
                                 expected_machine_uuid=self.target.machine_uuid, mode=EvidenceMode.LIVE)
        except ValueError as exc:
            raise ChannelError('collection_failed', 'Evidence failed validation: ' + str(exc)[:200]) from None

    def request(self, hostname, machine_uuid, *, origin_run_id=None):
        """Collect now and return a new assessed framework run. Raises ChannelError."""
        self._same_target(hostname, machine_uuid)
        collector_sha256 = hashlib.sha256(COLLECTOR.read_bytes()).hexdigest()
        output = [self._collect()]
        request_id = uuid4().hex
        run = self.runtime.start(output[0].encode('utf-8'), expected_hostname=self.target.hostname,
                                 expected_machine_uuid=self.target.machine_uuid, collection_request_id=request_id,
                                 mode=EvidenceMode.LIVE)
        return dict(request_id=request_id, state='assessment_ready', channel=self.channel,
                    framework_run_id=run.run_id, evidence_sha256=run.evidence_sha256,
                    target_id=run.target_id, collector_sha256=collector_sha256, origin_run_id=origin_run_id)
