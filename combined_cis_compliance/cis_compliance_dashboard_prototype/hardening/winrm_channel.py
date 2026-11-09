"""Scanner Agent's own channel to a saved server over PowerShell Remoting.

The agent invokes collection itself; nobody carries scripts or evidence files.
Only repository-registered scripts are sent, with typed parameters (never
string-built commands or model text). Credentials stay in the caller's memory.
"""
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
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


# The server's clock, read and set over the same checked connection. Scans and fix evidence carry the server's time,
# and evidence more than 5 minutes off this laptop's clock is refused, so the clocks must match before a round starts.
MAX_CLOCK_OFFSET_SECONDS = 30  # As on Ubuntu (backends/ubuntu/adapter.py).
CLOCK_FORMAT = "'yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture"
CLOCK_SCRIPT = "[DateTime]::UtcNow.ToString(" + CLOCK_FORMAT + ")"
SET_CLOCK_SCRIPT = r'''
param([Parameter(Mandatory)][string]$LaptopUtc)
$styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
$wanted = [DateTime]::Parse($LaptopUtc, [Globalization.CultureInfo]::InvariantCulture, $styles)
$before = [DateTime]::UtcNow
Set-Date -Date $wanted.ToLocalTime() | Out-Null
[ordered]@{
    before = $before.ToString(''' + CLOCK_FORMAT + r''')
    after = [DateTime]::UtcNow.ToString(''' + CLOCK_FORMAT + r''')
} | ConvertTo-Json -Compress
'''


def _utc_text(value):
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + f'{value.microsecond // 1000:03d}Z'


def _server_time(text):
    """A time the server reported, checked for its exact shape before it is read."""
    if type(text) is not str or len(text) != 24 or not text.endswith('Z'):
        raise ChannelError('channel_error', 'The server returned its clock in an unexpected form.')
    try:
        return datetime.fromisoformat(text[:-1]).replace(tzinfo=timezone.utc)
    except ValueError:
        raise ChannelError('channel_error', 'The server returned an unreadable clock.') from None


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
    """Runs one fixed script per call in a fresh NTLM-encrypted runspace. Between open() and close() (a batch of
    fixes) the calls share one connection and runspace instead: opening them cost about 4 s per call on the lab
    server, twice per fix. Each shared call runs in its own local scope, so no variable or function carries over."""

    def __init__(self, target):
        self.target = target
        self._wsman = self._pool = None

    def _connect(self):
        from pypsrp.wsman import WSMan
        return WSMan(self.target.host, port=self.target.port, username=self.target.username,
                     password=self.target.password, ssl=False, auth='ntlm', encryption='always',
                     connection_timeout=15, operation_timeout=20, read_timeout=30)

    @staticmethod
    def _invoke(pool, script, parameters, local_scope):
        from pypsrp.powershell import PowerShell
        shell = PowerShell(pool)
        shell.add_script(script, use_local_scope=local_scope)
        for name, value in (parameters or {}).items():
            shell.add_parameter(name, value)
        output = shell.invoke()
        return [str(item) for item in output], shell.had_errors, [str(e) for e in shell.streams.error]

    def open(self):
        from pypsrp.powershell import RunspacePool
        wsman = self._connect()
        wsman.__enter__()
        try:
            pool = RunspacePool(wsman)
            pool.__enter__()
        except BaseException:
            wsman.__exit__(None, None, None)
            raise
        self._wsman, self._pool = wsman, pool

    def close(self):
        pool, wsman, self._pool, self._wsman = self._pool, self._wsman, None, None
        for item in (pool, wsman):
            if item is not None:
                try:
                    item.__exit__(None, None, None)
                except Exception:  # Best effort: the server drops an idle shell by itself.
                    pass

    def run(self, script, parameters=None):
        if self._pool is not None:
            return self._invoke(self._pool, script, parameters, True)
        from pypsrp.powershell import RunspacePool
        wsman = self._connect()
        with wsman, RunspacePool(wsman) as pool:
            return self._invoke(pool, script, parameters, None)


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


def channel_batch(scanner):
    """One connection for a run of calls when the scanner supports it (stand-in scanners need not)."""
    batch = getattr(scanner, 'batch', None)
    return batch() if batch is not None else nullcontext()


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
        self._batches, self._shared = 0, None

    @contextmanager
    def batch(self):
        """Calls inside share one connection (see PsrpSession). Nothing else changes: every call still makes its
        own checks. A call that fails drops the connection, so the next call opens a fresh one, as without a batch."""
        self._batches += 1
        try:
            yield self
        finally:
            self._batches -= 1
            if not self._batches:
                self._drop()

    def _drop(self):
        shared, self._shared = self._shared, None
        if shared is not None and hasattr(shared, 'close'):
            shared.close()

    def _run(self, script, parameters=None):
        if not self._batches:
            return _run_script(self.target, self.session_factory, script, parameters)
        try:
            if self._shared is None:
                session = (self.session_factory or PsrpSession)(self.target)
                if hasattr(session, 'open'):
                    session.open()
                self._shared = session
            return self._shared.run(script, parameters)
        except ChannelError:
            self._drop()
            raise
        except Exception as exc:  # Network/auth libraries raise many unrelated types.
            self._drop()
            raise _classify(exc) from None

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

    def clock_offset(self):
        """How far the server's clock is from this laptop's, in seconds (positive: the server is ahead). Read-only,
        after the identity check; measured against the middle of the call, so the network delay does not count."""
        with self.batch():
            self.identity()
            sent = datetime.now(timezone.utc)
            output, had_errors, _ = self._run(CLOCK_SCRIPT)
            received = datetime.now(timezone.utc)
        if had_errors or len(output) != 1:
            raise ChannelError('channel_error', 'The server did not report its clock.')
        server = _server_time(output[0])
        laptop = sent + (received - sent) / 2
        return dict(server=server, laptop=laptop, offset=(server - laptop).total_seconds())

    def set_clock(self):
        """Set the server's clock to this laptop's time (UTC), after the identity check. Changes only the clock.
        Returns the server's time before and after, as it reported them."""
        with self.batch():
            self.identity()
            output, had_errors, errors = self._run(SET_CLOCK_SCRIPT,
                                                   {'LaptopUtc': _utc_text(datetime.now(timezone.utc))})
        if had_errors or len(output) != 1:
            raise ChannelError('clock_not_set', ((errors[0] if errors else '') or
                                                 'The server did not confirm the new time.')[:300])
        try:
            reported = json.loads(output[0])
        except json.JSONDecodeError:
            raise ChannelError('channel_error', 'The server confirmed the new time in an unexpected form.') from None
        if type(reported) is not dict or set(reported) != {'before', 'after'}:
            raise ChannelError('channel_error', 'The server confirmed the new time in an unexpected form.')
        return dict(before=_server_time(reported['before']), after=_server_time(reported['after']))

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
        with self.batch():  # Identity check and collection over one connection.
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
        try:
            run = self.runtime.start(output[0].encode('utf-8'), expected_hostname=self.target.hostname,
                                     expected_machine_uuid=self.target.machine_uuid, collection_request_id=request_id,
                                     mode=EvidenceMode.LIVE)
        except ValueError as exc:  # A scan the checks refused is a failed collection, not a mistake by the agent.
            if 'in the future' in str(exc):
                raise ChannelError('clock_mismatch', 'The server clock is more than 5 minutes ahead of this laptop, so '
                                   'its scan was refused. Use Sync server clock on the Agentic hardening page, then '
                                   'start again.') from None
            raise ChannelError('evidence_refused', 'The scan failed validation: ' + str(exc)[:200]) from None
        return dict(request_id=request_id, state='assessment_ready', channel=self.channel,
                    framework_run_id=run.run_id, evidence_sha256=run.evidence_sha256,
                    target_id=run.target_id, collector_sha256=collector_sha256, origin_run_id=origin_run_id)
