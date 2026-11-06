"""Discover once, authenticate once, verify identity, then bind an opaque backend handle."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from uuid import uuid4

from .contracts import Capabilities, ConnectionResult
from .discovery import discover_transport
from .identity import VerifiedIdentity
from .session import CredentialVault


class PendingChangeElsewhere(ValueError):
    """Another VM holds a running or unresolved change: connecting elsewhere would lose track of it."""


@dataclass
class VerifiedSession:
    connection_session_id: str
    identity: VerifiedIdentity
    target_id: str
    registration_epoch: str
    username: str
    host: str
    port: int
    channel: object = field(repr=False)
    target: object = field(default=None, repr=False)
    active: bool = True
    # Host UTC time taken before the login began: a commit-confirm needs a login that started after the change.
    connected_at: str = ''


def verify_windows_facts(found):
    if (found.get('build_number') != '20348' or 'Windows Server 2022' not in found.get('os_caption', '')
            or found.get('part_of_domain') is not False or type(found.get('domain_role')) is not int
            or found['domain_role'] != 2 or found.get('is_admin') is not True):
        raise ValueError('Supported standalone Windows Server 2022 administrator identity required')
    return VerifiedIdentity('windows', found['hostname'], found['machine_uuid'].lower(), 'Server 2022', 'winrm')


def _ssh(request, credentials, known):
    from backends.ubuntu.ssh_channel import SshChannel
    return SshChannel.connect(request, credentials, known)


def _backend(session, ledger):
    from .config import PATHS
    if session.identity.platform == 'windows':
        from backends.windows.adapter import WindowsBackend
        return WindowsBackend(PATHS.windows_imports, session=session, ledger=ledger)
    from backends.ubuntu.adapter import UbuntuBackend
    from .config import UBUNTU_FIREWALL_REGISTRATIONS
    return UbuntuBackend(PATHS.ubuntu_imports, session=session, ledger=ledger,
                         registered_firewall_manager=UBUNTU_FIREWALL_REGISTRATIONS.get(session.identity.machine_identity))


class ConnectionService:
    def __init__(self, ledger, vault=None, *, ssh_factory=_ssh, backend_factory=None,
                 discover=discover_transport, windows_scanner_factory=None):
        self.ledger, self.vault = ledger, vault or CredentialVault()
        self._ssh_factory, self._discover = ssh_factory, discover
        self._backend_factory = backend_factory or (lambda session: _backend(session, ledger))
        self._windows_scanner_factory = windows_scanner_factory
        self._sessions, self._backends = {}, {}

    def connect(self, request):
        channel = None
        credentials = self.vault.take(request.credential_ref)
        try:
            if self._sessions:
                raise ValueError('Disconnect the active VM before connecting another target')
            started = datetime.now(timezone.utc).isoformat()
            discovery = self._discover(request.endpoint)
            if discovery.transport is None:
                return ConnectionResult('disconnected', diagnostic_code=discovery.code, detail=discovery.detail)
            target = None
            if discovery.transport == 'ssh':
                channel = self._ssh_factory(request, credentials, self.ledger.known_fingerprint(request.endpoint))
                identity = channel.verify_identity(request)
                if identity.platform != 'ubuntu' or identity.os_version != '22.04' or identity.transport != 'ssh':
                    raise ValueError('Unsupported authenticated platform/transport')
            else:
                from hardening.winrm_channel import LiveScanner, WinRmTarget
                if credentials.key_path:
                    raise ValueError('Selected SSH key cannot be used with WinRM')
                if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', request.expected_machine_identity):
                    raise ValueError('Windows machine identity must be a UUID')
                target = WinRmTarget(request.expected_hostname, request.expected_machine_identity,
                                     credentials.username, credentials.password, request.endpoint.host, request.endpoint.port)
                scanner = (self._windows_scanner_factory or LiveScanner)(None, target)
                # Original identity verifies hostname, UUID and administrator; integration additionally checks OS.
                identity = verify_windows_facts(scanner.identity())
            if (identity.hostname.casefold() != request.expected_hostname.casefold()
                    or identity.machine_identity.lower() != request.expected_machine_identity.lower()):
                raise ValueError('Authenticated target mismatch')
            target_id, epoch = self.ledger.register(identity, request.endpoint)
            if self.ledger.owned_elsewhere(target_id, epoch):
                raise PendingChangeElsewhere('pending change elsewhere')
            session = VerifiedSession(uuid4().hex, identity, target_id, epoch, credentials.username,
                                      request.endpoint.host, request.endpoint.port, channel, target, connected_at=started)
            backend = self._backend_factory(session)
            capabilities = backend.capabilities(session.connection_session_id) if hasattr(backend, 'capabilities') else Capabilities()
            self._sessions[session.connection_session_id] = session
            self._backends[session.connection_session_id] = backend
            return ConnectionResult('connected', session.connection_session_id, identity.platform, identity.os_version,
                                     identity.transport, target_id, capabilities, 'verified', 'Authenticated OS and machine identity verified.')
        except Exception as exc:
            if channel is not None:
                channel.close()
            # Never echo authentication/library exceptions: they may include credentials or remote text.
            code = 'verification_failed' if isinstance(exc, ValueError) else 'connection_failed'
            detail = ('Identity or trust verification failed; check the independently verified fingerprint, '
                      'expected hostname, machine identity and supported OS. Credentials were cleared.'
                      if code == 'verification_failed' else
                      'Connection failed; check endpoint, trust and selected authentication. Credentials were cleared.')
            if isinstance(exc, PendingChangeElsewhere):
                code = 'pending_change_elsewhere'
                detail = ('Another VM has a running or unresolved change. Reconnect to that VM and settle it '
                          '(check its status or confirm it) first. Credentials were cleared.')
            return ConnectionResult('disconnected', diagnostic_code=code, detail=detail)
        finally:
            credentials = None

    def session(self, connection_session_id):
        session = self._sessions.get(connection_session_id)
        if session is None or not session.active:
            raise ValueError('Connection is absent or expired; reconnect and verify identity')
        return session

    def backend_for(self, connection_session_id):
        self.session(connection_session_id)
        return self._backends[connection_session_id]

    def disconnect(self, connection_session_id):
        # Always allowed: closing the channel changes nothing on the VM, and a supervised change keeps running
        # under systemd and its rollback watchdog. Switching to another VM is refused at connect while this one
        # holds a running or unresolved change; reconnecting to the same VM is how a commit-confirm is proven.
        session = self.session(connection_session_id)
        session.active = False
        if session.channel is not None:
            session.channel.close()
        session.channel = session.target = None
        self._backends.pop(connection_session_id, None)
        self._sessions.pop(connection_session_id, None)
        self.vault.clear()

    def resume_workflow(self, connection_session_id, workflow_session_id):
        session = self.session(connection_session_id)
        return self.ledger.resume(workflow_session_id, session.identity.platform, session.target_id, session.registration_epoch)
