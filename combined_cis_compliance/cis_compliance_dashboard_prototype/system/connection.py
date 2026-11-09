"""Discover once, authenticate once, verify identity, then bind an opaque backend handle."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from uuid import uuid4

from .contracts import Capabilities, ConnectionResult, VerificationRefused
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


# Win32_ComputerSystem.DomainRole, in words.
DOMAIN_ROLES = {0: 'a stand-alone workstation', 1: 'a member workstation', 2: 'a stand-alone server',
                3: 'a member server of a domain', 4: 'a backup domain controller', 5: 'a primary domain controller'}
STAND_ALONE_ONLY = 'Pair a stand-alone Windows Server 2022 (not joined to a domain) instead.'


def verify_windows_facts(found):
    if found.get('build_number') != '20348' or 'Windows Server 2022' not in found.get('os_caption', ''):
        raise VerificationRefused(f"The server reports {str(found.get('os_caption'))[:120]} (build "
                                  f"{str(found.get('build_number'))[:12]}); this program assesses Windows Server 2022 "
                                  '(build 20348) only.', STAND_ALONE_ONLY)
    if found.get('part_of_domain') is not False:
        raise VerificationRefused('The server is joined to a domain; this program assesses stand-alone servers only '
                                  '(the CIS Stand-alone benchmark).', STAND_ALONE_ONLY)
    if type(found.get('domain_role')) is not int or found['domain_role'] != 2:
        role = DOMAIN_ROLES.get(found.get('domain_role'), 'not reported')
        raise VerificationRefused(f'The server\'s role is {role}; this program assesses a stand-alone server only.',
                                  STAND_ALONE_ONLY)
    if found.get('is_admin') is not True:
        raise VerificationRefused('The account has no administrator token on the server.',
                                  'Use the built-in Administrator account.')
    return VerifiedIdentity('windows', found['hostname'], found['machine_uuid'].lower(), 'Server 2022', 'winrm')


def _ssh(request, credentials, known):
    from backends.ubuntu.ssh_channel import SshChannel
    return SshChannel.connect(request, credentials, known)


def _backend(session, ledger):
    from .config import PATHS
    if session.identity.platform == 'windows':
        from backends.windows.adapter import WindowsBackend
        # Live Windows dispatch: the plan opened it once the host coordination ledger (task 7) passed. Each fix still
        # needs the administrator's approval and the explicit confirmation, under the ledger's at-most-once claim.
        return WindowsBackend(PATHS.windows_imports, session=session, ledger=ledger, allow_mutation=True)
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

    def connect(self, request, *, paired=False):
        """`paired`: the endpoint and expected identity come from a pairing answer proven by its code, so the same
        machine may have moved to a new address (ledger.register readdress)."""
        channel = None
        credentials = self.vault.take(request.credential_ref)
        try:
            if self._sessions:
                raise VerificationRefused('Another server is connected in this session.',
                                          'Disconnect it first, then connect this one.')
            started = datetime.now(timezone.utc).isoformat()
            discovery = self._discover(request.endpoint)
            if discovery.transport is None:
                return ConnectionResult('disconnected', diagnostic_code=discovery.code, detail=discovery.detail)
            target = None
            if discovery.transport == 'ssh':
                channel = self._ssh_factory(request, credentials, self.ledger.known_fingerprint(request.endpoint))
                identity = channel.verify_identity(request)
                if identity.platform != 'ubuntu' or identity.os_version != '22.04' or identity.transport != 'ssh':
                    raise VerificationRefused(f'After login the server reports {identity.platform[:20]} '
                                              f'{identity.os_version[:20]}; this program supports Ubuntu 22.04 over SSH '
                                              'and Windows Server 2022 over WinRM only.')
            else:
                from hardening.winrm_channel import LiveScanner, WinRmTarget
                if credentials.key_path:
                    raise VerificationRefused('An SSH key file cannot log in to Windows (WinRM).',
                                              'Log in with the account and its password.')
                if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', request.expected_machine_identity):
                    raise VerificationRefused('The saved machine ID of this Windows server is not a UUID.',
                                              'Start pairing on the server and pair it again.')
                target = WinRmTarget(request.expected_hostname, request.expected_machine_identity,
                                     credentials.username, credentials.password, request.endpoint.host, request.endpoint.port)
                scanner = (self._windows_scanner_factory or LiveScanner)(None, target)
                # Original identity verifies hostname, UUID and administrator; integration additionally checks OS.
                identity = verify_windows_facts(scanner.identity())
            if (identity.hostname.casefold() != request.expected_hostname.casefold()
                    or identity.machine_identity.lower() != request.expected_machine_identity.lower()):
                raise VerificationRefused(
                    f'The machine that accepted the login is {identity.hostname[:63]} (ID {identity.machine_identity}),'
                    f' not {request.expected_hostname[:63]} (ID {request.expected_machine_identity[:64]}), the one '
                    'that answered the pairing code or was saved.')
            target_id, epoch = self.ledger.register(identity, request.endpoint, readdress=paired)
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
            detail = ('Identity or trust verification failed: the server that accepted the login is not the one '
                      'that was paired (hostname, machine identity or SSH host key differ), or it is not a supported '
                      'system. Pair it again with a new code. Credentials were cleared.'
                      if code == 'verification_failed' else
                      'Connection failed; check endpoint, trust and selected authentication. Credentials were cleared.')
            remedy = ''
            if isinstance(exc, VerificationRefused):  # One named check refused it: say which, in its own words.
                detail, remedy = exc.detail + ' Nothing was saved. Credentials were cleared.', exc.remedy
            state = getattr(exc, 'state', None)  # hardening.winrm_channel.ChannelError: a fixed failure category.
            if state in ('wrong_target', 'unsupported_target', 'not_admin'):
                code = 'verification_failed'
                if state in ('wrong_target', 'unsupported_target'):  # Written by the channel from checked facts.
                    detail = exc.detail + ' Nothing was saved. Credentials were cleared.'
                if state == 'not_admin':
                    detail = ('The account has no administrator token on the server; use the built-in Administrator '
                              'account. Credentials were cleared.')
            elif state == 'auth_failed':
                code, detail = 'auth_failed', 'The server rejected the username or password. Credentials were cleared.'
            elif state in ('unreachable', 'slow_reply'):  # Which network failure, in the channel's fixed words.
                code, detail = state, exc.detail + ' Credentials were cleared.'
            # SSH (paramiko) failures, recognised by class name so this layer does not import the SSH library.
            elif 'AuthenticationException' in {c.__name__ for c in type(exc).__mro__}:
                code, detail = 'auth_failed', 'The server rejected the username or password. Credentials were cleared.'
            elif isinstance(exc, (OSError, TimeoutError)):
                code, detail = 'unreachable', ('Nothing answered at the paired address and port. Credentials were '
                                               'cleared.')
            if isinstance(exc, PendingChangeElsewhere):
                code = 'pending_change_elsewhere'
                detail = ('Another server has a running or unresolved change. Connect to that server and settle it '
                          '(check its status or confirm it) first. Credentials were cleared.')
            return ConnectionResult('disconnected', diagnostic_code=code, detail=detail, remedy=remedy)
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
