"""Trusted SSH channel with fixed, bounded read-only operations. No implicit credentials."""
import base64
import hashlib
from pathlib import Path
import time
import paramiko

from system.discovery import connect_socket, remaining
from system.identity import verify_fingerprint, verify_ubuntu

READ_ONLY_COMMANDS = {
    'os_release': 'cat /etc/os-release',
    'hostname': 'hostname',
    'machine_id': 'cat /etc/machine-id',
    'helper': 'stat -c "%u %a %F" /usr/local/libexec/fyp-hardening/collect',
    'python': 'python3 --version',
    'openscap': 'oscap --version',
}
# The only privileged command. Approved setup installs the launcher root-owned and allows exactly
# this command, with no arguments, for the management account.
HELPER_COMMAND = 'sudo -n /usr/local/libexec/fyp-hardening/collect'
# The only privileged write path: the fixed root-owned runner, no arguments; operations arrive on stdin.
RUNNER_COMMAND = 'sudo -n /usr/local/libexec/fyp-hardening/runner'


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode('ascii').rstrip('=')


class SshChannel:
    def __init__(self, transport, public_fingerprint):
        self._transport = transport
        self.fingerprint = public_fingerprint

    @classmethod
    def connect(cls, request, credentials, known_fingerprint=None, *,
                transport_factory=paramiko.Transport, socket_factory=connect_socket):
        deadline = time.monotonic() + 30
        stream = socket_factory(request.endpoint, deadline)
        transport = None
        try:
            transport = transport_factory(stream)
            transport.banner_timeout = 10
            transport.auth_timeout = 15
            transport.start_client(timeout=remaining(deadline))
            public_fingerprint = fingerprint(transport.get_remote_server_key())
            # Authentication cannot precede trust and never silently tries a second method.
            verify_fingerprint(public_fingerprint, known_fingerprint, credentials.confirmed_fingerprint)
            if credentials.key_path:
                key = paramiko.PKey.from_path(Path(credentials.key_path))
                transport.auth_publickey(credentials.username, key)
            else:
                transport.auth_password(credentials.username, credentials.password, fallback=False)
            if not transport.is_authenticated():
                raise ValueError('SSH authentication did not complete')
            return cls(transport, public_fingerprint)
        except BaseException:
            if transport is not None:
                transport.close()
            stream.close()
            raise

    def read(self, operation, *, deadline=None, max_bytes=16384):
        if operation not in READ_ONLY_COMMANDS:
            raise ValueError('Unregistered read-only operation')
        deadline = min(deadline or float('inf'), time.monotonic() + 15)
        channel = self._transport.open_session(timeout=remaining(deadline))
        output, errors = bytearray(), bytearray()
        try:
            channel.settimeout(remaining(deadline))
            channel.exec_command(READ_ONLY_COMMANDS[operation])
            while True:
                remaining(deadline)
                if channel.recv_ready():
                    output.extend(channel.recv(4096))
                if channel.recv_stderr_ready():
                    errors.extend(channel.recv_stderr(4096))
                if len(output) + len(errors) > max_bytes:
                    raise ValueError('Remote output exceeds limit')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                time.sleep(.01)
            if channel.recv_exit_status() != 0:
                raise ValueError('Read-only probe unavailable: ' + operation)
            return output.decode('utf-8', errors='strict')
        finally:
            channel.close()

    def invoke_helper(self, stdin_bytes, *, deadline_seconds=600, max_bytes=10*1024*1024 + 4096):
        """Run the one fixed root-owned collector command; request on stdin, envelope bytes back.

        `sudo -n` never prompts: a password is never sent over stdin, where cached sudo credentials
        could deliver it to the helper instead. Remote stderr is bounded and never surfaced.
        """
        if type(stdin_bytes) is not bytes or len(stdin_bytes) > 64*1024:
            raise ValueError('Invalid collector request')
        return self._fixed(HELPER_COMMAND, stdin_bytes, deadline_seconds, max_bytes)

    def invoke_runner(self, stdin_bytes, *, deadline_seconds=1900, max_bytes=65536):
        """The one fixed remediation runner command; header line and exact payload on stdin."""
        if type(stdin_bytes) is not bytes or len(stdin_bytes) > 260*1024:
            raise ValueError('Invalid runner input')
        return self._fixed(RUNNER_COMMAND, stdin_bytes, deadline_seconds, max_bytes)

    def _fixed(self, command, stdin_bytes, deadline_seconds, max_bytes):
        deadline = time.monotonic() + deadline_seconds
        channel = self._transport.open_session(timeout=remaining(deadline))
        output, error_bytes = bytearray(), 0
        try:
            channel.settimeout(remaining(deadline))
            channel.exec_command(command)
            channel.sendall(stdin_bytes)
            channel.shutdown_write()
            while True:
                remaining(deadline)
                if channel.recv_ready():
                    output.extend(channel.recv(65536))
                if channel.recv_stderr_ready():
                    error_bytes += len(channel.recv_stderr(4096))
                if len(output) > max_bytes or error_bytes > 65536:
                    raise ValueError('Fixed command output exceeds limit')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                time.sleep(.01)
            status = channel.recv_exit_status()
            if status != 0:
                raise ValueError(f'Ubuntu fixed helper command refused or is not installed (exit status {status})')
            return bytes(output)
        finally:
            channel.close()

    def verify_identity(self, request):
        deadline = time.monotonic() + 30
        return verify_ubuntu(self.read('os_release', deadline=deadline), self.read('hostname', deadline=deadline),
                             self.read('machine_id', deadline=deadline), request.expected_hostname,
                             request.expected_machine_identity, self.fingerprint)

    def close(self):
        self._transport.close()
