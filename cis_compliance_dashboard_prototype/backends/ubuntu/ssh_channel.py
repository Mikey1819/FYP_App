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
    'helper': 'stat -c "%u %a %F" /usr/local/libexec/fyp-hardening/collector.py',
    'python': 'python3 --version',
    'openscap': 'oscap --version',
}


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

    def verify_identity(self, request):
        deadline = time.monotonic() + 30
        return verify_ubuntu(self.read('os_release', deadline=deadline), self.read('hostname', deadline=deadline),
                             self.read('machine_id', deadline=deadline), request.expected_hostname,
                             request.expected_machine_identity, self.fingerprint)

    def close(self):
        self._transport.close()
