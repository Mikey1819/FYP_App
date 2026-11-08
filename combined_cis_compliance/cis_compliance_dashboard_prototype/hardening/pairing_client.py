"""Finding a server on the local network by its pairing code (the laptop's side of pairing).

The administrator starts pairing on the server, which then shows a one-time code. Here the laptop asks every local
network it is on "is there a server with this code?" (a signed `find` message, see pairing.py) and waits for a signed
`found` answer. Only an answer that proves the same code, to this very question, is accepted. A Windows server then
lets this laptop's address reach WinRM; an Ubuntu server's SSH is already reachable, and its answer names the SSH host
key the login must then find. Logging in and checking the server's identity happen afterwards (servers_view.py and
system/connection.py), and on Windows also the pairing record over WinRM (server_control.py).
"""
from dataclasses import dataclass
import ipaddress
from uuid import UUID
import select
import socket
import time

from .pairing import PAIRING_PORT, MAX_MESSAGE, PairingError, make_find, read_found
from .system_detect import detect


@dataclass(frozen=True)
class FoundServer:
    address: str          # Where the answer came from: the server's address on this network.
    hostname: str
    machine_uuid: str
    port: int             # The server's WinRM port (Windows) or SSH port (Ubuntu).
    pairing_id: str       # The server's record of this pairing; checked again over WinRM after login.
    laptop_address: str   # This laptop's address on that network, as the server saw it.
    os: str               # The server's operating system, as it reported it (see pairing.py and system_detect.py).
    os_name: str
    os_version: str
    host_key: str | None = None  # Ubuntu only: the SSH host key fingerprint, signed with the code.

    @property
    def platform(self):
        """'windows' or 'ubuntu': which connection and workspace this server gets (None for anything else)."""
        return {'windows': 'windows', 'ubuntu': 'ubuntu'}.get(self.os)

    @property
    def transport(self):
        return 'ssh' if self.platform == 'ubuntu' else 'winrm'

    @property
    def machine_identity(self):
        """The identity the connection checks after login: the Windows machine UUID, or Ubuntu's /etc/machine-id
        (the same 128 bits, written as 32 lowercase hexadecimal characters without dashes)."""
        return UUID(self.machine_uuid).hex if self.platform == 'ubuntu' else self.machine_uuid

    @property
    def system(self):
        """Which kind of system this is, with a note for the page (system_detect.DetectedSystem)."""
        return detect(self.os, self.os_name, self.os_version)


def _usable(address):
    """A local-network address: private range only (192.168.x, 10.x, 172.16-31.x), the kind every home and office
    network uses. Loopback, self-assigned (169.254.x) and public addresses are left out, so the pairing question
    never goes out on an internet-wide virtual network such as a gaming or remote-access VPN (seen on the
    development laptop: Radmin VPN, 26.x), where strangers could see it."""
    ip = ipaddress.ip_address(address)
    return (ip.version == 4 and ip.is_private and not
            (ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified))


def local_addresses():
    """This laptop's local-network IPv4 addresses (Wi-Fi, Ethernet, VirtualBox host-only adapters...)."""
    found = []
    try:
        found = [info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except OSError:
        pass
    try:  # The address of the default route. Connecting a UDP socket sends nothing.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('192.0.2.1', 9))
            found.append(probe.getsockname()[0])
    except OSError:
        pass
    return list(dict.fromkeys(a for a in found if _usable(a)))


def find_server(code, *, name=None, port=PAIRING_PORT, timeout=6.0, attempts=3, targets=None, sources=None):
    """Ask for a server with this code; return the first valid answer as a FoundServer, or raise PairingError.

    Each local address gets its own socket, so a broadcast leaves through every network the laptop is on (Windows
    sends a broadcast through one network only per socket). The same question is repeated `attempts` times, because
    UDP messages can get lost; the server answers a repeat with the same answer. `targets` (address, port) pairs and
    `sources` replace the broadcast and the local addresses, for tests.
    """
    message, nonce = make_find(code, name or socket.gethostname())
    sources = list(sources or local_addresses())
    if not sources:
        raise PairingError('This laptop has no network address. Connect it to the same network as the server.')
    sockets = []
    try:
        for source in sources:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.bind((source, 0))
            except OSError:
                s.close()
                continue
            sockets.append(s)
        if not sockets:
            raise PairingError('Could not use any network address of this laptop.')
        destinations = list(targets or [('255.255.255.255', port)])
        deadline = time.monotonic() + timeout
        for attempt in range(attempts):
            for s in sockets:
                for destination in destinations:
                    try:
                        s.sendto(message, destination)
                    except OSError:
                        pass  # This network cannot reach that destination; the others may.
            attempt_end = min(deadline, time.monotonic() + timeout / attempts)
            while (remaining := attempt_end - time.monotonic()) > 0:
                ready, _, _ = select.select(sockets, [], [], remaining)
                for s in ready:
                    try:
                        raw, (address, _) = s.recvfrom(MAX_MESSAGE + 1)
                    except OSError:  # For example an "unreachable" notice on Windows; keep listening.
                        continue
                    try:
                        answer = read_found(raw, code, nonce)
                    except PairingError:
                        continue  # Not ours, not for this question, or not proving the code: ignore it.
                    return FoundServer(address, answer['hostname'], answer['machine_uuid'], answer['port'],
                                       answer['pairing_id'], s.getsockname()[0], answer['os'], answer['os_name'],
                                       answer['os_version'], answer.get('host_key'))
        # A server never answers a wrong code (an answer it could not sign would prove nothing, and silence keeps it
        # hidden), so the laptop cannot tell a wrong code from no server. The helper window on the server can.
        raise PairingError('No server answered. The code may be wrong or expired: the helper window on the server '
                           'shows "Wrong code" if so, and after 5 wrong codes it stops pairing until you click Start '
                           'pairing again. Otherwise, this laptop is not on the same network as the server.')
    finally:
        for s in sockets:
            s.close()
