"""Finding a server on the local network by its pairing code (the laptop's side of pairing).

The administrator starts pairing on the server, which then shows a one-time code. Here the laptop asks every local
network it is on "is there a server with this code?" (a signed `find` message, see pairing.py) and waits for a signed
`found` answer. Only an answer that proves the same code, to this very question, is accepted. The server then lets
this laptop's address reach WinRM. Logging in, and checking the server's identity and pairing record over WinRM,
happen afterwards (servers_view.py and server_control.py).
"""
from dataclasses import dataclass
import ipaddress
import select
import socket
import time

from .pairing import PAIRING_PORT, MAX_MESSAGE, PairingError, make_find, read_found


@dataclass(frozen=True)
class FoundServer:
    address: str          # Where the answer came from: the server's address on this network.
    hostname: str
    machine_uuid: str
    port: int             # The server's WinRM port.
    pairing_id: str       # The server's record of this pairing; checked again over WinRM after login.
    laptop_address: str   # This laptop's address on that network, as the server saw it.


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
                                       answer['pairing_id'], s.getsockname()[0])
        raise PairingError('No server answered with this code. Check that the code is still shown on the server, '
                           'that you typed it correctly, and that this laptop is on the same network as the server.')
    finally:
        for s in sockets:
            s.close()
