"""Credential-free discovery of one supplied endpoint. No redirects or port guessing."""
from dataclasses import dataclass
import ipaddress
import queue
import re
import socket
import threading
import time

from .contracts import Endpoint

MAX_BYTES = 16384
_resolvers = threading.BoundedSemaphore(8)


@dataclass(frozen=True)
class DiscoveryResult:
    transport: str | None
    code: str
    detail: str


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError('Endpoint discovery deadline exceeded')
    return seconds


def connect_socket(endpoint, deadline):
    """Bound DNS separately: system resolvers do not honor socket timeouts."""
    try:
        ip = ipaddress.ip_address(endpoint.host)
        address = (socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM, 0,
                   '', (endpoint.host, endpoint.port))
    except ValueError:
        if not _resolvers.acquire(blocking=False):
            raise TimeoutError('Resolver budget exhausted')
        result = queue.Queue(maxsize=1)
        def resolve():
            try:
                result.put(socket.getaddrinfo(endpoint.host, endpoint.port, type=socket.SOCK_STREAM))
            except OSError:
                result.put(None)
            finally:
                _resolvers.release()
        threading.Thread(target=resolve, daemon=True).start()
        try:
            addresses = result.get(timeout=remaining(deadline))
        except queue.Empty:
            raise TimeoutError('DNS deadline exceeded') from None
        if not addresses:
            raise OSError('Endpoint could not be resolved')
        address = addresses[0]  # No enumeration of targets or other ports.
    stream = socket.socket(address[0], address[1], address[2])
    try:
        stream.settimeout(remaining(deadline))
        stream.connect(address[4])
        return stream
    except BaseException:
        stream.close()
        raise


def classify_banner(raw):
    if len(raw) > MAX_BYTES or b'\x00' in raw:
        return None
    for line in raw.splitlines()[:16]:
        if re.fullmatch(rb'SSH-2\.0-[\x21-\x7e]{1,240}(?: [\x20-\x7e]*)?', line) and len(line) <= 253:
            return 'ssh'
    return None


def classify_wsman(status, headers, body):
    if status in (301, 302, 303, 307, 308) or len(body) > MAX_BYTES:
        return None
    if status == 401:
        auth = next((v for k, v in headers.items() if k.lower() == 'www-authenticate'), '')
        if re.search(r'\b(NTLM|Negotiate)\b', auth, flags=re.I):
            return 'winrm_candidate'
    if status == 200:
        from defusedxml.ElementTree import fromstring
        try:
            root = fromstring(body)
            if any(node.tag == '{http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd}IdentifyResponse'
                   for node in root.iter()):
                return 'winrm'
        except Exception:
            return None
    return None


def _banner_probe(endpoint, deadline):
    with connect_socket(endpoint, deadline) as stream:
        data = b''
        while len(data) <= MAX_BYTES:
            stream.settimeout(remaining(deadline))
            part = stream.recv(min(1024, MAX_BYTES + 1 - len(data)))
            if not part:
                break
            data += part
            if classify_banner(data) or data.startswith((b'HTTP/', b'\x15\x03', b'\x16\x03')):
                break
        return data


def _wsman_probe(endpoint, deadline):
    body = (b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/>'
            b'<s:Body><i:Identify xmlns:i="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"/>'
            b'</s:Body></s:Envelope>')
    host = '[' + endpoint.host + ']' if ':' in endpoint.host else endpoint.host
    request = (f'POST /wsman HTTP/1.1\r\nHost: {host}:{endpoint.port}\r\n'
               'Content-Type: application/soap+xml;charset=UTF-8\r\nConnection: close\r\n'
               f'Content-Length: {len(body)}\r\n\r\n').encode('ascii') + body
    with connect_socket(endpoint, deadline) as stream:
        stream.sendall(request)
        data = b''
        while len(data) <= MAX_BYTES:
            stream.settimeout(remaining(deadline))
            part = stream.recv(min(4096, MAX_BYTES + 1 - len(data)))
            if not part:
                break
            data += part
            if b'\r\n\r\n' in data and data.startswith(b'HTTP/1.1 401'):
                break
    if len(data) > MAX_BYTES:
        raise ValueError('Discovery response exceeds limit')
    header, sep, body = data.partition(b'\r\n\r\n')
    lines = header.decode('ascii', errors='strict').split('\r\n')
    match = re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: .*)?', lines[0])
    if not sep or not match:
        raise ValueError('Malformed HTTP probe response')
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(':')
        if not colon:
            raise ValueError('Malformed HTTP header')
        headers[name] = value.strip()
    return int(match[1]), headers, body


def discover_transport(endpoint: Endpoint, deadline=None, *, banner_probe=_banner_probe, wsman_probe=_wsman_probe):
    if endpoint.method != 'auto':
        return DiscoveryResult(endpoint.method, 'override', 'Selected transport; OS and identity still require verification.')
    deadline = min(deadline or float('inf'), time.monotonic() + 10)
    try:
        raw = banner_probe(endpoint, min(deadline, time.monotonic() + 2))
        if classify_banner(raw):
            return DiscoveryResult('ssh', 'ssh_banner', 'SSH protocol detected; operating system is not yet known.')
        if raw.startswith((b'\x15\x03', b'\x16\x03')):
            return DiscoveryResult(None, 'unsupported_tls', 'TLS endpoint requires a supported secure transport configuration.')
    except (OSError, ValueError, TimeoutError):
        pass
    try:
        remaining(deadline)
        candidate = classify_wsman(*wsman_probe(endpoint, deadline))
        if candidate:
            return DiscoveryResult('winrm', candidate, 'WS-Man candidate; authenticated Windows identity verification is required.')
    except (OSError, ValueError, TimeoutError):
        pass
    return DiscoveryResult(None, 'ambiguous', 'Could not identify transport within limits. Select SSH or WinRM in Advanced settings.')
