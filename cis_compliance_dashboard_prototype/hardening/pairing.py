"""Pairing messages: how this laptop and the server helper recognise each other by a one-time code.

The server helper shows a 9-digit code: scripts/server_access/FYP-ServerAccess.ps1 on Windows Server 2022, and
scripts/server_access/fyp-pair-ubuntu.py on Ubuntu 22.04. The administrator types it here.
The laptop then asks the local network "is there a server with this code?" (`find`), and the server answers (`found`)
with its name, machine UUID and operating system (system_detect.py turns the last into a note on the page).
An Ubuntu answer also carries `host_key`, the SHA256 fingerprint of the server's SSH host key. It is signed with the
code like every other field, so the administrator never has to type the fingerprint: knowing the code that the
server's own screen showed stands for having read the key from that screen. The Windows answer has no such field
(WinRM has no host key to pin), so its bytes are exactly those of the Windows project.
Each side proves it knows the code with an HMAC-SHA256 signature keyed by the code, so the code itself never travels
on the network. The PowerShell helper builds and checks the same messages; both sides are tested against the same
examples in scripts/server_access/pairing_vectors.json. Design: docs/design/LAN_PAIRING_DESIGN.md.

This module only builds and checks messages. Sending them is in pairing_client.py.
"""
import hashlib
import hmac
import json
import re
import secrets
from uuid import UUID

PAIRING_PORT = 47815  # UDP, local network only.
VERSION = 1
MAX_MESSAGE = 1024  # Bytes. Both messages are far smaller; anything larger is not ours.
CODE_DIGITS = 9

_HEX32 = re.compile(r'[0-9a-f]{32}')
_HEX64 = re.compile(r'[0-9a-f]{64}')
# Windows computer names: letters, digits and hyphens. Underscore and dot are allowed for safety; nothing else.
_NAME = re.compile(r'[A-Za-z0-9._-]{1,63}')
# The server's operating system, as the helper reports it (read by system_detect.py):
#   os          a short id: "windows", or the ID line of /etc/os-release on Linux ("ubuntu", "debian"...)
#   os_name     the full name, plain printable ASCII ("Microsoft Windows Server 2022 Standard Evaluation")
#   os_version  the version number ("10.0.20348" on Windows, "22.04" on Ubuntu)
_OS_ID = re.compile(r'[a-z0-9._-]{1,32}')
_OS_NAME = re.compile(r'[ -~]{1,100}')
_OS_VERSION = re.compile(r'[A-Za-z0-9._-]{1,32}')
# An OpenSSH SHA256 host key fingerprint, as ssh-keygen -lf prints it (and as the SSH channel computes it).
_HOST_KEY = re.compile(r'SHA256:[A-Za-z0-9+/]{43}')


class PairingError(Exception):
    """A message that is not a valid pairing message, or whose proof is wrong. Never trusted further."""


def normalize_code(text):
    """The typed code, as 9 digits. Spaces and dashes are allowed when typing ("482-913-075")."""
    digits = re.sub(r'[\s-]', '', str(text))
    if not re.fullmatch(r'\d{%d}' % CODE_DIGITS, digits):
        raise ValueError(f'The pairing code has {CODE_DIGITS} digits, as shown on the server.')
    return digits


def format_code(digits):
    digits = normalize_code(digits)
    return f'{digits[:3]}-{digits[3:6]}-{digits[6:]}'


def new_code():
    """A fresh random code. The server helper makes its own; this is for tests and examples."""
    return ''.join(secrets.choice('0123456789') for _ in range(CODE_DIGITS))


def new_nonce():
    """A random 128-bit value used once, so an old message cannot be replayed."""
    return secrets.token_hex(16)


def laptop_name(name):
    """This computer's name as sent in `find`, reduced to safe characters (shown on the server's screen)."""
    cleaned = re.sub(r'[^A-Za-z0-9._-]', '', str(name))[:63]
    return cleaned or 'laptop'


def _key(code):
    return ('FYP-PAIR-v1:' + normalize_code(code)).encode('ascii')


def _mac(code, *fields):
    # Fields are joined with line breaks in a fixed order. None may contain a line break (checked by the callers).
    text = '\n'.join(str(f) for f in fields)
    return hmac.new(_key(code), text.encode('utf-8'), hashlib.sha256).hexdigest()


def _find_fields(m):
    return 'find', VERSION, m['nonce_l'], m['laptop_name']


def _found_fields(m):
    fields = ('found', VERSION, m['nonce_l'], m['nonce_s'], m['hostname'], m['machine_uuid'], m['port'],
              m['pairing_id'], m['os'], m['os_name'], m['os_version'])
    return fields + (m['host_key'],) if 'host_key' in m else fields


def _encode(message):
    raw = json.dumps(message, separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_MESSAGE:
        raise ValueError('Pairing message too large')
    return raw


def _decode(raw, kind, keys):
    """Parse strictly: our exact fields with the right types, or PairingError."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_MESSAGE:
        raise PairingError('not a pairing message')
    try:
        message = json.loads(bytes(raw).decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise PairingError('not a pairing message') from None
    if type(message) is not dict or set(message) != set(keys) or message.get('type') != kind:
        raise PairingError('not a ' + kind + ' message')
    if message.get('v') != VERSION or type(message['v']) is not int:
        raise PairingError('unsupported pairing version')
    if not (type(message.get('mac')) is str and _HEX64.fullmatch(message['mac'])):
        raise PairingError('malformed proof')
    return message


def _check(condition, what):
    if not condition:
        raise PairingError('malformed ' + what)


def _verify(code, message, fields):
    if not hmac.compare_digest(_mac(code, *fields), message['mac']):
        raise PairingError('wrong pairing code')


FIND_KEYS = ('v', 'type', 'nonce_l', 'laptop_name', 'mac')
FOUND_KEYS = ('v', 'type', 'nonce_l', 'nonce_s', 'hostname', 'machine_uuid', 'port', 'pairing_id', 'os', 'os_name',
              'os_version', 'mac')
FOUND_SSH_KEYS = FOUND_KEYS + ('host_key',)  # An Ubuntu answer: the same fields plus the SSH host key fingerprint.


def make_find(code, name, nonce_l=None):
    """The laptop's question. Returns (bytes to broadcast, nonce_l to match the answer with)."""
    message = dict(v=VERSION, type='find', nonce_l=nonce_l or new_nonce(), laptop_name=laptop_name(name))
    message['mac'] = _mac(code, *_find_fields(message))
    return _encode(message), message['nonce_l']


def read_find(raw, code):
    """Server side (mirrors the PowerShell helper, used in tests): the checked question."""
    m = _decode(raw, 'find', FIND_KEYS)
    _check(type(m['nonce_l']) is str and _HEX32.fullmatch(m['nonce_l']), 'nonce')
    _check(type(m['laptop_name']) is str and _NAME.fullmatch(m['laptop_name']), 'laptop name')
    _verify(code, m, _find_fields(m))
    return m


def make_found(code, nonce_l, hostname, machine_uuid, port, pairing_id, nonce_s=None, *, os, os_name, os_version,
               host_key=None):
    """Server side (mirrors the helpers, used in tests): the answer to one checked question, including which
    operating system the server runs and, for an SSH server, its host key fingerprint."""
    message = dict(v=VERSION, type='found', nonce_l=nonce_l, nonce_s=nonce_s or new_nonce(), hostname=hostname,
                   machine_uuid=str(UUID(machine_uuid)), port=port, pairing_id=pairing_id, os=os, os_name=os_name,
                   os_version=os_version)
    if host_key is not None:
        message['host_key'] = host_key
    message['mac'] = _mac(code, *_found_fields(message))
    return _encode(message)


def read_found(raw, code, nonce_l):
    """The laptop's check of an answer: right format, answers *our* question (nonce_l), and proves the code."""
    try:
        m = _decode(raw, 'found', FOUND_KEYS)
    except PairingError:
        m = _decode(raw, 'found', FOUND_SSH_KEYS)
    _check('host_key' not in m or (type(m['host_key']) is str and _HOST_KEY.fullmatch(m['host_key'])), 'host key')
    _check(type(m['nonce_l']) is str and _HEX32.fullmatch(m['nonce_l']), 'nonce')
    _check(type(m['nonce_s']) is str and _HEX32.fullmatch(m['nonce_s']), 'nonce')
    _check(type(m['pairing_id']) is str and _HEX32.fullmatch(m['pairing_id']), 'pairing id')
    _check(type(m['hostname']) is str and _NAME.fullmatch(m['hostname']), 'hostname')
    _check(type(m['port']) is int and 1 <= m['port'] <= 65535, 'port')
    _check(type(m['os']) is str and _OS_ID.fullmatch(m['os']), 'system id')
    _check(type(m['os_name']) is str and _OS_NAME.fullmatch(m['os_name']), 'system name')
    _check(type(m['os_version']) is str and _OS_VERSION.fullmatch(m['os_version']), 'system version')
    try:
        _check(type(m['machine_uuid']) is str and str(UUID(m['machine_uuid'])) == m['machine_uuid'], 'machine UUID')
    except ValueError:
        raise PairingError('malformed machine UUID') from None
    if m['nonce_l'] != nonce_l:
        raise PairingError('answer to another question')
    _verify(code, m, _found_fields(m))
    # Ubuntu is reached over SSH, so its answer must name the host key; a Windows answer never has one.
    _check(('host_key' in m) == (m['os'] == 'ubuntu'), 'host key')
    return m
