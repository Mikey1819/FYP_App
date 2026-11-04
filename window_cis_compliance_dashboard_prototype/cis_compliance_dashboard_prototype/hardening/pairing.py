"""Pairing messages: how this laptop and the server helper recognise each other by a one-time code.

The server helper (scripts/server_access/FYP-ServerAccess.ps1) shows a 9-digit code. The administrator types it here.
The laptop then asks the local network "is there a server with this code?" (`find`), and the server answers (`found`).
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
    return ('found', VERSION, m['nonce_l'], m['nonce_s'], m['hostname'], m['machine_uuid'], m['port'],
            m['pairing_id'])


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
FOUND_KEYS = ('v', 'type', 'nonce_l', 'nonce_s', 'hostname', 'machine_uuid', 'port', 'pairing_id', 'mac')


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


def make_found(code, nonce_l, hostname, machine_uuid, port, pairing_id, nonce_s=None):
    """Server side (mirrors the PowerShell helper, used in tests): the answer to one checked question."""
    message = dict(v=VERSION, type='found', nonce_l=nonce_l, nonce_s=nonce_s or new_nonce(), hostname=hostname,
                   machine_uuid=str(UUID(machine_uuid)), port=port, pairing_id=pairing_id)
    message['mac'] = _mac(code, *_found_fields(message))
    return _encode(message)


def read_found(raw, code, nonce_l):
    """The laptop's check of an answer: right format, answers *our* question (nonce_l), and proves the code."""
    m = _decode(raw, 'found', FOUND_KEYS)
    _check(type(m['nonce_l']) is str and _HEX32.fullmatch(m['nonce_l']), 'nonce')
    _check(type(m['nonce_s']) is str and _HEX32.fullmatch(m['nonce_s']), 'nonce')
    _check(type(m['pairing_id']) is str and _HEX32.fullmatch(m['pairing_id']), 'pairing id')
    _check(type(m['hostname']) is str and _NAME.fullmatch(m['hostname']), 'hostname')
    _check(type(m['port']) is int and 1 <= m['port'] <= 65535, 'port')
    try:
        _check(type(m['machine_uuid']) is str and str(UUID(m['machine_uuid'])) == m['machine_uuid'], 'machine UUID')
    except ValueError:
        raise PairingError('malformed machine UUID') from None
    if m['nonce_l'] != nonce_l:
        raise PairingError('answer to another question')
    _verify(code, m, _found_fields(m))
    return m
