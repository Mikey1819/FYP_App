"""Strict authenticated identity parsing. OS-release is never executed."""
from dataclasses import dataclass
import hmac
import re


@dataclass(frozen=True)
class VerifiedIdentity:
    platform: str
    hostname: str
    machine_identity: str
    os_version: str
    transport: str
    host_fingerprint: str | None = None


def parse_os_release(raw):
    if type(raw) is not str or len(raw.encode('utf-8')) > 16384 or '\x00' in raw:
        raise ValueError('Invalid OS-release evidence')
    values = {}
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'([A-Z][A-Z0-9_]*)=(.*)', line)
        if not match or match[1] in values:
            raise ValueError('Malformed or duplicate OS-release field')
        value = match[2]
        if value.startswith(('"', "'")):
            if len(value) < 2 or value[-1] != value[0]:
                raise ValueError('Unbalanced OS-release quotes')
            value = value[1:-1]
        elif re.search(r'\s', value):
            raise ValueError('Unquoted OS-release whitespace')
        values[match[1]] = value
    return values


def verify_ubuntu(os_release, hostname, machine_id, expected_hostname, expected_machine_id, fingerprint=None):
    values = parse_os_release(os_release)
    if values.get('ID') != 'ubuntu' or values.get('VERSION_ID') != '22.04':
        raise ValueError('Unsupported OS: Ubuntu 22.04 over SSH is required')
    if not re.fullmatch(r'[0-9a-f]{32}', expected_machine_id) or expected_machine_id == '0' * 32:
        raise ValueError('Ubuntu machine identity must be 32 lowercase hexadecimal characters')
    if machine_id.strip() != expected_machine_id or hostname.strip().casefold() != expected_hostname.casefold():
        raise ValueError('Authenticated machine identity does not match the registration')
    return VerifiedIdentity('ubuntu', hostname.strip(), machine_id.strip(), '22.04', 'ssh', fingerprint)


def verify_fingerprint(actual, known, independently_confirmed):
    if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', actual):
        raise ValueError('Invalid SSH host fingerprint')
    if known is not None:
        if not hmac.compare_digest(actual, known):
            raise ValueError('SSH host key changed; explicit re-enrolment is required')
    elif independently_confirmed is None or not hmac.compare_digest(actual, independently_confirmed):
        raise ValueError('SSH trust required: independently confirm the server fingerprint before login')
