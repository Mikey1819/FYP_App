"""Execution-acceptance marker family. Python 3.10, stdlib only.

Exercises the real commit-confirm path on the VM without touching any system configuration: the only file it
writes is /var/lib/fyp-hardening/acceptance/marker inside the runner's own root-only state directory. Two
scenarios prove the machinery end to end: `confirm` (applied, then confirmed over a fresh SSH login) and
`rollback` (applied, deliberately not confirmed, restored by the systemd rollback timer).
"""
import hashlib
import json
import os
from pathlib import Path
import re

MARKER = '/var/lib/fyp-hardening/acceptance/marker'
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_acceptance.py').read_bytes()).hexdigest()


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class AcceptanceMarkerFamily:
    action_id = 'acceptance.marker.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 30
    supervision, confirm_seconds = 'confirm', 60

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if (type(params) is not dict or set(params) != {'scenario', 'nonce'} or params['scenario'] not in ('confirm', 'rollback')
                or type(params['nonce']) is not str or not re.fullmatch(r'[0-9a-f]{32}', params['nonce'])):
            raise ValueError('Invalid acceptance marker parameters')

    def read_state(self, params):
        return _dump({'marker': self.system.read_marker()})

    def expected_after(self, params, before):
        return _dump({'marker': params['scenario'] + ':' + params['nonce']})

    def summary(self, params, before):
        return {'writes': MARKER, 'scenario': params['scenario'], 'system_configuration': 'untouched',
                'expected': 'confirmed over a fresh login' if params['scenario'] == 'confirm'
                else 'restored by the rollback timer after about 90 seconds'}

    def apply(self, params):
        self.system.write_marker(params['scenario'] + ':' + params['nonce'])

    def restore(self, params, before):
        self.system.write_marker(json.loads(before)['marker'])


class LinuxAcceptanceIO:
    """Mixin: the marker file only, inside the runner's root-only state directory."""

    def read_marker(self):
        target = Path(MARKER)
        if target.is_symlink():
            raise ValueError('The acceptance marker must not be a symlink')
        if not target.exists():
            return None
        data = target.read_bytes()
        if len(data) > 128:
            raise ValueError('Unexpected acceptance marker content')
        return data.decode('ascii')

    def write_marker(self, content):
        target = Path(MARKER)
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError('The acceptance marker must not be a symlink')
        if content is None:
            if target.exists():
                target.unlink()
            return
        target.parent.mkdir(mode=0o700, exist_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            os.write(fd, content.encode('ascii'))
            os.fsync(fd)
        finally:
            os.close(fd)
