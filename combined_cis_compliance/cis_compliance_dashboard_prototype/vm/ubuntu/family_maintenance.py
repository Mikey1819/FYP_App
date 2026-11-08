"""Auxiliary maintenance operations: apt metadata refresh and approved reboot. Python 3.10, stdlib only.

Neither is a CIS control family. Both run as systemd-supervised jobs behind the same approval and gate.
- `maintenance.apt_refresh.v1`: `apt-get update`. State is the digest of the apt sources configuration plus a
  stamp the job writes only after a successful update, so the approval binds the exact repository configuration
  (changed sources make the request stale) and success is exact. It changes no configuration; no restore.
- `maintenance.reboot.v1`: stamps the current boot ID in the runner state directory, then schedules
  `systemctl reboot` 60 s later through a fixed transient timer. The after-state is reached only when the boot ID
  differs from the stamp: the runner holds the request as `awaiting_reboot` (keeping its lock) until the VM is back
  on a new boot. A reboot cannot be undone.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

STAMPS = '/var/lib/fyp-hardening/maintenance'
_HEX32 = re.compile(r'[0-9a-f]{32}')
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_maintenance.py').read_bytes()).hexdigest()


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class AptRefreshFamily:
    action_id = 'maintenance.apt_refresh.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 600
    supervision = 'job'

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or set(params) != {'nonce'} or type(params['nonce']) is not str \
                or not _HEX32.fullmatch(params['nonce']):
            raise ValueError('Invalid metadata refresh parameters')

    def read_state(self, params):
        return _dump({'repository_digest': self.system.apt_sources_digest(), 'stamp': self.system.read_stamp('apt-refresh')})

    def expected_after(self, params, before):
        state = json.loads(before)
        state['stamp'] = params['nonce']
        return _dump(state)

    def summary(self, params, before):
        return {'command': 'apt-get update', 'repository_digest': json.loads(before)['repository_digest'],
                'effect': 'Refreshes package lists only: installs nothing and changes no configuration.'}

    def apply(self, params):
        self.system.apt_update()
        self.system.write_stamp('apt-refresh', params['nonce'])

    def restore(self, params, before):
        raise ValueError('A package-list refresh changes no configuration and is not restored')


class RebootFamily:
    action_id = 'maintenance.reboot.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60
    supervision = 'job'
    completes_after_reboot = True
    DELAY_SECONDS = 60

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if (type(params) is not dict or set(params) != {'nonce', 'staged_request_ids', 'maintenance_window'}
                or type(params['nonce']) is not str or not _HEX32.fullmatch(params['nonce'])
                or params['maintenance_window'] != 'now'):
            raise ValueError('Invalid reboot parameters')
        staged = params['staged_request_ids']
        if (type(staged) is not list or not 1 <= len(staged) <= 64 or staged != sorted(set(staged))
                or any(type(s) is not str or not _HEX32.fullmatch(s) for s in staged)):
            raise ValueError('A reboot must name the applied changes it completes')

    def read_state(self, params):
        stamped = self.system.read_stamp('reboot-' + params['nonce'])
        rebooted = stamped is not None and stamped != self.system.boot_id()
        return _dump({'rebooted_for': params['nonce'] if rebooted else None})

    def expected_after(self, params, before):
        return _dump({'rebooted_for': params['nonce']})

    def summary(self, params, before):
        return {'reboot_in_seconds': self.DELAY_SECONDS, 'completes': params['staged_request_ids'],
                'after': 'The connection drops. Reconnect when the VM is back; Check status confirms the new boot, '
                         'then a fresh scan verifies the staged changes.'}

    def apply(self, params):
        self.system.write_stamp('reboot-' + params['nonce'], self.system.boot_id())
        self.system.schedule_reboot(self.DELAY_SECONDS)

    def restore(self, params, before):
        raise ValueError('A reboot cannot be undone')


class LinuxMaintenanceIO:
    """Mixin: apt sources digest, boot ID, stamps in the runner state directory, and one fixed reboot timer."""

    def apt_update(self):
        """`apt-get update` through LinuxPackageIO's fixed-environment runner (moved here from the retired 1.2.2.1
        patch family on 2026-11-08; the approved package-list refresh is its only user)."""
        if self._exec(list(self._APT) + ['update'], 600)[0] != 0:
            raise OSError('apt-get update failed')

    def apt_sources_digest(self):
        digest = hashlib.sha256(b'apt-sources-v1\0')
        paths = [Path('/etc/apt/sources.list')] if Path('/etc/apt/sources.list').exists() else []
        folder = Path('/etc/apt/sources.list.d')
        if folder.is_dir():
            paths += sorted(p for p in folder.iterdir() if p.suffix in ('.list', '.sources'))[:256]
        for path in paths:
            data = self.io._bytes(path, 1024 * 1024)
            digest.update(str(path).encode('utf-8') + b'\0' + str(len(data)).encode('ascii') + b'\0' + data)
        return digest.hexdigest()

    def boot_id(self):
        from .collector import read_bounded
        with open('/proc/sys/kernel/random/boot_id', 'rb') as handle:
            value = read_bounded(handle, 128).decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f-]{36}', value):
            raise ValueError('Unexpected boot ID')
        return value

    def _stamp_path(self, name):
        if not re.fullmatch(r'(apt-refresh|reboot-[0-9a-f]{32})', name):
            raise ValueError('Unregistered maintenance stamp')
        return Path(STAMPS) / name

    def read_stamp(self, name):
        path = self._stamp_path(name)
        if path.is_symlink():
            raise ValueError('Maintenance stamps must not be symlinks')
        return path.read_text(encoding='ascii').strip() if path.exists() else None

    def write_stamp(self, name, content):
        path = self._stamp_path(name)
        path.parent.mkdir(mode=0o700, exist_ok=True)
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError('Maintenance stamps must not be symlinks')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            os.write(fd, content.encode('ascii'))
            os.fsync(fd)
        finally:
            os.close(fd)

    def schedule_reboot(self, seconds):
        if type(seconds) is not int or not 30 <= seconds <= 300:
            raise ValueError('Invalid reboot delay')
        argv = ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=fyp-hardening-reboot',
                '--on-active=%ds' % seconds, '/usr/bin/systemctl', 'reboot']
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'},
                                shell=False, close_fds=True, timeout=60)
        if result.returncode != 0:
            raise OSError('systemd refused to schedule the reboot')
