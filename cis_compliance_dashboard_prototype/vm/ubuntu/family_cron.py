"""Crontab permission family for CIS 2.4.1.2. Python 3.10, stdlib only.

CIS v2.0.0 p.324: `chown root:root /etc/crontab` and `chmod og-rwx /etc/crontab` (the owner bits are kept; group and
other lose every permission). Only /etc/crontab is touched, never recursively; a symlinked or non-regular file is
refused, and the change goes through a descriptor opened with O_NOFOLLOW so a last-moment symlink cannot redirect it.
Restore returns the recorded mode and ownership exactly. Replaced 1.2.2.1 in the selection on 2026-11-08.
"""
import hashlib
import json
import os
from pathlib import Path
import stat

PATH = '/etc/crontab'
PARAMS = {'path': PATH, 'owner': 0, 'group': 0, 'remove': 'og-rwx'}
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_cron.py').read_bytes()).hexdigest()


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class CrontabPermissionFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60
    control_id = '2.4.1.2'
    action_id = 'ubuntu.2.4.1.2.v1'

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or _dump(params) != _dump(PARAMS):
            raise ValueError('Only root ownership and removing group/other permissions on /etc/crontab are managed')

    def read_state(self, params):
        return _dump(self.system.crontab_stat())

    def expected_after(self, params, before):
        state = json.loads(before)
        return _dump(dict(state, mode=state['mode'] & ~0o077, uid=0, gid=0))

    def check_eligible(self, params):
        self.system.crontab_stat()  # refuses a missing, symlinked or non-regular file

    def summary(self, params, before):
        state, after = json.loads(before), json.loads(self.expected_after(params, before))
        return {'file': PATH, 'current': 'mode %04o, owner uid %d, group gid %d' % (state['mode'], state['uid'], state['gid']),
                'after': 'mode %04o, owner uid 0 (root), group gid 0 (root)' % after['mode'],
                'commands': ['chown root:root /etc/crontab', 'chmod og-rwx /etc/crontab'],
                'impact': 'Only root can read or change the system crontab; cron itself runs as root and is unaffected.',
                'recovery': 'Restore the recorded mode and ownership of /etc/crontab'}

    def apply(self, params):
        state = self.system.crontab_stat()
        self.system.set_crontab(state['mode'] & ~0o077, 0, 0)

    def restore(self, params, before):
        state = json.loads(before)
        self.system.set_crontab(state['mode'], state['uid'], state['gid'])


class LinuxCronIO:
    """Mixin: stat and change the one registered file, /etc/crontab, without following symlinks."""

    def crontab_stat(self):
        info = os.lstat(PATH)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError('/etc/crontab must be a regular file, not a symlink')
        return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}

    def set_crontab(self, mode, uid, gid):
        if (type(mode) is not int or not 0 <= mode <= 0o7777 or type(uid) is not int or type(gid) is not int
                or uid < 0 or gid < 0):
            raise ValueError('Invalid crontab mode or ownership')
        fd = os.open(PATH, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ValueError('/etc/crontab must be a regular file')
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)  # after fchown, which may clear set-id bits
        finally:
            os.close(fd)
