"""Fixed systemd argv for supervised runner jobs and the commit-confirm rollback timer. Python 3.10, stdlib only.

A supervised family's write runs in a transient unit (`fyp-hardening-job-<request>`), bounded by RuntimeMaxSec and
independent of the SSH session that approved it. A commit-confirm family also gets a transient timer
(`fyp-hardening-rollback-<request>`) armed BEFORE the job starts; unless a confirmation arrives over a fresh SSH
login first, the timer runs the runner's `rollback` operation, which restores the recorded before-state.
Unit names carry only a validated 32-hex request ID; no shell, no caller-supplied text.
"""
import re
import subprocess

RUNNER_PATH = '/usr/local/libexec/fyp-hardening/runner'
_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'}


def _run(argv):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          env=_ENV, shell=False, close_fds=True, timeout=60).returncode


def _rid(request_id):
    if type(request_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', request_id):
        raise ValueError('Invalid request ID')
    return request_id


def _seconds(value):
    if type(value) is not int or not 1 <= value <= 7200:
        raise ValueError('Invalid supervision time')
    return value


class SystemdLauncher:
    def __init__(self, run=None):
        self.run = run or _run

    def _call(self, argv):
        if self.run(argv) != 0:
            raise OSError('systemd refused the supervision request')

    def arm_rollback(self, request_id, seconds):
        rid = _rid(request_id)
        self._call(['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=fyp-hardening-rollback-' + rid,
                    '--on-active=%ds' % _seconds(seconds), '--timer-property=AccuracySec=1s', RUNNER_PATH, 'rollback', rid])

    def start_job(self, request_id, seconds):
        rid = _rid(request_id)
        self._call(['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=fyp-hardening-job-' + rid,
                    '--property=RuntimeMaxSec=%d' % _seconds(seconds), RUNNER_PATH, 'job', rid])

    def job_active(self, request_id):
        return self.run(['/usr/bin/systemctl', 'is-active', '--quiet',
                         'fyp-hardening-job-' + _rid(request_id) + '.service']) == 0

    def stop_job(self, request_id):
        self._call(['/usr/bin/systemctl', 'stop', 'fyp-hardening-job-' + _rid(request_id) + '.service'])

    def disarm_rollback(self, request_id):
        self._call(['/usr/bin/systemctl', 'stop', 'fyp-hardening-rollback-' + _rid(request_id) + '.timer'])
