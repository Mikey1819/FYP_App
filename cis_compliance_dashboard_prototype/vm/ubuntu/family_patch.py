"""Patch job for CIS 1.2.2.1 (Manual: updates, patches and additional security software). Python 3.10, stdlib only.

CIS: `apt update && apt upgrade`. Here: `apt-get update`, then `apt-get -y upgrade`, as a systemd-supervised job
(up to 1800 s). A plain upgrade never removes or newly installs packages; holds are kept; apt never prompts and
needrestart only lists services. Refused while dpkg reports broken or half-configured packages. State is the list
of pending upgrades and holds, so the after-state is exact: nothing pending, holds unchanged.
There is no automatic restore: package downgrades are not reliable, so the recovery is the VirtualBox snapshot.
The control stays a CIS Manual review afterwards, and the VM is never rebooted (reboot-required is reported).
"""
import hashlib
import json
from pathlib import Path

PARAMS = {'upgrade': 'apt-get upgrade'}
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_patch.py').read_bytes()
                                       + (_HERE / 'family_package.py').read_bytes()).hexdigest()


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class PatchFamily:
    action_id = 'ubuntu.1.2.2.1.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 1800
    supervision = 'job'

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or params != PARAMS:
            raise ValueError('Only a plain apt-get upgrade is managed')

    def read_state(self, params):
        return _dump(self.system.upgrade_plan())

    def expected_after(self, params, before):
        state = json.loads(before)
        state['pending'] = []
        return _dump(state)

    def check_eligible(self, params):
        if self.system.dpkg_broken():
            raise ValueError('dpkg reports broken or half-configured packages; repair them by hand first')

    def summary(self, params, before):
        state = json.loads(before)
        return {'steps': ['apt-get update', 'apt-get -y upgrade'], 'pending_before_update': state['pending'][:40],
                'held_kept': state['held'],
                'recovery': 'No automatic restore (downgrades are not reliable): restore the VirtualBox snapshot.',
                'control': 'CIS 1.2.2.1 is Manual: it stays a human patch review after this job.',
                'reboot': 'Not performed; a kernel update may report that a reboot is required.'}

    def apply(self, params):
        self.system.apt_update()
        self.system.apt_upgrade()

    def restore(self, params, before):
        raise ValueError('Package upgrades are not reversed automatically; restore the VirtualBox snapshot')


class LinuxPatchIO:
    """Mixin over LinuxPackageIO's fixed-environment runner: the upgrade plan, dpkg audit, update and upgrade."""

    def upgrade_plan(self):
        from .family_package import parse_simulation
        code, out = self._exec(list(self._APT) + ['-s', 'upgrade'], 120)
        if code != 0:
            raise ValueError('apt could not plan the upgrade')
        held_code, held = self._exec(['/usr/bin/apt-mark', 'showhold'], 60)
        if held_code != 0:
            raise ValueError('apt-mark showhold failed')
        return {'pending': sorted({name for op, name, _, _ in parse_simulation(out) if op == 'Inst'}),
                'held': sorted(line.strip() for line in held.splitlines() if line.strip())}

    def dpkg_broken(self):
        code, out = self._exec(['/usr/bin/dpkg', '--audit'], 60)
        return code != 0 or bool(out.strip())

    def apt_update(self):
        if self._exec(list(self._APT) + ['update'], 600)[0] != 0:
            raise OSError('apt-get update failed')

    def apt_upgrade(self):
        argv = list(self._APT) + ['-y', '-o', 'Dpkg::Options::=--force-confdef', '-o', 'Dpkg::Options::=--force-confold',
                                  'upgrade']
        if self._exec(argv, 1500)[0] != 0:
            raise OSError('apt-get upgrade failed')
