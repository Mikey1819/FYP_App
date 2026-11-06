"""Service family for CIS 6.3.1.2 (auditd enabled and active). Python 3.10, stdlib only.

CIS: `systemctl unmask auditd`, `systemctl enable auditd`, `systemctl start auditd`. Only the missing steps run.
Refused when the unit is not installed (6.3.1.1 comes first) or its enablement state is one this family does
not model (static, indirect, generated, ...). Restore returns the recorded enablement and activity. auditd's
unit sets RefuseManualStop, so a restore that must stop it sends SIGTERM through `systemctl kill` and waits for
the unit to become inactive.
"""
import hashlib
import json
from pathlib import Path
import time

SPECS = {'6.3.1.2': 'auditd.service'}
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_service.py').read_bytes()).hexdigest()


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class ServiceFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60

    def __init__(self, control_id, system):
        self.control_id, self.unit, self.system = control_id, SPECS[control_id], system
        self.action_id = 'ubuntu.%s.v1' % control_id

    def validate(self, params):
        if type(params) is not dict or _dump(params) != _dump({'unit': self.unit, 'enabled': True, 'active': True}):
            raise ValueError('Only enabling and starting the registered unit is managed')

    def read_state(self, params):
        return _dump(self.system.unit_state(self.unit))

    def expected_after(self, params, before):
        state = json.loads(before)
        state.update(enabled='enabled', active='active')
        return _dump(state)

    def check_eligible(self, params):
        state = self.system.unit_state(self.unit)
        if state['load'] != 'loaded' and state['enabled'] != 'masked':
            raise ValueError('The unit is not installed; install its package first')
        if state['enabled'] not in ('enabled', 'disabled', 'masked'):
            raise ValueError('This unit enablement state is not modelled')
        if state['active'] not in ('active', 'inactive', 'failed'):
            raise ValueError('The unit is changing state; try again')

    def summary(self, params, before):
        state = json.loads(before)
        steps = (['unmask'] if state['enabled'] == 'masked' else []) + (
            ['enable'] if state['enabled'] != 'enabled' else []) + (['start'] if state['active'] != 'active' else [])
        return {'unit': self.unit, 'current': state, 'steps': steps}

    def apply(self, params):
        state = self.system.unit_state(self.unit)
        if state['enabled'] == 'masked':
            self.system.systemctl('unmask', self.unit)
        if state['enabled'] != 'enabled':
            self.system.systemctl('enable', self.unit)
        if state['active'] != 'active':
            self.system.systemctl('start', self.unit)

    def restore(self, params, before):
        state, current = json.loads(before), self.system.unit_state(self.unit)
        if state['active'] != 'active' and current['active'] == 'active':
            self.system.systemctl('stop', self.unit)
        if current['enabled'] != state['enabled']:
            self.system.systemctl({'disabled': 'disable', 'masked': 'mask', 'enabled': 'enable'}[state['enabled']],
                                  self.unit)


class LinuxServiceIO:
    """Mixin: `systemctl show` for one registered unit and an allowlist of fixed systemctl verbs."""
    _VERBS = ('unmask', 'enable', 'start', 'stop', 'disable', 'mask')

    def unit_state(self, unit):
        if unit not in SPECS.values():
            raise ValueError('Unregistered unit')
        result = self.io._run(('/usr/bin/systemctl', 'show', '--property=LoadState,UnitFileState,ActiveState', unit), 20)
        if result.returncode != 0:
            raise ValueError('systemctl show failed')
        values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        return {'load': values.get('LoadState', ''), 'enabled': values.get('UnitFileState', '') or 'not-found',
                'active': values.get('ActiveState', '')}

    def systemctl(self, verb, unit):
        if verb not in self._VERBS or unit not in SPECS.values():
            raise ValueError('Unregistered systemctl command')
        if verb == 'stop':
            # auditd refuses manual stops; SIGTERM through systemd is its documented shutdown path.
            if self.io._run(('/usr/bin/systemctl', 'kill', '--signal=SIGTERM', unit), 30).returncode != 0:
                raise OSError('systemctl kill failed')
            for _ in range(40):
                if self.unit_state(unit)['active'] in ('inactive', 'failed'):
                    return
                time.sleep(0.5)
            raise OSError('The unit did not stop')
        if self.io._run(('/usr/bin/systemctl', verb, unit), 60).returncode != 0:
            raise OSError('systemctl ' + verb + ' failed')
