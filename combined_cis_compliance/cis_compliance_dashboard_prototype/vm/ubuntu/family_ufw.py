"""UFW families: default deny (CIS 4.1.7), loopback rules (4.1.4) and enable (4.1.3). Python 3.10, stdlib only.

CIS: `ufw default deny incoming|outgoing|routed`, and "the following rules should be considered before applying the
default deny": http, https, ntp, DNS 53 and DNS over TLS 853. That list is the approved site profile here (blanket
approval, 2026-11-06), shown in every approval summary. Order: the outbound allowances are added first, then only
directions whose default is `allow` become `deny` (deny, reject and disabled already comply), so outbound traffic
is never fully blocked mid-change. Refused when UFW is inactive, or when incoming would become deny without an SSH
allow rule (the management channel). State is ufw's own `### tuple ###` records plus the reported defaults, so the
after-state is exact; restore resets the defaults and deletes only the rules this change added. Commit-confirm:
unless a fresh SSH login confirms within the window, the rollback timer restores the before-state.

4.1.7 and 4.1.4 each record only their own part of the configuration (administrator, 13 November 2026, so both are
approved and executed in one round, as the sysctl/sshd/sudo fixes since 11 November): 4.1.7 the default policies and
its five outbound rules, 4.1.4 its four loopback rules and whether they go in front. Neither changes the other's part
(4.1.7 adds only outbound allow rules, which never decide loopback traffic against the CIS classes), so the second
is not stale after the first, and each restore takes back only its own rules. 4.1.3 still records all the rules.
"""
import hashlib
import json
from pathlib import Path
import re

ALLOW_OUT = ['53', '80/tcp', '123/udp', '443/tcp', '853']
PARAMS = {'defaults': 'deny', 'allow_out': ALLOW_OUT}
DIRECTIONS = ('incoming', 'outgoing', 'routed')
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_ufw.py').read_bytes()).hexdigest()


def rule_tuple(port, network):
    number, _, proto = port.partition('/')
    return 'allow %s %s %s any %s out' % (proto or 'any', number, network, network)


def parse_tuples(text):
    return [line[len('### tuple ### '):].strip() for line in text.splitlines() if line.startswith('### tuple ### ')]


def parse_defaults(status):
    active = re.search(r'^Status: (active|inactive)$', status, re.M)
    if not active:
        raise ValueError('Unknown UFW status')
    found = re.search(r'^Default: (deny|reject|allow) \(incoming\), (deny|reject|allow) \(outgoing\), '
                      r'(deny|reject|allow|disabled) \(routed\)', status, re.M)
    return active.group(1) == 'active', dict(zip(DIRECTIONS, found.groups())) if found else None


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class UfwDefaultDenyFamily:
    action_id = 'ubuntu.4.1.7.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 120
    supervision, confirm_seconds = 'confirm', 600

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or params != PARAMS:
            raise ValueError('Only the approved default-deny site profile is managed')

    @staticmethod
    def _nets(ipv6):
        return [('rules4', '0.0.0.0/0')] + ([('rules6', '::/0')] if ipv6 else [])

    def _scope(self, state):
        """Only this fix's part: the default policies and, per address family, whether each outbound rule exists."""
        return {'active': state['active'], 'ipv6': state['ipv6'], 'defaults': state['defaults'],
                'allow_out': {port: [rule_tuple(port, net) in state[key] for key, net in self._nets(state['ipv6'])]
                              for port in ALLOW_OUT}}

    def read_state(self, params):
        return _dump(self._scope(self.system.ufw_state()))

    @staticmethod
    def _missing(state, port):
        networks = [('rules4', '0.0.0.0/0')] + ([('rules6', '::/0')] if state['ipv6'] else [])
        return any(rule_tuple(port, net) not in state[key] for key, net in networks)

    def expected_after(self, params, before):
        state = json.loads(before)
        state['allow_out'] = {port: [True] * len(present) for port, present in state['allow_out'].items()}
        state['defaults'] = {d: 'deny' if v == 'allow' else v for d, v in state['defaults'].items()}
        return _dump(state)

    def check_eligible(self, params):
        state = self.system.ufw_state()
        if not state['active'] or state['defaults'] is None:
            raise ValueError('UFW is not active; enable it under its own approval first')
        if state['defaults']['incoming'] == 'allow' and not any(
                re.fullmatch(r'allow (tcp|any) 22 \S+ \S+ \S+ in', rule) for rule in state['rules4']):
            raise ValueError('Denying incoming traffic without an SSH allow rule would lock out the management channel')

    def summary(self, params, before):
        state = json.loads(before)
        return {'defaults_changed': {d: [v, 'deny'] for d, v in state['defaults'].items() if v == 'allow'},
                'allow_out_added': [port for port in ALLOW_OUT if not all(state['allow_out'][port])],
                'site_profile': 'CIS 4.1.7 list: DNS 53, http 80/tcp, ntp 123/udp, https 443/tcp, DNS over TLS 853',
                'confirm_window_seconds': self.confirm_seconds,
                'after_apply': 'Disconnect and reconnect within 10 minutes, then confirm; otherwise the change '
                               'is rolled back automatically.'}

    def apply(self, params):
        state = self.system.ufw_state()
        for port in ALLOW_OUT:
            if self._missing(state, port):
                self.system.ufw(['allow', 'out', port])
        for direction in DIRECTIONS:
            if state['defaults'][direction] == 'allow':
                self.system.ufw(['default', 'deny', direction])

    def restore(self, params, before):
        state, current = json.loads(before), self.system.ufw_state()
        for direction in DIRECTIONS:
            old = state['defaults'][direction]
            if current['defaults'][direction] != old:
                if old == 'disabled':
                    raise ValueError('A disabled routed policy cannot be set back through ufw default')
                self.system.ufw(['default', old, direction])
        for port in ALLOW_OUT:
            added = any(not was and rule_tuple(port, net) in current[key]
                        for (key, net), was in zip(self._nets(state['ipv6']), state['allow_out'][port]))
            if added:
                self.system.ufw(['delete', 'allow', 'out', port])


# ---- CIS 4.1.4: loopback rules -------------------------------------------------------------------
LOOPBACK = [(['allow', 'in', 'on', 'lo'], [('rules4', 'allow any any 0.0.0.0/0 any 0.0.0.0/0 in_lo'),
                                          ('rules6', 'allow any any ::/0 any ::/0 in_lo')]),
            (['allow', 'out', 'on', 'lo'], [('rules4', 'allow any any 0.0.0.0/0 any 0.0.0.0/0 out_lo'),
                                           ('rules6', 'allow any any ::/0 any ::/0 out_lo')]),
            (['deny', 'in', 'from', '127.0.0.0/8'], [('rules4', 'deny any any 0.0.0.0/0 any 127.0.0.0/8 in')]),
            (['deny', 'in', 'from', '::1'], [('rules6', 'deny any any ::/0 any ::1 in')])]
EXPECTED_CLASSES = {'loopback_in': 'allow', 'loopback_out': 'allow', 'spoofed_in': 'deny'}


class UfwLoopbackFamily:
    """CIS 4.1.4: `ufw allow in on lo`, `allow out on lo`, `deny in from 127.0.0.0/8`, `deny in from ::1`.

    Missing rules are appended in CIS order (ufw appends, so earlier user rules keep precedence). Eligibility runs
    the collector's own resolver on the predicted rule list. If an earlier rule would still decide a class
    differently, the missing rules go in front instead (`ufw prepend`, ufw 0.36, in reverse so they keep CIS order):
    live 13 November 2026, the SSH rule 4.1.3 adds (`ufw allow 22/tcp`, from anywhere) also covers spoofed
    127.0.0.0/8 traffic to port 22, so the appended deny came too late. The loopback rules only allow traffic on lo
    and deny loopback sources elsewhere, so being first changes nothing for remote traffic. Refused when neither
    complies, when one address family has no rules yet (prepend into an empty list is not relied on), or when ufw's
    IPv6 is off while the kernel has IPv6. Restore deletes only the rules this change added. Commit-confirm.
    """
    action_id = 'ubuntu.4.1.4.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 120
    supervision, confirm_seconds = 'confirm', 600

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or params != {'rules': 'cis-loopback'}:
            raise ValueError('Only the CIS loopback rule set is managed')

    @staticmethod
    def _wanted(tuples, ipv6):
        return [(key, line) for key, line in tuples if key == 'rules4' or ipv6]

    def _scope(self, state):
        """Only this fix's part: whether each CIS loopback rule exists, and whether they go in front."""
        return {'active': state['active'], 'ipv6': state['ipv6'],
                'loopback': [[line in state[key] for key, line in self._wanted(tuples, state['ipv6'])]
                             for _, tuples in LOOPBACK],
                'front': self._front(state)}

    def read_state(self, params):
        return _dump(self._scope(self.system.ufw_state()))

    @staticmethod
    def _plan(state):
        """Commands to run and the tuples they add, in CIS order; IPv6 rules only when ufw manages IPv6."""
        plan = []
        for command, tuples in LOOPBACK:
            wanted = [(key, line) for key, line in tuples if key == 'rules4' or state['ipv6']]
            missing = [(key, line) for key, line in wanted if line not in state[key]]
            if wanted and missing:
                plan.append((command, missing))
        return plan

    @staticmethod
    def _placed(state, front):
        """The rule lists after adding the missing CIS rules at the end, or in front (CIS order either way)."""
        after = json.loads(_dump(state))
        added = {'rules4': [], 'rules6': []}
        for _, missing in UfwLoopbackFamily._plan(state):
            for key, line in missing:
                added[key].append(line)
        for key, lines in added.items():
            after[key] = lines + after[key] if front else after[key] + lines
        return after

    @staticmethod
    def _complies(state, after):
        from .probes import ufw_loopback
        resolved = ufw_loopback(after['rules4'], after['rules6'])
        return all(resolved[family] == EXPECTED_CLASSES for family in ['ipv4'] + (['ipv6'] if state['ipv6'] else []))

    def _front(self, state):
        """True when the missing rules go in front: appending would not comply, and both families have rules."""
        if self._complies(state, self._placed(state, False)):
            return False
        return bool(state['rules4']) and (bool(state['rules6']) or not state['ipv6'])

    def expected_after(self, params, before):
        """Every CIS loopback rule present, placed so they comply (nothing is then left to put in front)."""
        state = json.loads(before)
        state['loopback'] = [[True] * len(present) for present in state['loopback']]
        state['front'] = False
        return _dump(state)

    def check_eligible(self, params):
        state = self.system.ufw_state()
        if not state['active']:
            raise ValueError('UFW is not active (4.1.3 comes first)')
        if not state['ipv6'] and self.system.kernel_ipv6():
            raise ValueError('ufw IPv6 is off while the kernel has IPv6; the IPv6 loopback rules cannot be added')
        if not self._plan(state):
            raise ValueError('The CIS loopback rules are already present')
        for _, tuples in LOOPBACK:
            wanted = [(key, line) for key, line in tuples if key == 'rules4' or state['ipv6']]
            present = [line in state[key] for key, line in wanted]
            if any(present) and not all(present):
                raise ValueError('A loopback rule exists for only one address family; `ufw delete` would remove both '
                                 'on restore, so complete or remove it by hand')
        if not self._complies(state, self._placed(state, self._front(state))):
            raise ValueError('Earlier ufw rules would still decide loopback traffic differently; edit them by hand')

    def summary(self, params, before):
        state = json.loads(before)
        front = state['front']
        missing = [command for (command, _), present in zip(LOOPBACK, state['loopback']) if present and not all(present)]
        return {'commands': ['ufw ' + ('prepend ' if front else '') + ' '.join(command) for command in missing],
                'order': ('in front of the existing rules (an earlier rule, such as an SSH allow from anywhere, '
                          'would otherwise decide loopback traffic)' if front else 'appended after existing rules'),
                'confirm_window_seconds': self.confirm_seconds,
                'after_apply': 'Disconnect and reconnect within 10 minutes, then confirm; otherwise the change '
                               'is rolled back automatically.'}

    def apply(self, params):
        state = self.system.ufw_state()
        if self._front(state):
            for command, _ in reversed(self._plan(state)):  # each goes to the top: reversed keeps CIS order
                self.system.ufw(['prepend'] + list(command))
            return
        for command, _ in self._plan(state):
            self.system.ufw(list(command))

    def restore(self, params, before):
        state, current = json.loads(before), self.system.ufw_state()
        for (command, tuples), present in reversed(list(zip(LOOPBACK, state['loopback']))):
            wanted = self._wanted(tuples, state['ipv6'])
            if any(not was and line in current[key] for (key, line), was in zip(wanted, present)):
                self.system.ufw(['delete'] + list(command))  # only the rules this change added


# ---- CIS 4.1.3: ufw service enabled and firewall active -------------------------------------------
class UfwEnableFamily:
    """CIS 4.1.3: `systemctl unmask ufw.service`, `systemctl --now enable ufw.service`, `ufw enable`.

    Never enabled without an SSH (port 22) allow rule, so the management channel keeps working: when ufw's user
    rules have none, `ufw allow 22/tcp` is added first (administrator, 13 November 2026: no console step by hand).
    While ufw is off every port is open, so the rule widens nothing. Refused when ufw is not installed or there is
    nothing to do. Restore disables the firewall again if it was inactive, then deletes the SSH rule if this change
    added it, and returns the recorded unit enablement/activity. Commit-confirm.
    """
    action_id = 'ubuntu.4.1.3.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 120
    supervision, confirm_seconds = 'confirm', 600
    UNIT = 'ufw.service'
    SSH = [('rules4', 'allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in'), ('rules6', 'allow tcp 22 ::/0 any ::/0 in')]

    def __init__(self, system):
        self.system = system

    @staticmethod
    def _has_ssh_rule(state):
        return any(re.fullmatch(r'allow (tcp|any) 22 \S+ \S+ \S+ in', rule) for rule in state['rules4'])

    def _ssh_tuples(self, state):
        return [(key, line) for key, line in self.SSH if key == 'rules4' or state.get('ipv6')]

    def validate(self, params):
        if type(params) is not dict or _dump(params) != _dump({'enable': True}):
            raise ValueError('Only enabling ufw is managed')

    def read_state(self, params):
        state = self.system.ufw_state()
        return _dump({'unit': self.system.unit_state(self.UNIT), 'active': state['active'], 'ipv6': state['ipv6'],
                      'rules4': state['rules4'], 'rules6': state['rules6']})

    def expected_after(self, params, before):
        state = json.loads(before)
        if not self._has_ssh_rule(state):
            for key, line in self._ssh_tuples(state):
                if line not in state[key]:
                    state[key].append(line)
        state['unit'].update(enabled='enabled', active='active')
        state['active'] = True
        return _dump(state)

    def check_eligible(self, params):
        unit, state = self.system.unit_state(self.UNIT), self.system.ufw_state()
        if unit['load'] != 'loaded' and unit['enabled'] != 'masked':
            raise ValueError('ufw is not installed')
        if unit['enabled'] not in ('enabled', 'disabled', 'masked'):
            raise ValueError('This unit enablement state is not modelled')
        if unit['enabled'] == 'enabled' and unit['active'] == 'active' and state['active']:
            raise ValueError('ufw is already enabled and active')

    def summary(self, params, before):
        state = json.loads(before)
        steps = (['ufw allow 22/tcp (SSH, so the management channel keeps working)']
                 if not self._has_ssh_rule(state) else []) + (
            ['systemctl unmask ufw.service'] if state['unit']['enabled'] == 'masked' else []) + (
            ['systemctl enable ufw.service'] if state['unit']['enabled'] != 'enabled' else []) + (
            ['systemctl start ufw.service'] if state['unit']['active'] != 'active' else []) + (
            ['ufw --force enable'] if not state['active'] else [])
        return {'steps': steps, 'confirm_window_seconds': self.confirm_seconds,
                'after_apply': 'Disconnect and reconnect within 10 minutes, then confirm; otherwise the change '
                               'is rolled back automatically.'}

    def apply(self, params):
        unit, state = self.system.unit_state(self.UNIT), self.system.ufw_state()
        if not self._has_ssh_rule(state):
            self.system.ufw(['allow', '22/tcp'])  # first, so SSH is never cut when ufw starts
        if unit['enabled'] == 'masked':
            self.system.systemctl('unmask', self.UNIT)
        if unit['enabled'] != 'enabled':
            self.system.systemctl('enable', self.UNIT)
        if unit['active'] != 'active':
            self.system.systemctl('start', self.UNIT)
        if not state['active']:
            self.system.ufw(['--force', 'enable'])

    def restore(self, params, before):
        state = json.loads(before)
        if not state['active'] and self.system.ufw_state()['active']:
            self.system.ufw(['disable'])
        now = self.system.ufw_state()
        if any(line in now[key] and line not in state[key] for key, line in self.SSH):
            self.system.ufw(['delete', 'allow', '22/tcp'])  # only the rule this change added
        current = self.system.unit_state(self.UNIT)
        if state['unit']['active'] != 'active' and current['active'] == 'active':
            self.system.systemctl('stop', self.UNIT)
        if current['enabled'] != state['unit']['enabled']:
            self.system.systemctl({'disabled': 'disable', 'masked': 'mask', 'enabled': 'enable'}[state['unit']['enabled']],
                                  self.UNIT)


class LinuxUfwIO:
    """Mixin: `ufw status verbose`, bounded reads of ufw's rule records, and an allowlist of fixed ufw argv."""
    _ALLOWED = ({('allow', 'out', p) for p in ALLOW_OUT} | {('delete', 'allow', 'out', p) for p in ALLOW_OUT}
                | {('default', v, d) for v in ('allow', 'deny', 'reject') for d in DIRECTIONS}
                | {tuple(c) for c, _ in LOOPBACK} | {('delete',) + tuple(c) for c, _ in LOOPBACK}
                | {('prepend',) + tuple(c) for c, _ in LOOPBACK}
                | {('--force', 'enable'), ('disable',), ('allow', '22/tcp'), ('delete', 'allow', '22/tcp')})

    def kernel_ipv6(self):
        value = self._text('/sys/module/ipv6/parameters/disable').strip()
        return value == '0' 

    def _text(self, path):
        target = Path(path)
        return self.io._bytes(target, 4 * 1024 * 1024).decode('utf-8') if target.exists() else ''

    def ufw_state(self):
        result = self.io._run(('/usr/sbin/ufw', 'status', 'verbose'), 20)
        if result.returncode != 0:
            raise ValueError('ufw status failed')
        active, defaults = parse_defaults(result.stdout)
        settings = dict(line.split('=', 1) for line in self._text('/etc/default/ufw').splitlines()
                        if '=' in line and not line.lstrip().startswith('#'))
        return {'active': active, 'ipv6': settings.get('IPV6', '').strip().strip('"').lower() == 'yes',
                'defaults': defaults, 'rules4': parse_tuples(self._text('/etc/ufw/user.rules')),
                'rules6': parse_tuples(self._text('/etc/ufw/user6.rules'))}

    def ufw(self, args):
        if tuple(args) not in self._ALLOWED:
            raise ValueError('Unregistered ufw command')
        if self.io._run(('/usr/sbin/ufw',) + tuple(args), 60).returncode != 0:
            raise OSError('ufw refused the change')
