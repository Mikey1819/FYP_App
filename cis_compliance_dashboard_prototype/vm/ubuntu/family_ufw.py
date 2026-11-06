"""UFW default-deny family for CIS 4.1.7. Python 3.10, stdlib only.

CIS: `ufw default deny incoming|outgoing|routed`, and "the following rules should be considered before applying the
default deny": http, https, ntp, DNS 53 and DNS over TLS 853. That list is the approved site profile here (blanket
approval, 2026-11-06), shown in every approval summary. Order: the outbound allowances are added first, then only
directions whose default is `allow` become `deny` (deny, reject and disabled already comply), so outbound traffic
is never fully blocked mid-change. Refused when UFW is inactive, or when incoming would become deny without an SSH
allow rule (the management channel). State is ufw's own `### tuple ###` records plus the reported defaults, so the
after-state is exact; restore resets the defaults and deletes only the rules this change added. Commit-confirm:
unless a fresh SSH login confirms within the window, the rollback timer restores the before-state.
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

    def read_state(self, params):
        return _dump(self.system.ufw_state())

    @staticmethod
    def _missing(state, port):
        networks = [('rules4', '0.0.0.0/0')] + ([('rules6', '::/0')] if state['ipv6'] else [])
        return any(rule_tuple(port, net) not in state[key] for key, net in networks)

    def expected_after(self, params, before):
        state = json.loads(before)
        for port in ALLOW_OUT:
            for key, net in [('rules4', '0.0.0.0/0')] + ([('rules6', '::/0')] if state['ipv6'] else []):
                if rule_tuple(port, net) not in state[key]:
                    state[key].append(rule_tuple(port, net))
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
                'allow_out_added': [port for port in ALLOW_OUT if self._missing(state, port)],
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
            added = any(rule_tuple(port, net) in current[key] and rule_tuple(port, net) not in state[key]
                        for key, net in (('rules4', '0.0.0.0/0'), ('rules6', '::/0')))
            if added:
                self.system.ufw(['delete', 'allow', 'out', port])


class LinuxUfwIO:
    """Mixin: `ufw status verbose`, bounded reads of ufw's rule records, and an allowlist of fixed ufw argv."""
    _ALLOWED = ({('allow', 'out', p) for p in ALLOW_OUT} | {('delete', 'allow', 'out', p) for p in ALLOW_OUT}
                | {('default', v, d) for v in ('allow', 'deny', 'reject') for d in DIRECTIONS})

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
