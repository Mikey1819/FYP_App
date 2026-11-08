"""Account-aging families for CIS 5.4.1.1, 5.4.1.3 and 5.4.1.5. Python 3.10, stdlib only.

Each family sets one approved site value in its default source (/etc/login.defs or /etc/default/useradd) when that
default fails, and runs `chage` only for password-bearing accounts whose own value fails. Accounts that already
comply, locked accounts and the password hashes are never touched or read into state.
Lockout guard (5.4.1.1 and 5.4.1.5): no change may leave a changed account's password expired or expiring within
MARGIN_DAYS, and accounts with a forced change (last change 0) or no last-change date are refused, so the
management account cannot be locked out by an approved change.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import time
from .family_sysctl import HEADER
from .probes import _integer, account_aging

MARGIN_DAYS = 30
LOGIN_DEFS = '/etc/login.defs'
USERADD = '/etc/default/useradd'
SPECS = {
    '5.4.1.1': dict(param='maxdays', target=365, field='maximum', flag='--maxdays', source=LOGIN_DEFS, key='PASS_MAX_DAYS'),
    '5.4.1.3': dict(param='warndays', target=7, field='warning', flag='--warndays', source=LOGIN_DEFS, key='PASS_WARN_AGE'),
    '5.4.1.5': dict(param='inactive', target=45, field='inactive', flag='--inactive', source=USERADD, key='INACTIVE'),
}
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_aging.py').read_bytes()
                                       + (_HERE / 'probes.py').read_bytes()).hexdigest()


def parse_accounts(passwd_text, shadow_text):
    """The collector's account records plus each last-change day (None when empty); never the hash field."""
    records = account_aging(passwd_text, shadow_text)
    lastchg = {}
    for line in shadow_text.splitlines():
        fields = line.split(':')
        lastchg[fields[0]] = _integer(fields[2]) if fields[2] else None
    for record in records:
        record['lastchg'] = lastchg[record['name']]
    return records


def good(control_id, value, minimum=-1):
    if control_id == '5.4.1.1':
        return 1 <= value <= 365 and value > minimum
    if control_id == '5.4.1.3':
        return value >= 7
    return 0 <= value <= 45


def login_value(text, key):
    """The single value the collector reads for `key`; anything ambiguous is refused, as the collector refuses it."""
    rows = [i for i, line in enumerate(text.splitlines())
            if line.strip() and not line.lstrip().startswith('#') and line.split()[0] == key]
    if len(rows) != 1 or len(text.splitlines()[rows[0]].split()) != 2:
        raise ValueError('The %s default is missing or ambiguous' % key)
    return rows[0], _integer(text.splitlines()[rows[0]].split()[1])


def useradd_value(text):
    rows = [i for i, line in enumerate((text or '').splitlines())
            if not line.lstrip().startswith('#') and '=' in line and line.split('=', 1)[0].strip() == 'INACTIVE']
    if len(rows) > 1:
        raise ValueError('The INACTIVE default is ambiguous')
    if not rows:
        return None, -1
    return rows[0], _integer(text.splitlines()[rows[0]].split('=', 1)[1].strip())


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class AgingFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 120

    def __init__(self, control_id, system):
        self.control_id, self.spec, self.system = control_id, SPECS[control_id], system
        self.action_id = 'ubuntu.%s.v1' % control_id

    def validate(self, params):
        name = self.spec['param']
        if type(params) is not dict or set(params) != {name} or type(params[name]) is not int or params[name] != self.spec['target']:
            raise ValueError('Only %s = %d is managed' % (name, self.spec['target']))

    # ---- default source -----------------------------------------------------------------
    def _read_default(self):
        data = self.system.login_defs() if self.spec['source'] == LOGIN_DEFS else self.system.useradd_defaults()
        return None if data is None else data.decode('utf-8')

    def _default(self, text):
        """(current value, minimum the value must exceed)."""
        if self.spec['source'] == USERADD:
            return useradd_value(text)[1], -1
        value = login_value(text, self.spec['key'])[1]
        return value, login_value(text, 'PASS_MIN_DAYS')[1] if self.control_id == '5.4.1.1' else -1

    def _edited(self, text):
        value, minimum = self._default(text)
        if good(self.control_id, value, minimum):
            return text
        target = self.spec['target']
        if self.spec['source'] == LOGIN_DEFS:
            row = login_value(text, self.spec['key'])[0]
            lines = text.splitlines(True)
            line = lines[row]
            end = len(line.rstrip('\r\n'))
            token = line.split()[1]
            cut = line.rindex(token, 0, end)
            lines[row] = line[:cut] + str(target) + line[cut + len(token):]
            return ''.join(lines)
        if text is None:
            return HEADER.decode('utf-8') + 'INACTIVE=%d\n' % target
        row = useradd_value(text)[0]
        if row is None:
            return text + ('' if text.endswith('\n') or not text else '\n') + 'INACTIVE=%d\n' % target
        lines = text.splitlines(True)
        lines[row] = 'INACTIVE=%d' % target + lines[row][len(lines[row].rstrip('\r\n')):]
        return ''.join(lines)

    # ---- state ----------------------------------------------------------------------------
    def _accounts(self):
        return [r for r in self.system.account_records() if r['password_bearing']]

    def read_state(self, params):
        text = self._read_default()
        self._default(text)
        return _dump({'default': text,
                      'accounts': {r['name']: {'value': r[self.spec['field']], 'minimum': r['minimum']}
                                   for r in self._accounts()}})

    def _changes(self, state):
        return {name: [row['value'], self.spec['target']] for name, row in sorted(state['accounts'].items())
                if not good(self.control_id, row['value'], row['minimum'])}

    def expected_after(self, params, before):
        state = json.loads(before)
        for name in self._changes(state):
            state['accounts'][name]['value'] = self.spec['target']
        state['default'] = self._edited(state['default'])
        return _dump(state)

    def check_eligible(self, params):
        text = self._read_default()
        value, minimum = self._default(text)
        if self.control_id == '5.4.1.1' and minimum >= self.spec['target']:
            raise ValueError('PASS_MIN_DAYS would not be below the new maximum; users could not change passwords')
        today = self.system.today()
        for record in self._accounts():
            current = record[self.spec['field']]
            if good(self.control_id, current, record['minimum']):
                continue
            if self.control_id == '5.4.1.1' and record['minimum'] >= self.spec['target']:
                raise ValueError('An account minimum age would not be below the new maximum')
            if self.control_id == '5.4.1.3':
                continue
            if record['lastchg'] in (None, 0):
                raise ValueError('An account has no usable last-change date; aging could expire or lock it')
            maximum = self.spec['target'] if self.control_id == '5.4.1.1' else record['maximum']
            if maximum != -1 and record['lastchg'] + maximum < today + MARGIN_DAYS:
                raise ValueError('An account password would be expired or expire within %d days' % MARGIN_DAYS)

    def summary(self, params, before):
        state = json.loads(before)
        value = self._default(state['default'])[0]
        edited = self._edited(state['default']) != state['default']
        return {'file': self.spec['source'], 'default': [self.spec['key'], value, self.spec['target']] if edited else None,
                'accounts': self._changes(state), 'command': 'chage ' + self.spec['flag']}

    # ---- change ---------------------------------------------------------------------------
    def _write_default(self, text):
        data = None if text is None else text.encode('utf-8')
        if self.spec['source'] == LOGIN_DEFS:
            self.system.write_login_defs(data)
        else:
            self.system.write_useradd_defaults(data)

    def apply(self, params):
        state = json.loads(self.read_state(params))
        edited = self._edited(state['default'])
        if edited != state['default']:
            self._write_default(edited)
        for name in self._changes(state):
            self.system.chage(name, self.spec['flag'], self.spec['target'])

    def restore(self, params, before):
        state, current = json.loads(before), json.loads(self.read_state(params))
        if current['default'] != state['default']:
            self._write_default(state['default'])
        for name, row in sorted(state['accounts'].items()):
            if name not in current['accounts']:
                raise ValueError('An account in the recorded state no longer exists')
            if current['accounts'][name]['value'] != row['value']:
                self.system.chage(name, self.spec['flag'], row['value'])


class LinuxAgingIO:
    """Mixin: bounded passwd/shadow/login.defs/useradd reads; atomic writes of the two default files; fixed chage argv."""

    def account_records(self):
        read = lambda path: self.io._bytes(Path(path), 4 * 1024 * 1024).decode('utf-8')
        return parse_accounts(read('/etc/passwd'), read('/etc/shadow'))

    def today(self):
        return int(time.time() // 86400)

    def login_defs(self):
        return self.io._bytes(Path(LOGIN_DEFS), 1024 * 1024)

    def useradd_defaults(self):
        return self.io._bytes(Path(USERADD), 1024 * 1024) if Path(USERADD).exists() else None

    def _replace(self, path, content):
        target = Path(path)
        if target.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        mode, gid = 0o644, 0
        if target.exists():
            info = target.stat()
            mode, gid = info.st_mode & 0o777, info.st_gid
        tmp = target.with_name('.' + target.name + '.fyp-tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), mode)
        try:
            os.write(fd, content)
            os.fchown(fd, 0, gid)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)

    def write_login_defs(self, content):
        if content is None:
            raise ValueError('login.defs is never removed')
        self._replace(LOGIN_DEFS, content)

    def write_useradd_defaults(self, content):
        if content is None:
            target = Path(USERADD)
            if target.is_symlink():
                raise ValueError('Managed files must not be symlinks')
            if target.exists():
                target.unlink()
            return
        self._replace(USERADD, content)

    def chage(self, name, flag, value):
        if flag not in ('--maxdays', '--warndays', '--inactive') or type(value) is not int or not -1 <= value <= 99999:
            raise ValueError('Unregistered chage change')
        if not re.fullmatch(r'[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,127}', name):
            raise ValueError('Unsupported account name')
        result = self.io._run(('/usr/bin/chage', flag, str(value), '--', name), 20)
        if result.returncode != 0:
            raise OSError('chage refused the change (exit status %d)' % result.returncode)
