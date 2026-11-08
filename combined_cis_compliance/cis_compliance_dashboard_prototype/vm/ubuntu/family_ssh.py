"""SSH server families for CIS 5.1.7, 5.1.10, 5.1.16, 5.1.19, 5.1.20 and 5.1.21. Python 3.10, stdlib only.

CIS allows the setting "in a file in Include location" when the order of precedence is understood. sshd keeps
the FIRST value it obtains; Ubuntu's sshd_config expands `Include /etc/ssh/sshd_config.d/*.conf` in place, drop-ins
in lexical order. The family therefore writes only /etc/ssh/sshd_config.d/00-fyp-hardening-cis.conf and refuses
whenever that file might not decide the value: a Match block, any other Include, no Include, an earlier main-file
line or earlier drop-in setting the same key, foreign content in the managed file, or an already invalid config.
Each control owns only its own keys in the shared file. Writes are validated with `sshd -t`, then sshd is
reloaded (existing sessions survive); any failure puts the previous file back. Every change is a commit-confirm
job: unless a fresh SSH login confirms it within the window, the rollback timer restores the before-state.
"""
import hashlib
import json
import os
from pathlib import Path
from .family_sysctl import HEADER

MANAGED = '/etc/ssh/sshd_config.d/00-fyp-hardening-cis.conf'
NAME = MANAGED.rsplit('/', 1)[1]
INCLUDE = '/etc/ssh/sshd_config.d/*.conf'
SETTINGS = {
    '5.1.7': {'ClientAliveInterval': '15', 'ClientAliveCountMax': '3'},
    '5.1.10': {'HostbasedAuthentication': 'no'},
    '5.1.16': {'MaxAuthTries': '4'},
    '5.1.19': {'PermitEmptyPasswords': 'no'},
    '5.1.20': {'PermitRootLogin': 'no'},
    '5.1.21': {'PermitUserEnvironment': 'no'},
}
ORDER = sorted({key for settings in SETTINGS.values() for key in settings})
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_ssh.py').read_bytes()).hexdigest()


def _tokens(line):
    return line.split('#', 1)[0].split()


def managed_entries(data):
    """Key -> value from the managed file; anything this family did not write is refused."""
    if data is None:
        return {}
    if not data.startswith(HEADER):
        raise ValueError('The managed sshd drop-in holds content this family did not write')
    entries = {}
    for line in data[len(HEADER):].decode('utf-8').splitlines():
        tokens = _tokens(line)
        if not tokens:
            continue
        if len(tokens) != 2 or tokens[0] not in ORDER or tokens[0] in entries:
            raise ValueError('The managed sshd drop-in holds content this family did not write')
        entries[tokens[0]] = tokens[1]
    return entries


def render(entries):
    if not entries:
        return None
    return HEADER + ''.join('%s %s\n' % (key, entries[key]) for key in ORDER if key in entries).encode('ascii')


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class SshFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 120
    supervision, confirm_seconds = 'confirm', 600

    def __init__(self, control_id, system):
        self.control_id, self.settings, self.system = control_id, SETTINGS[control_id], system
        self.action_id = 'ubuntu.%s.v1' % control_id

    def validate(self, params):
        if type(params) is not dict or set(params) != {'settings'} or params['settings'] != self.settings:
            raise ValueError('Only the CIS values for this control are managed')

    def _managed(self):
        _, dropins = self.system.sshd_sources()
        return managed_entries(dict(dropins).get(NAME))

    def read_state(self, params):
        entries, effective = self._managed(), self.system.effective()
        return _dump({'entries': {key: entries.get(key) for key in self.settings},
                      'effective': {key.lower(): effective.get(key.lower()) for key in self.settings}})

    def expected_after(self, params, before):
        state = json.loads(before)
        state['entries'] = dict(self.settings)
        state['effective'] = {key.lower(): value.lower() for key, value in self.settings.items()}
        return _dump(state)

    def check_eligible(self, params):
        main, dropins = self.system.sshd_sources()
        self._managed()
        keys = {key.lower() for key in self.settings}
        before_include, includes = True, 0
        for line in main.decode('utf-8').splitlines():
            tokens = _tokens(line)
            if not tokens:
                continue
            word = tokens[0].lower()
            if word == 'match':
                raise ValueError('Match blocks are not modelled; set these values by hand')
            if word == 'include':
                if tokens[1:] != [INCLUDE]:
                    raise ValueError('Only the standard sshd_config.d Include is modelled')
                includes += 1
                before_include = False
            elif before_include and word in keys:
                raise ValueError('sshd_config sets this option before the Include, so it would win')
        if includes != 1:
            raise ValueError('sshd_config must include sshd_config.d exactly once for the drop-in to apply')
        for name, data in dropins:
            for line in data.decode('utf-8').splitlines():
                tokens = _tokens(line)
                if not tokens:
                    continue
                if tokens[0].lower() in ('match', 'include'):
                    raise ValueError('Match or Include in a drop-in is not modelled')
                if name < NAME and tokens[0].lower() in keys:
                    raise ValueError('An earlier drop-in sets this option, so it would win')

    def summary(self, params, before):
        state = json.loads(before)
        return {'managed_file': MANAGED, 'settings': self.settings, 'current_effective': state['effective'],
                'confirm_window_seconds': self.confirm_seconds,
                'after_apply': 'Disconnect and reconnect within 10 minutes, then confirm; otherwise the change '
                               'is rolled back automatically.'}

    def _write(self, entries):
        self.system.write_sshd_dropin(render(entries))

    def apply(self, params):
        entries = self._managed()
        entries.update(self.settings)
        self._write(entries)

    def restore(self, params, before):
        state, entries = json.loads(before), self._managed()
        for key in self.settings:
            if state['entries'][key] is None:
                entries.pop(key, None)
            else:
                entries[key] = state['entries'][key]
        self._write(entries)


class LinuxSshIO:
    """Mixin: bounded reads of sshd sources, `sshd -T`/`-t`, writes to the one managed drop-in, `systemctl reload`."""

    def sshd_sources(self):
        main = self.io._bytes(Path('/etc/ssh/sshd_config'), 1024 * 1024)
        folder, dropins = Path('/etc/ssh/sshd_config.d'), []
        if folder.is_dir():
            for path in sorted(folder.glob('*.conf'))[:256]:
                dropins.append((path.name, self.io._bytes(path, 1024 * 1024)))
        return main, dropins

    def effective(self):
        result = self.io._run(('/usr/sbin/sshd', '-T'), 20)
        if result.returncode != 0:
            raise ValueError('sshd -T failed; the configuration is not valid')
        values = {}
        for line in result.stdout.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                values.setdefault(parts[0].lower(), parts[1].strip().lower())
        return values

    def _sshd_ok(self, argv, seconds):
        return self.io._run(argv, seconds).returncode == 0

    def _put_sshd_dropin(self, content):
        target = Path(MANAGED)
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        if content is None:
            if target.exists():
                target.unlink()
            return
        tmp = target.with_name('.' + NAME + '.tmp')  # not *.conf: never read by sshd
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)

    def write_sshd_dropin(self, content):
        target = Path(MANAGED)
        previous = target.read_bytes() if target.exists() and not target.is_symlink() else None
        self._put_sshd_dropin(content)
        if not self._sshd_ok(('/usr/sbin/sshd', '-t'), 20):
            self._put_sshd_dropin(previous)
            raise OSError('sshd -t rejected the configuration; the previous file was put back')
        if not self._sshd_ok(('/usr/bin/systemctl', 'reload', 'ssh.service'), 30):
            self._put_sshd_dropin(previous)
            self._sshd_ok(('/usr/bin/systemctl', 'reload', 'ssh.service'), 30)
            raise OSError('sshd reload failed; the previous file was put back')
