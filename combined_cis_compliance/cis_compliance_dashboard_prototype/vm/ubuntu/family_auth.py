"""Sudo defaults (CIS 5.2.2 use_pty, 5.2.3 logfile) and password minimum length (CIS 5.3.3.2.2) families. Python 3.10, stdlib only.

5.2.2 `Defaults use_pty` and 5.2.3 `Defaults logfile="/var/log/sudo.log"` (approved site path) share
/etc/sudoers.d/60-fyp-hardening-cis, one line per control; each control's state and restore cover only its line,
and an empty file is removed. The file is staged under a dotted name that sudo ignores, checked with
`visudo -cf`, installed, and the whole configuration is checked with `visudo -c`; a failure removes it at once.
Nothing else is edited.
5.3.3.2.2: `minlen = 14` in /etc/security/pwquality.conf.d/60-fyp-hardening-cis.conf. Eligibility runs the
collector's own resolver on the simulated after-state, so a PAM argument, pwquality.conf or a later drop-in
that would still win makes it refuse. Existing passwords are never changed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
from .family_sysctl import HEADER
from .probes import password_minlen

SUDO_MANAGED = '/etc/sudoers.d/60-fyp-hardening-cis'
SUDO_STAGED = '/etc/sudoers.d/.60-fyp-hardening-cis.tmp'  # contains '.', so sudo never reads it
PWQ_MANAGED = '/etc/security/pwquality.conf.d/60-fyp-hardening-cis.conf'
SUDO_LOGFILE = '/var/log/sudo.log'  # approved site policy (blanket approval 2026-11-06)
SUDO_LINES = {'5.2.2': 'Defaults use_pty', '5.2.3': 'Defaults logfile="%s"' % SUDO_LOGFILE}
SUDO_PARAMS = {'5.2.2': {'use_pty': True}, '5.2.3': {'logfile': SUDO_LOGFILE}}
SUDO_NEGATION = {'5.2.2': '!use_pty', '5.2.3': '!logfile'}
PWQ_CONTENT = HEADER + b'minlen = 14\n'
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_auth.py').read_bytes()
                                       + (_HERE / 'probes.py').read_bytes()).hexdigest()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sudo_lines(data):
    """Control IDs whose line is in the managed sudoers file; content this family did not write is refused."""
    if data is None:
        return set()
    if not data.startswith(HEADER):
        raise ValueError('The managed sudoers file holds content this family did not write')
    owners = {line: cid for cid, line in SUDO_LINES.items()}
    found = set()
    for line in data[len(HEADER):].decode('utf-8').splitlines():
        if not line.strip():
            continue
        if line not in owners or owners[line] in found:
            raise ValueError('The managed sudoers file holds content this family did not write')
        found.add(owners[line])
    return found


def sudo_render(controls):
    if not controls:
        return None
    return HEADER + ''.join(SUDO_LINES[c] + '\n' for c in sorted(SUDO_LINES) if c in controls).encode('ascii')


class SudoDefaultsFamily:
    """One `Defaults` line per control in /etc/sudoers.d/60-fyp-hardening-cis (5.2.2 use_pty, 5.2.3 logfile)."""
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60

    def __init__(self, control_id, system):
        self.control_id, self.system = control_id, system
        self.action_id = 'ubuntu.%s.v1' % control_id

    def validate(self, params):
        if type(params) is not dict or _dump(params) != _dump(SUDO_PARAMS[self.control_id]):
            raise ValueError('Only the approved sudo default for this control is managed')

    def _sources(self):
        sources = self.system.sudo_sources()
        return sources, sudo_lines(dict(sources).get(SUDO_MANAGED))

    def read_state(self, params):
        sources, controls = self._sources()
        return _dump({'sources': {path: _sha(data) for path, data in sources if path != SUDO_MANAGED},
                      'line': self.control_id in controls})

    def expected_after(self, params, before):
        state = json.loads(before)
        state['line'] = True
        return _dump(state)

    def check_eligible(self, params):
        sources, _ = self._sources()
        negation = SUDO_NEGATION[self.control_id]
        for path, data in sources:
            for line in data.decode('utf-8').splitlines():
                stripped = line.strip()
                if re.match(r'^[@#]include', stripped):
                    if path == '/etc/sudoers' and stripped in ('@includedir /etc/sudoers.d', '#includedir /etc/sudoers.d'):
                        continue
                    raise ValueError('Unsupported sudo include')
                if stripped.startswith('Defaults') and negation in ''.join(shlex.split(stripped, comments=True)):
                    raise ValueError('A sudo source negates this default')

    def summary(self, params, before):
        return {'managed_file': SUDO_MANAGED, 'line': SUDO_LINES[self.control_id],
                'validation': 'visudo -cf, then visudo -c'}

    def _write(self, controls):
        content = sudo_render(controls)
        if content is None:
            self.system.remove_sudo_managed()
        else:
            self.system.write_sudo_managed(content)

    def apply(self, params):
        _, controls = self._sources()
        self._write(controls | {self.control_id})

    def restore(self, params, before):
        _, controls = self._sources()
        wanted = (controls | {self.control_id}) if json.loads(before)['line'] else (controls - {self.control_id})
        self._write(wanted)


class SudoLogfileFamily(SudoDefaultsFamily):
    def __init__(self, system):
        super().__init__('5.2.3', system)


class SudoUsePtyFamily(SudoDefaultsFamily):
    def __init__(self, system):
        super().__init__('5.2.2', system)


class PasswordMinlenFamily:
    action_id = 'ubuntu.5.3.3.2.2.v1'
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60

    def __init__(self, system):
        self.system = system

    def validate(self, params):
        if type(params) is not dict or set(params) != {'minlen'} or type(params['minlen']) is not int or params['minlen'] != 14:
            raise ValueError('Only minlen = 14 is managed')

    def _sources(self):
        main, dropins, pam = self.system.pwquality_sources()
        name = PWQ_MANAGED.rsplit('/', 1)[1]
        managed = dict(dropins).get(name)
        if managed is not None and not managed.startswith(HEADER):
            raise ValueError('The managed pwquality file holds content this family did not write')
        return main, dropins, pam, managed

    def read_state(self, params):
        main, dropins, pam, managed = self._sources()
        return _dump({'main': _sha(main), 'dropins': {n: _sha(d) for n, d in dropins}, 'pam': _sha(pam),
                      'managed': managed.decode('utf-8') if managed is not None else None})

    def expected_after(self, params, before):
        state = json.loads(before)
        state['dropins'][PWQ_MANAGED.rsplit('/', 1)[1]] = _sha(PWQ_CONTENT)
        state['managed'] = PWQ_CONTENT.decode('utf-8')
        return _dump(state)

    def check_eligible(self, params):
        main, dropins, pam, _ = self._sources()
        name = PWQ_MANAGED.rsplit('/', 1)[1]
        after = [(n, d.decode('utf-8')) for n, d in dropins if n != name] + [(name, PWQ_CONTENT.decode('utf-8'))]
        if password_minlen(after, main.decode('utf-8'), pam.decode('utf-8')) < params['minlen']:
            raise ValueError('A PAM argument, pwquality.conf or a later drop-in would keep minlen below 14')

    def summary(self, params, before):
        return {'managed_file': PWQ_MANAGED, 'minlen': params['minlen'], 'existing_passwords': 'unchanged'}

    def apply(self, params):
        self.system.write_pwquality_managed(PWQ_CONTENT)

    def restore(self, params, before):
        state = json.loads(before)
        if state['managed'] is None:
            self.system.remove_pwquality_managed()
        else:
            self.system.write_pwquality_managed(state['managed'].encode('utf-8'))


class LinuxAuthIO:
    """Mixin: bounded sudoers/pwquality reads; writes only the two managed files (unvalidated on the VM)."""

    def sudo_sources(self):
        sources = [('/etc/sudoers', self.io._bytes(Path('/etc/sudoers'), 1024 * 1024))]
        folder = Path('/etc/sudoers.d')
        if folder.is_dir():
            names = sorted(p.name for p in folder.iterdir() if '.' not in p.name and not p.name.endswith('~'))
            for name in names[:256]:
                sources.append(('/etc/sudoers.d/' + name, self.io._bytes(folder / name, 1024 * 1024)))
        return sources

    def _visudo(self, *args):
        result = self.io._run(('/usr/sbin/visudo',) + args, 20)
        return result.returncode == 0

    def _write(self, path, content, mode):
        target = Path(path)
        if target.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), mode)
        try:
            os.write(fd, content)
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)

    def write_sudo_managed(self, content):
        self._write(SUDO_STAGED, content, 0o440)
        if not self._visudo('-cf', SUDO_STAGED):
            os.unlink(SUDO_STAGED)
            raise OSError('visudo rejected the staged sudoers file; nothing was installed')
        os.replace(SUDO_STAGED, SUDO_MANAGED)
        if not self._visudo('-c'):
            os.unlink(SUDO_MANAGED)
            raise OSError('The full sudo configuration failed validation; the managed file was removed')

    def remove_sudo_managed(self):
        target = Path(SUDO_MANAGED)
        if target.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        if target.exists():
            target.unlink()
        if not self._visudo('-c'):
            raise OSError('The sudo configuration failed validation after removal')

    def pwquality_sources(self):
        main = Path('/etc/security/pwquality.conf')
        main_bytes = self.io._bytes(main, 1024 * 1024) if main.exists() else b''
        folder, dropins = Path('/etc/security/pwquality.conf.d'), []
        if folder.is_dir():
            for path in sorted(folder.glob('*.conf'))[:256]:
                dropins.append((path.name, self.io._bytes(path, 1024 * 1024)))
        return main_bytes, dropins, self.io._bytes(Path('/etc/pam.d/common-password'), 1024 * 1024)

    def write_pwquality_managed(self, content):
        folder = Path(PWQ_MANAGED).parent
        folder.mkdir(mode=0o755, exist_ok=True)
        tmp = folder / ('.' + Path(PWQ_MANAGED).name + '.tmp')
        self._write(str(tmp), content, 0o644)
        os.replace(tmp, PWQ_MANAGED)

    def remove_pwquality_managed(self):
        target = Path(PWQ_MANAGED)
        if target.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        if target.exists():
            target.unlink()
