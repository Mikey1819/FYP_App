"""Core-dump remediation family for CIS 1.5.3 (printed pp.159-161). Python 3.10, standard library only.

Three managed parts, no other file edited:
- `* hard core 0` in /etc/security/limits.d/60-fyp-hardening-cis.conf;
- fs.suid_dumpable = 0 persisted (shared managed sysctl drop-in) and at runtime;
- only when systemd-coredump is installed: Storage=none and ProcessSizeMax=0 in the drop-in
  /etc/systemd/coredump.conf.d/60-fyp-hardening-cis.conf (overrides coredump.conf without editing it).
Not eligible when another source would keep the control failing: a non-zero hard core limit for any other
domain, a later '*' limit, a later coredump drop-in or a later sysctl source with another value.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
from .family_sysctl import HEADER, SysctlFamily

ACTION_ID = 'ubuntu.1.5.3.v1'
LIMITS_MANAGED = '/etc/security/limits.d/60-fyp-hardening-cis.conf'
COREDUMP_MANAGED = '/etc/systemd/coredump.conf.d/60-fyp-hardening-cis.conf'
LIMITS_CONTENT = HEADER + b'*\thard\tcore\t0\n'
COREDUMP_CONTENT = HEADER + b'[Coredump]\nStorage=none\nProcessSizeMax=0\n'
SYSCTL_PARAMS = {'keys': {'fs.suid_dumpable': 0}}
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_core.py').read_bytes()
                                       + (_HERE / 'family_sysctl.py').read_bytes()).hexdigest()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _hard_core(data):
    """(domain, value) for each hard core limit line; 'unlimited' is -1."""
    rows = []
    for line in data.decode('utf-8').splitlines():
        tokens = shlex.split(line, comments=True)
        if len(tokens) == 4 and tokens[1] in ('hard', '-') and tokens[2] == 'core':
            rows.append((tokens[0], -1 if tokens[3] == 'unlimited' else int(tokens[3])))
    return rows


def _coredump_values(data):
    values, section = {}, None
    for raw in data.decode('utf-8').splitlines():
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if line.startswith('['):
            section = line
            continue
        if section == '[Coredump]' and '=' in line:
            key, value = (part.strip() for part in line.split('=', 1))
            values[key] = value
    return values


class CoreDumpFamily:
    action_id = ACTION_ID
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60

    def __init__(self, system):
        self.system = system
        self.sysctl = SysctlFamily('1.5.3', system)

    def validate(self, params):
        if (type(params) is not dict or set(params) != {'sysctl', 'limits', 'coredump'} or params['limits'] is not True
                or type(params['coredump']) is not bool):
            raise ValueError('Invalid core-dump family parameters')
        self.sysctl.validate(params['sysctl'])
        if params['sysctl'] != SYSCTL_PARAMS:
            raise ValueError('Only fs.suid_dumpable = 0 is managed')

    @staticmethod
    def _managed(files, path):
        data = dict(files).get(path)
        if data is not None and not data.startswith(HEADER):
            raise ValueError('A managed core-dump file holds content this family did not write')
        return data

    def read_state(self, params):
        limits = self.system.limits_files()
        self._managed(limits, LIMITS_MANAGED)
        state = {'sysctl': self.sysctl.read_state(params['sysctl']).decode('utf-8'),
                 'limits': {path: _sha(data) for path, data in limits},
                 'limits_managed': (dict(limits).get(LIMITS_MANAGED) or b'').decode('utf-8') or None,
                 'coredump': None, 'coredump_managed': None}
        if params['coredump']:
            coredump = self.system.coredump_files()
            self._managed(coredump, COREDUMP_MANAGED)
            state['coredump'] = {path: _sha(data) for path, data in coredump}
            state['coredump_managed'] = (dict(coredump).get(COREDUMP_MANAGED) or b'').decode('utf-8') or None
        return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def expected_after(self, params, before):
        state = json.loads(before)
        state['sysctl'] = self.sysctl.expected_after(params['sysctl'], state['sysctl'].encode('utf-8')).decode('utf-8')
        state['limits'][LIMITS_MANAGED] = _sha(LIMITS_CONTENT)
        state['limits_managed'] = LIMITS_CONTENT.decode('utf-8')
        if params['coredump']:
            state['coredump'][COREDUMP_MANAGED] = _sha(COREDUMP_CONTENT)
            state['coredump_managed'] = COREDUMP_CONTENT.decode('utf-8')
        return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def check_eligible(self, params):
        self.sysctl.check_eligible(params['sysctl'])
        managed_name = LIMITS_MANAGED.rsplit('/', 1)[1]
        for path, data in self.system.limits_files():
            if path == LIMITS_MANAGED:
                continue
            later = path != '/etc/security/limits.conf' and path.rsplit('/', 1)[1] > managed_name
            for domain, value in _hard_core(data):
                if value != 0 and (domain != '*' or later):
                    raise ValueError('Another hard core limit would keep core dumps allowed')
        if params['coredump']:
            name = COREDUMP_MANAGED.rsplit('/', 1)[1]
            for path, data in self.system.coredump_files():
                if path == COREDUMP_MANAGED or path == '/etc/systemd/coredump.conf' or path.rsplit('/', 1)[1] <= name:
                    continue
                values = _coredump_values(data)
                if values.get('Storage', 'none') != 'none' or values.get('ProcessSizeMax', '0') != '0':
                    raise ValueError('A later coredump drop-in overrides the managed values')

    def summary(self, params, before):
        state = json.loads(before)
        return {'limits_file': LIMITS_MANAGED, 'coredump_file': COREDUMP_MANAGED if params['coredump'] else None,
                'sysctl': self.sysctl.summary(params['sysctl'], state['sysctl'].encode('utf-8'))['keys']}

    def apply(self, params):
        self.sysctl.apply(params['sysctl'])
        self.system.write_file(LIMITS_MANAGED, LIMITS_CONTENT)
        if params['coredump']:
            self.system.write_file(COREDUMP_MANAGED, COREDUMP_CONTENT)

    def restore(self, params, before):
        state = json.loads(before)
        self.sysctl.restore(params['sysctl'], state['sysctl'].encode('utf-8'))
        for path, key, needed in ((LIMITS_MANAGED, 'limits_managed', True),
                                  (COREDUMP_MANAGED, 'coredump_managed', params['coredump'])):
            if not needed:
                continue
            if state[key] is None:
                self.system.remove_file(path)
            else:
                self.system.write_file(path, state[key].encode('utf-8'))


class LinuxCoreDumpIO:
    """Mixin for LinuxSysctlSystem: bounded reads of limits/coredump sources, writes to the two managed files only."""
    COREDUMP_DIRS = ('/etc/systemd/coredump.conf.d', '/run/systemd/coredump.conf.d',
                     '/usr/local/lib/systemd/coredump.conf.d', '/usr/lib/systemd/coredump.conf.d')

    def _bounded_files(self, main, directories):
        found = []
        if Path(main).exists():
            found.append((main, self.io._bytes(Path(main), 1024 * 1024)))
        for directory in directories:
            folder = Path(directory)
            if not folder.is_dir():
                continue
            for path in sorted(folder.glob('*.conf'))[:256]:
                found.append((str(path), self.io._bytes(path, 1024 * 1024)))
        return found

    def limits_files(self):
        return self._bounded_files('/etc/security/limits.conf', ('/etc/security/limits.d',))

    def coredump_files(self):
        files = self._bounded_files('/etc/systemd/coredump.conf', self.COREDUMP_DIRS)
        return files[:1] + sorted(files[1:], key=lambda row: row[0].rsplit('/', 1)[1])

    def write_file(self, path, content):
        if path not in (LIMITS_MANAGED, COREDUMP_MANAGED):
            raise ValueError('Unregistered managed file')
        target = Path(path)
        target.parent.mkdir(mode=0o755, exist_ok=True)
        if target.is_symlink() or target.parent.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        tmp = target.with_name('.' + target.name + '.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)

    def remove_file(self, path):
        if path not in (LIMITS_MANAGED, COREDUMP_MANAGED):
            raise ValueError('Unregistered managed file')
        target = Path(path)
        if target.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        if target.exists():
            target.unlink()
