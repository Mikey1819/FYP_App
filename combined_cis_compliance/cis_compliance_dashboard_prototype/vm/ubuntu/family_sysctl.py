"""Sysctl remediation family for CIS 1.5.1, 3.3.1, 3.3.2 and 3.3.8. Python 3.10, standard library only.

Writes exactly the benchmark keys to one managed drop-in, /etc/sysctl.d/60-fyp-hardening-cis.conf, and
sets the same keys at runtime with fixed `sysctl -w key=value` argument lists. No other file is edited.
A request is not eligible when a canonically later sysctl source or UFW's sysctl file would set one of
the keys to another value (the benchmark warns later files override earlier ones), or when the managed
file holds content this family did not write. The runner keeps the exact before-state for recovery.
The drop-in is shared by several controls (and 1.5.3's fs.suid_dumpable), so each control's state covers only
its own keys in it (administrator request 2026-11-11): a fix on another key never makes it stale, the fixes can be
approved and executed together, and a restore puts back only this control's keys (the file goes when none is left).
"""
import hashlib
import json
import os
from pathlib import Path
import re
from .spec import SYSCTL

MANAGED = '/etc/sysctl.d/60-fyp-hardening-cis.conf'
HEADER = b'# Managed by FYP hardening (CIS Ubuntu 22.04). Exact keys only; changes are detected.\n'
REQUIRED = dict(SYSCTL)
SUBPART = {'1.5.3': {'fs.suid_dumpable': 0}}  # used inside the core-dump family only
ALL_KEYS = frozenset(k for keys in list(REQUIRED.values()) + list(SUBPART.values()) for k in keys)
IMPLEMENTATION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
SYSCTL_DIRS = ('/etc/sysctl.d/', '/run/sysctl.d/', '/usr/local/lib/sysctl.d/', '/usr/lib/sysctl.d/', '/lib/sysctl.d/')


def parse_conf(data):
    """sysctl.d syntax: comments (#, ;), optional leading '-', '/' or '.' separators; the last value wins."""
    return parse_entries(data)[0]


def parse_entries(data):
    """(values, excluded): settings by key (globs kept as written) and '-key' glob exclusions."""
    values, excluded = {}, set()
    for raw in data.decode('utf-8').splitlines():
        line = raw.strip()
        if not line or line[0] in '#;':
            continue
        if '=' not in line:
            if line.startswith('-'):
                excluded.add(line.lstrip('-').strip().replace('/', '.'))  # e.g. Ubuntu 50-default.conf
                continue
            raise ValueError('Unparseable sysctl setting')
        key, value = (part.strip() for part in line.split('=', 1))
        key = key.lstrip('-').strip().replace('/', '.')
        if not re.fullmatch(r'[a-z0-9_.*-]{1,128}', key):
            raise ValueError('Unsupported sysctl key syntax')
        values[key] = value
    return values, excluded


def _conflicts(data, wanted):
    import fnmatch
    values, excluded = parse_entries(data) if data is not None else ({}, set())
    for key, value in wanted.items():
        if key in values and values[key] != value:
            return True
        if key not in excluded and any(any(c in g for c in '*?[]') and fnmatch.fnmatchcase(key, g) and v != value
                                       for g, v in values.items()):
            return True
    return False


def validate_params(control_id, params):
    """Exactly {'keys': {key: required value}}; a planner may omit only IPv6 keys (when IPv6 is disabled)."""
    required = REQUIRED.get(control_id) or SUBPART.get(control_id)
    if required is None or type(params) is not dict or set(params) != {'keys'} or type(params['keys']) is not dict:
        raise ValueError('Invalid sysctl family parameters')
    keys = params['keys']
    if not keys or not set(keys) <= set(required) or any(type(v) is not int or v != required[k] for k, v in keys.items()):
        raise ValueError('Parameters must be the benchmark keys and values for this control')
    if any(k not in keys and '.ipv6.' not in k for k in required):
        raise ValueError('Only IPv6 keys may be omitted')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


class SysctlFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60

    def __init__(self, control_id, system):
        if control_id not in REQUIRED and control_id not in SUBPART:
            raise ValueError('Not a sysctl control')
        self.control_id, self.system = control_id, system
        self.action_id = 'ubuntu.' + control_id + '.v1'

    def validate(self, params):
        validate_params(self.control_id, params)

    def _managed(self):
        data = self.system.read_config(MANAGED)
        if data is None:
            return None, {}
        values = parse_conf(data)
        if not data.startswith(HEADER) or not set(values) <= ALL_KEYS:
            raise ValueError('Managed sysctl file holds content this family did not write')
        return data, values

    @staticmethod
    def _render(values):
        return HEADER + b''.join(('%s = %s\n' % (k, values[k])).encode('ascii') for k in sorted(values))

    def _content(self, params):
        _, values = self._managed()
        return self._render(dict(values, **{k: str(v) for k, v in params['keys'].items()}))

    @staticmethod
    def _own(data, keys):
        """This control's part of the shared drop-in: its keys' values (None when absent). Content this family did
        not write is kept as a digest, so it still changes the state (and check_eligible refuses it)."""
        if data is None:
            return {'keys': {k: None for k in sorted(keys)}}
        try:
            values = parse_conf(data)
        except (ValueError, UnicodeDecodeError):
            return {'foreign': _sha(data)}
        if not data.startswith(HEADER) or not set(values) <= ALL_KEYS:
            return {'foreign': _sha(data)}
        return {'keys': {k: values.get(k) for k in sorted(keys)}}

    def read_state(self, params):
        config = {}
        for path in self.system.config_paths():
            if path == MANAGED:
                continue  # shared by other controls: only this control's keys in it count (below)
            data = self.system.read_config(path)
            config[path] = _sha(data) if data is not None else 'missing'
        ufw_path = self.system.ufw_sysctl_path()
        ufw = self.system.read_config(ufw_path) if ufw_path else None
        state = {'config': config, 'managed': self._own(self.system.read_config(MANAGED), params['keys']),
                 'ufw': _sha(ufw) if ufw is not None else None,
                 'runtime': {k: self.system.runtime(k) for k in sorted(params['keys'])}}
        return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def expected_after(self, params, before):
        state = json.loads(before)
        state['managed'] = {'keys': {k: str(params['keys'][k]) for k in sorted(params['keys'])}}
        state['runtime'] = {k: params['keys'][k] for k in sorted(params['keys'])}
        return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')

    def check_eligible(self, params):
        """Refuse when another source would override the managed values (load order is by file name)."""
        self._managed()
        managed_name = MANAGED.rsplit('/', 1)[1]
        wanted = {k: str(v) for k, v in params['keys'].items()}
        for path in self.system.config_paths():
            name = path.rsplit('/', 1)[1]
            if path == MANAGED or name <= managed_name:
                continue  # earlier sources are superseded by the managed file
            if _conflicts(self.system.read_config(path), wanted):
                raise ValueError('A later sysctl source sets one of these keys to another value')
        ufw_path = self.system.ufw_sysctl_path()
        if ufw_path and _conflicts(self.system.read_config(ufw_path), wanted):
            raise ValueError("UFW's sysctl file sets one of these keys to another value")

    def summary(self, params, before):
        state = json.loads(before)
        return {'managed_file': MANAGED, 'keys': [{'key': k, 'runtime': state['runtime'][k], 'proposed': v}
                                                  for k, v in sorted(params['keys'].items())]}

    def apply(self, params):
        self.system.write_managed(self._content(params))
        for key in sorted(params['keys']):
            self.system.set_runtime(key, params['keys'][key])

    def restore(self, params, before):
        """Approved recovery only: this control's keys in the managed file (absent ones removed, the file removed when
        no key is left) and their runtime values, as recorded before. Other controls' keys stay as they are now.
        A before-state recorded by the earlier whole-file version is put back whole, as that version did."""
        state = json.loads(before)
        recorded = state['managed']
        if isinstance(recorded, dict) and 'keys' in recorded:
            _, values = self._managed()
            for key, value in recorded['keys'].items():
                if value is None:
                    values.pop(key, None)
                else:
                    values[key] = value
            if values:
                self.system.write_managed(self._render(values))
            else:
                self.system.remove_managed()
        elif recorded is None:
            self.system.remove_managed()
        else:
            self.system.write_managed(recorded.encode('utf-8'))
        for key in sorted(params['keys']):
            self.system.set_runtime(key, state['runtime'][key])


class LinuxSysctlSystem:
    """Fixed, bounded target I/O for the sysctl family; requires a preflighted FixedProbeIO. Unvalidated on the VM."""

    def __init__(self, io):
        if getattr(io, '_verified', False) is not True:
            raise ValueError('Verified target preflight is required')
        self.io = io

    def config_paths(self):
        output = self.io.command('sysctl_config')
        if output.returncode != 0:
            raise OSError('systemd-sysctl --cat-config failed')
        paths = re.findall(r'^# (/\S+\.conf)$', output.stdout, re.M)
        if not paths or any(not p.startswith(SYSCTL_DIRS) and p != '/etc/sysctl.conf' for p in paths):
            raise ValueError('Unexpected sysctl source list')
        return paths

    def read_config(self, path):
        allowed = path.startswith(SYSCTL_DIRS) and path.endswith('.conf')
        if not allowed and path not in ('/etc/sysctl.conf', '/etc/ufw/sysctl.conf'):
            raise ValueError('Unregistered sysctl source')
        target = Path(path)
        if not target.exists() and not target.is_symlink():
            return None
        if target.is_symlink():  # Ubuntu ships 99-sysctl.conf -> ../sysctl.conf
            if path != '/etc/sysctl.d/99-sysctl.conf' or str(target.resolve()) != '/etc/sysctl.conf':
                raise ValueError('Unsupported sysctl source symlink')
            target = Path('/etc/sysctl.conf')
        return self.io._bytes(target, 1024 * 1024)

    def ufw_sysctl_path(self):
        try:
            defaults = self.io.read_file('/etc/default/ufw')
        except FileNotFoundError:
            return None
        found = [line.split('=', 1)[1].strip().strip('"') for line in defaults.splitlines()
                 if re.match(r'^\s*IPT_SYSCTL\s*=', line)]
        if not found:
            return None
        if found != ['/etc/ufw/sysctl.conf']:
            raise ValueError('Unsupported UFW sysctl source')
        return found[0]

    def runtime(self, key):
        if key not in ALL_KEYS:
            raise ValueError('Unregistered sysctl key')
        output = self.io.command('sysctl.' + key)
        if output.returncode != 0:
            raise OSError('sysctl read failed')
        return int(output.stdout.strip())

    def write_managed(self, content):
        target = Path(MANAGED)
        if target.is_symlink():
            raise ValueError('Managed sysctl file must not be a symlink')
        tmp = target.with_name('.' + target.name + '.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)

    def remove_managed(self):
        target = Path(MANAGED)
        if target.is_symlink():
            raise ValueError('Managed sysctl file must not be a symlink')
        if target.exists():
            target.unlink()

    def set_runtime(self, key, value):
        if key not in ALL_KEYS or type(value) is not int:
            raise ValueError('Unregistered sysctl write')
        result = self.io._run(('/usr/sbin/sysctl', '-w', '%s=%d' % (key, value)), 20)
        if result.returncode != 0:
            raise OSError('sysctl -w failed')
