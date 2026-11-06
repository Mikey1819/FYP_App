"""Audit-rule families for CIS 6.3.3.4 (time change), 6.3.3.6 (privileged commands) and 6.3.3.8 (identity).

Python 3.10, stdlib only. Each control writes its own file in /etc/audit/rules.d with the exact CIS rule text,
then `augenrules --load`; a failed load puts the previous file back. 6.3.3.6 uses the privileged-binary inventory
and UID_MIN from the assessed evidence, and the target re-checks every path is still a setuid/setgid file.
Refused when auditd is not installed, the configuration is locked (`enabled 2`: augenrules would silently not
load), another file sets `-e 2` (a restore could then only take effect after a reboot), a later file contains
`-D` (it would delete these rules) or any rule cannot be parsed by the collector (suppressions, unknown filters).
State is the managed file plus whether every rule of this change is loaded, compared semantically, because
`auditctl -l` prints `-F key=`, `auid!=-1`, `-S all` and its own syscall order.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from .family_sysctl import HEADER
from .probes import audit_rules
from .spec import IDENTITY_PATHS

RULES_DIR = '/etc/audit/rules.d'
FILES = {'6.3.3.4': '60-fyp-cis-time-change.rules', '6.3.3.6': '60-fyp-cis-privileged.rules',
         '6.3.3.8': '60-fyp-cis-identity.rules'}
RULESETS = {'6.3.3.4': 'time-change', '6.3.3.8': 'identity'}
_PATH = re.compile(r'/(?:[A-Za-z0-9._+-]+/)*[A-Za-z0-9._+-]+')
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_audit.py').read_bytes()
                                       + (_HERE / 'probes.py').read_bytes()).hexdigest()


def rule_lines(control_id, params):
    if control_id == '6.3.3.4':
        return ['-a always,exit -F arch=%s -S adjtimex,settimeofday,clock_settime -k time-change' % arch
                for arch in ('b64', 'b32')] + ['-w /etc/localtime -p wa -k time-change']
    if control_id == '6.3.3.8':
        return ['-w %s -p wa -k identity' % path for path in sorted(IDENTITY_PATHS)]
    return ['-a always,exit -F path=%s -F perm=x -F auid>=%d -F auid!=unset -k privileged' % (path, params['uid_min'])
            for path in params['paths']]


def _normal(row):
    return (row['action'], row['path'], tuple(sorted(set(row['syscalls']) - {'all'})), row['arch'],
            ''.join(sorted(row['permissions'])), row['key'], row['auid_min'], row['exclude_unset'])


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class AuditRulesFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 120

    def __init__(self, control_id, system):
        self.control_id, self.name, self.system = control_id, FILES[control_id], system
        self.action_id = 'ubuntu.%s.v1' % control_id

    def validate(self, params):
        if self.control_id in RULESETS:
            if type(params) is not dict or params != {'ruleset': RULESETS[self.control_id]}:
                raise ValueError('Only the CIS rule set for this control is managed')
            return
        if type(params) is not dict or set(params) != {'paths', 'uid_min'}:
            raise ValueError('Privileged-command rules need exactly the inventory paths and UID_MIN')
        uid, paths = params['uid_min'], params['paths']
        if type(uid) is not int or not 500 <= uid <= 60000:
            raise ValueError('Invalid UID_MIN')
        if (type(paths) is not list or not 1 <= len(paths) <= 512 or paths != sorted(set(paths))
                or any(type(p) is not str or not _PATH.fullmatch(p) or '/../' in p + '/' or '/./' in p + '/'
                       for p in paths)):
            raise ValueError('Invalid privileged path inventory')

    def _content(self, params):
        return HEADER + ''.join(line + '\n' for line in rule_lines(self.control_id, params)).encode('ascii')

    def _managed(self):
        data = dict(self.system.audit_files()).get(self.name)
        if data is not None and not data.startswith(HEADER):
            raise ValueError('The managed audit rules file holds content this family did not write')
        return data

    def _loaded(self, params):
        wanted = {_normal(row) for row in audit_rules(''.join(line + '\n' for line in rule_lines(self.control_id, params)))}
        have = {_normal(row) for row in audit_rules(self.system.audit_loaded())}
        return wanted <= have

    def read_state(self, params):
        managed = self._managed()
        return _dump({'managed': managed.decode('utf-8') if managed is not None else None,
                      'loaded': self._loaded(params)})

    def expected_after(self, params, before):
        state = json.loads(before)
        state.update(managed=self._content(params).decode('utf-8'), loaded=True)
        return _dump(state)

    def check_eligible(self, params):
        status = self.system.audit_status()
        if not status['installed']:
            raise ValueError('auditd is not installed; 6.3.1.1 comes first')
        if status['enabled'] == 2:
            raise ValueError('Audit rules are locked (-e 2); they can only change after a reboot')
        self._managed()
        for name, data in self.system.audit_files():
            if name == self.name:
                continue
            audit_rules(data.decode('utf-8'))  # the collector's parser: unparseable rules are refused
            for line in data.decode('utf-8').splitlines():
                tokens = line.split('#', 1)[0].split()
                if tokens == ['-e', '2']:
                    raise ValueError('Another rules file locks the configuration; a restore would need a reboot')
                if tokens == ['-D'] and name > self.name:
                    raise ValueError('A later rules file deletes all rules, including these')
        if self.control_id == '6.3.3.6':
            changed = [path for path in params['paths'] if not self.system.is_privileged(path)]
            if changed:
                raise ValueError('The privileged-binary inventory changed since the scan; rescan first')

    def summary(self, params, before):
        lines = rule_lines(self.control_id, params)
        return {'rules_file': RULES_DIR + '/' + self.name, 'rule_count': len(lines),
                'rules': lines[:12] + (['... %d more' % (len(lines) - 12)] if len(lines) > 12 else []),
                'load': 'augenrules --load'}

    def apply(self, params):
        self.system.install_rules(self.name, self._content(params))

    def restore(self, params, before):
        managed = json.loads(before)['managed']
        self.system.install_rules(self.name, managed.encode('utf-8') if managed is not None else None)


class LinuxAuditIO:
    """Mixin: bounded reads of rules.d, `auditctl -l`/`-s`, writes to the three managed files, `augenrules --load`."""

    def audit_files(self):
        folder, found = Path(RULES_DIR), []
        if folder.is_dir():
            for path in sorted(folder.glob('*.rules'))[:256]:
                found.append((path.name, self.io._bytes(path, 4 * 1024 * 1024)))
        return found

    def audit_status(self):
        installed = Path('/usr/sbin/auditctl').exists() and Path(RULES_DIR).is_dir()
        enabled = None
        if installed:
            result = self.io._run(('/usr/sbin/auditctl', '-s'), 20)
            match = re.search(r'^enabled (\d)$', result.stdout, re.M)
            enabled = int(match.group(1)) if result.returncode == 0 and match else None
            if enabled is None:
                raise ValueError('auditctl -s did not report the enabled state')
        return {'installed': installed, 'enabled': enabled}

    def audit_loaded(self):
        result = self.io._run(('/usr/sbin/auditctl', '-l'), 20)
        if result.returncode != 0:
            raise ValueError('auditctl -l failed')
        return result.stdout

    def is_privileged(self, path):
        try:
            info = os.lstat(path)
        except OSError:
            return False
        return stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o6000)

    def _put(self, name, content):
        if name not in FILES.values():
            raise ValueError('Unregistered audit rules file')
        target = Path(RULES_DIR) / name
        if target.is_symlink():
            raise ValueError('Managed files must not be symlinks')
        if content is None:
            if target.exists():
                target.unlink()
            return
        tmp = target.with_name('.' + name + '.tmp')  # not *.rules: augenrules never reads it
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0), 0o640)
        try:
            os.write(fd, content)
            os.fchmod(fd, 0o640)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, target)

    def install_rules(self, name, content):
        target = Path(RULES_DIR) / name
        previous = target.read_bytes() if target.exists() and not target.is_symlink() else None
        self._put(name, content)
        if self.io._run(('/usr/sbin/augenrules', '--load'), 60).returncode != 0:
            self._put(name, previous)
            self.io._run(('/usr/sbin/augenrules', '--load'), 60)
            raise OSError('augenrules --load failed; the previous file was put back')
