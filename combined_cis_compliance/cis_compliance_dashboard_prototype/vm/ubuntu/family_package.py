"""Package families: install 1.3.1.1 (apparmor) and 6.3.1.1 (auditd); purge 1.5.4 (prelink). 2.1.2 keeps avahi-daemon
and masks its units instead (family_service.AvahiMaskFamily; administrator decision 2026-11-08).

Python 3.10, stdlib only. Each runs as a systemd-supervised job (supervision.py), never in the SSH session.
Eligibility is apt's own read-only simulation (`apt-get -s`) of exactly this change:
- an install may add new packages and upgrade the installed ones apt needs for them (live 13 November 2026:
  auditd needs a newer libauparse0; the administrator asked for no apt upgrade by hand), listed in the approval
  summary; any removal is refused;
- a purge may only remove the CIS target packages: if apt would take anything else with them (the CIS
  "review dependent packages" impact), it is refused, and the dependency branch stays a human decision.
The simulated plan is part of the recorded state, so the after-state is exact (targets present or absent,
empty plan) and restore is bounded: purge exactly the packages the install added (an upgrade it needed stays,
never downgraded), or reinstall the purged
targets at their recorded versions (purged configuration returns to package defaults; prelinking is not
redone). No package lists are refreshed here; an unavailable download fails the job before dpkg changes.
A fix is refused at once while apt's lock is held (refuse_while_apt_busy: live 13 November 2026, after a snapshot
restore Ubuntu's automatic updates held it for over 30 minutes, and longer waits only delayed everything behind the
package fixes). A lock taken in between is waited for up to 5 minutes, inside a job of at most 30 minutes.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SPECS = {
    '1.3.1.1': dict(mode='install', packages=('apparmor', 'apparmor-utils'), before=()),
    '1.5.4': dict(mode='purge', packages=('prelink',), before=(('/usr/sbin/prelink', '-ua'),)),
    '6.3.1.1': dict(mode='install', packages=('auditd', 'audispd-plugins'), before=()),
}
_NAME = r'[a-z0-9][a-z0-9+.-]{0,127}'
_VERSION = r'[A-Za-z0-9.+:~-]{1,128}'
_HERE = Path(__file__).resolve().parent
IMPLEMENTATION_SHA256 = hashlib.sha256((_HERE / 'family_package.py').read_bytes()).hexdigest()


def parse_simulation(text):
    """[(op, package, version, replaced_version)] from `apt-get -s` output; Conf lines repeat Inst and are skipped."""
    plan = []
    for line in text.splitlines():
        if not line.startswith(('Inst ', 'Remv ', 'Purg ')):
            continue
        if line.startswith('Inst '):
            # apt may append a related-package list, e.g. ") [python3.10:amd64 ]" or ") []" (live 2026-11-07:
            # every 1.2.2.1 preview was refused on such lines).
            match = re.fullmatch(r'Inst (%s)(?::[a-z0-9]+)? (?:\[(%s)\] )?\((%s) [^()]*\)(?: \[[^\[\]]*\])?'
                                 % (_NAME, _VERSION, _VERSION), line)
            if not match:
                raise ValueError('Unrecognised apt simulation line')
            plan.append(('Inst', match.group(1), match.group(3), match.group(2)))
        else:
            match = re.fullmatch(r'(Remv|Purg) (%s)(?::[a-z0-9]+)?(?: \[(%s)\])?.*' % (_NAME, _VERSION), line)
            if not match:
                raise ValueError('Unrecognised apt simulation line')
            plan.append((match.group(1), match.group(2), match.group(3), None))
    return plan


def refuse_while_apt_busy(system, kind='install'):
    """Refused while something holds the locks this operation needs (`kind`: 'install' for an install or purge, 'lists'
    for a package-list refresh), after LinuxPackageIO.apt_busy has tried again for up to 30 seconds (live 13 November
    2026: after a snapshot restore Ubuntu's automatic updates held apt's lock for over 30 minutes; 1.3.1.1 and 6.3.1.1
    each waited out the lock and changed nothing). Systems without the probe (fixtures) are never busy."""
    holder = getattr(system, 'apt_busy', lambda kind='install': None)(kind)
    if holder:
        raise ValueError(('apt is busy: %s holds the package lock. Nothing was changed; run the next round once it '
                          'has finished.' % holder)[:200])


def _dump(state):
    return json.dumps(state, sort_keys=True, separators=(',', ':')).encode('utf-8')


class PackageFamily:
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 1800  # remediation_schema.MAX_JOB_SECONDS: the lock wait plus the install
    supervision = 'job'

    def __init__(self, control_id, system):
        self.control_id, self.spec, self.system = control_id, SPECS[control_id], system
        self.action_id = 'ubuntu.%s.v1' % control_id

    def validate(self, params):
        if type(params) is not dict or set(params) != {'packages'} or params['packages'] != list(self.spec['packages']):
            raise ValueError('Only the CIS package set for this control is managed')

    def read_state(self, params):
        names = list(self.spec['packages'])
        plan = parse_simulation(self.system.simulate(self.spec['mode'], names))
        return _dump({'mode': self.spec['mode'], 'packages': self.system.package_status(names),
                      'plan': [list(step) for step in plan]})

    def expected_after(self, params, before):
        state = json.loads(before)
        planned = {name: version for op, name, version, _ in state['plan'] if op == 'Inst'}
        for name, row in state['packages'].items():
            if state['mode'] == 'install':
                state['packages'][name] = {'status': 'installed', 'version': planned.get(name, row['version'])}
            else:
                state['packages'][name] = {'status': 'absent', 'version': None}
        state['plan'] = []
        return _dump(state)

    def check_eligible(self, params):
        refuse_while_apt_busy(self.system)
        state = json.loads(self.read_state(params))
        if any(row['status'] not in ('installed', 'absent') for row in state['packages'].values()):
            raise ValueError('A target package is half-installed; repair it by hand first')
        plan, targets = state['plan'], set(self.spec['packages'])
        if self.spec['mode'] == 'install':
            if any(op != 'Inst' for op, _, _, _ in plan):
                raise ValueError('The install would remove existing packages')
            missing = {n for n, row in state['packages'].items() if row['status'] == 'absent'}
            if not missing or not missing <= {name for _, name, _, _ in plan}:
                raise ValueError('Nothing to install, or a target package is unavailable from the configured sources')
        else:
            installed = {n for n, row in state['packages'].items() if row['status'] == 'installed'}
            if not installed or any(op != 'Purg' for op, _, _, _ in plan) or {name for _, name, _, _ in plan} != installed:
                raise ValueError('The purge would also remove dependent packages, or nothing is installed')

    def summary(self, params, before):
        state = json.loads(before)
        if state['mode'] == 'install':
            changes = {'will_install': ['%s=%s' % (name, version) for _, name, version, old in state['plan'] if old is None]}
            upgrades = ['%s %s -> %s' % (name, old, version) for _, name, version, old in state['plan'] if old is not None]
            if upgrades:
                changes['will_upgrade'] = upgrades  # needed by the install; kept on restore
        else:
            changes = {'will_purge': ['%s=%s' % (name, version) for _, name, version, _ in state['plan']]}
        return {**changes,
                'steps_before': [' '.join(argv) for argv in self.spec['before']],
                'restore': 'purge exactly the added packages' if state['mode'] == 'install'
                else 'reinstall the recorded versions (configuration returns to package defaults)'}

    def apply(self, params):
        names = list(self.spec['packages'])
        if self.spec['mode'] == 'install':
            self.system.install(names)
            return
        for argv in self.spec['before']:
            self.system.run_fixed(list(argv))
        self.system.purge(names)

    def restore(self, params, before):
        state = json.loads(before)
        if state['mode'] == 'install':
            added = [name for op, name, _, replaced in state['plan'] if op == 'Inst' and replaced is None]
            current = self.system.package_status(added)
            present = [name for name in added if current[name]['status'] == 'installed']
            if present:
                self.system.purge(present)
            return
        pinned = ['%s=%s' % (name, row['version']) for name, row in sorted(state['packages'].items())
                  if row['status'] == 'installed']
        if pinned:
            self.system.install(pinned)


class LinuxPackageIO:
    """Mixin: fixed apt/dpkg argv with a fixed environment; no shell, no caller-supplied text beyond validated names."""
    _ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive',
            'NEEDRESTART_MODE': 'l', 'APT_LISTCHANGES_FRONTEND': 'none'}
    LOCK_SECONDS, RUN_SECONDS = 300, 1500  # a lock taken in between; a held lock is refused before (2026-11-13)
    _APT = ('/usr/bin/apt-get', '-q', '-o', 'DPkg::Lock::Timeout=%d' % LOCK_SECONDS)
    _FIXED = {('/usr/sbin/prelink', '-ua'),
              ('/usr/bin/systemctl', 'stop', '--', 'avahi-daemon.socket', 'avahi-daemon.service')}

    def _exec(self, argv, seconds):
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=self._ENV, shell=False, close_fds=True, timeout=seconds)
        return result.returncode, result.stdout[:4 * 1024 * 1024].decode('utf-8', errors='replace')

    @staticmethod
    def _names(names, *, pinned=False):
        pattern = _NAME + ('=' + _VERSION if pinned else '')
        if not names or any(type(n) is not str or not re.fullmatch(pattern, n) for n in names):
            raise ValueError('Invalid package name')
        return list(names)

    # The locks each operation takes (live 13 November 2026: an install was refused because the automatic package-list
    # download held the list lock, which an install never takes).
    LOCKS = {'install': ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/cache/apt/archives/lock'),
             'lists': ('/var/lib/apt/lists/lock',)}
    BUSY_TRIES, BUSY_PAUSE = 7, 5  # a held lock is tried again for about 30 s before the fix is refused
    NAMES = {'unattended-upgr': "Ubuntu's automatic updates (unattended-upgrades, pid %s)",
             'apt.systemd.dai': "Ubuntu's automatic updates (apt.systemd.daily, pid %s)",
             'packagekitd': 'PackageKit (packagekitd, pid %s)'}

    @staticmethod
    def _pause(seconds):
        import time
        time.sleep(seconds)

    @staticmethod
    def _proc(path):
        return Path(path).read_text(encoding='ascii', errors='replace')[:65536]

    def _held(self, locks):
        """The first of `locks` someone holds now, or None: a non-blocking try of the POSIX record lock apt and dpkg
        take on it, released at once."""
        import fcntl
        for path in locks:
            try:
                fd = os.open(path, os.O_RDWR)
            except OSError:
                continue  # not there (or not openable): nothing can hold it
            try:
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(fd, fcntl.LOCK_UN)
            except OSError:
                return path
            finally:
                os.close(fd)
        return None

    def _holder(self, path):
        """Who holds `path`: the process the kernel's lock table names, else a running automatic-update unit."""
        try:
            inode = os.stat(path).st_ino
            for line in self._proc('/proc/locks').splitlines():
                fields = line.split()
                if len(fields) >= 6 and fields[1] == 'POSIX' and fields[5].rsplit(':', 1)[-1] == str(inode) \
                        and fields[4].isdigit():
                    name = self._proc('/proc/%s/comm' % fields[4]).strip()
                    return self.NAMES.get(name, 'the process ' + re.sub(r'[^\w.+-]', '?', name)[:20]
                                          + ' (pid %s)') % fields[4]
        except (OSError, ValueError):
            pass
        for unit, name in (('apt-daily-upgrade.service', "Ubuntu's automatic updates (apt-daily-upgrade)"),
                           ('apt-daily.service', "Ubuntu's automatic package-list download (apt-daily)")):
            state = self._exec(['/usr/bin/systemctl', 'is-active', unit], 20)[1].strip()
            if state in ('active', 'activating', 'reloading'):  # a oneshot unit reads "activating" while it runs
                return name
        return 'another apt or dpkg process'

    def apt_busy(self, kind='install'):
        """Who holds a lock this operation needs, or None; a held lock is tried again for about 30 seconds first."""
        for attempt in range(self.BUSY_TRIES):
            path = self._held(self.LOCKS[kind])
            if path is None:
                return None
            if attempt + 1 < self.BUSY_TRIES:
                self._pause(self.BUSY_PAUSE)
        return self._holder(path)

    def package_status(self, names):
        rows = {}
        for name in self._names(names):
            code, out = self._exec(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\\t${Version}\\n', '--', name], 30)
            fields = out.strip().split('\t') if code == 0 and out.strip() else ['not-installed', '']
            status = fields[0]
            rows[name] = {'status': 'installed' if status == 'installed' else
                          'absent' if status in ('not-installed', 'config-files') else 'incomplete',
                          'version': fields[1] if status == 'installed' and len(fields) == 2 else None}
        return rows

    def simulate(self, mode, names):
        if mode not in ('install', 'purge'):
            raise ValueError('Unregistered package operation')
        extra = ['--no-install-recommends'] if mode == 'install' else []
        code, out = self._exec(list(self._APT) + ['-s'] + extra + [mode, '--'] + self._names(names), 120)
        if code != 0:
            raise ValueError('apt could not plan this change')
        return out

    def install(self, names):
        pinned = any('=' in n for n in names)
        argv = list(self._APT) + ['-y', '--no-install-recommends', '-o', 'Dpkg::Options::=--force-confdef',
                                  '-o', 'Dpkg::Options::=--force-confold', 'install', '--'] + self._names(names, pinned=pinned)
        if self._exec(argv, self.RUN_SECONDS)[0] != 0:
            raise OSError('apt-get install failed')

    def purge(self, names):
        if self._exec(list(self._APT) + ['-y', 'purge', '--'] + self._names(names), self.RUN_SECONDS)[0] != 0:
            raise OSError('apt-get purge failed')

    def run_fixed(self, argv):
        if tuple(argv) not in self._FIXED:
            raise ValueError('Unregistered fixed command')
        if self._exec(list(argv), 300)[0] != 0:
            raise OSError('A fixed preparation command failed')
