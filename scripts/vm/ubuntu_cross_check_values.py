#!/usr/bin/env python3
"""Independent second reading of the Ubuntu CIS values on the VM (task 17 cross-check). READ-ONLY.

Run on the VM by the administrator, then copy the JSON back to the laptop:
    sudo python3 ubuntu_cross_check_values.py > crosscheck.json
Compare there (from the app directory):
    ..\\.venv-integration\\Scripts\\python.exe -B -m tools.ubuntu_value_cross_check crosscheck.json

It reads each value with a different command or its own parser wherever one exists, and records which. It never
writes, installs, restarts or changes anything: only fixed read commands (no shell) and file reads. Root is needed
only to read /etc/shadow, the audit rules and the account ages; without it those values are reported as unreadable.
Python 3.10 (Ubuntu 22.04 standard library only).
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 'fyp-ubuntu-crosscheck-v1'
SYSCTL = ('kernel.randomize_va_space', 'fs.suid_dumpable', 'net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding',
          'net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects',
          'net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route',
          'net.ipv6.conf.all.accept_source_route', 'net.ipv6.conf.default.accept_source_route')
PACKAGES = ('apparmor', 'apparmor-utils', 'prelink', 'avahi-daemon', 'ufw', 'auditd', 'audispd-plugins')
UNITS = ('avahi-daemon.service', 'avahi-daemon.socket', 'ufw.service', 'auditd.service')
SSH = ('clientaliveinterval', 'clientalivecountmax', 'hostbasedauthentication', 'maxauthtries',
       'permitemptypasswords', 'permitrootlogin', 'permituserenvironment')
AUDIT_KEYS = ('time-change', 'identity', 'privileged')
SYSCTL_DIRS = ('/usr/lib/sysctl.d', '/lib/sysctl.d', '/usr/local/lib/sysctl.d', '/run/sysctl.d', '/etc/sysctl.d')


def run(*argv, timeout=60):
    """A fixed read-only command; (exit code, stdout). Never a shell."""
    try:
        done = subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        return done.returncode, done.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, ''


def read(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def number(text):
    try:
        return int(str(text).strip())
    except ValueError:
        return None


def runtime_sysctl():
    """/proc/sys files directly (the collector uses `sysctl -n`)."""
    return {key: number(read('/proc/sys/' + key.replace('.', '/')) or '') for key in SYSCTL}


def persistent_sysctl():
    """Own resolution of the sysctl.d files with systemd's precedence (the collector uses systemd-sysctl's output):
    files are ordered by name across all directories, a same-named file in a later directory replaces an earlier
    one, /etc/sysctl.conf is read last, and the last assignment of a key wins."""
    by_name = {}
    for directory in SYSCTL_DIRS:
        folder = Path(directory)
        if folder.is_dir():
            for path in folder.glob('*.conf'):
                by_name[path.name] = path
    files = [by_name[name] for name in sorted(by_name)] + [Path('/etc/sysctl.conf')]
    values = {}
    for path in files:
        for line in (read(path) or '').splitlines():
            line = line.strip()
            if not line or line[0] in '#;' or '=' not in line:
                continue
            key, value = (part.strip() for part in line.lstrip('-').split('=', 1))
            key = key.replace('/', '.')
            if key in SYSCTL:
                values[key] = number(value)
    return {key: values.get(key, 'unset') for key in SYSCTL}


def packages():
    """`apt-cache policy` Installed: line (the collector uses dpkg-query)."""
    result = {}
    for name in PACKAGES:
        code, out = run('apt-cache', 'policy', name)
        match = re.search(r'^\s*Installed:\s*(\S+)', out, re.M)
        result[name] = None if code != 0 else ('absent' if not match or match.group(1) == '(none)' else 'installed')
    return result


def units():
    """`systemctl is-enabled` / `is-active` (the collector uses `systemctl show`)."""
    result = {}
    for unit in UNITS:
        _, enabled = run('systemctl', 'is-enabled', unit)
        _, active = run('systemctl', 'is-active', unit)
        result[unit] = {'enabled': enabled.strip() or 'not-found', 'active': active.strip() or 'unknown'}
    return result


def ufw():
    """UFW configuration files (the collector uses `ufw status verbose`)."""
    defaults, conf = read('/etc/default/ufw') or '', read('/etc/ufw/ufw.conf') or ''
    policy = {'DROP': 'deny', 'REJECT': 'reject', 'ACCEPT': 'allow'}

    def setting(text, name):
        match = re.search(r'^\s*%s\s*=\s*"?([A-Za-z]+)"?' % name, text, re.M)
        return match.group(1) if match else None
    enabled = setting(conf, 'ENABLED')
    rules = {}
    for family, path in (('ipv4', '/etc/ufw/user.rules'), ('ipv6', '/etc/ufw/user6.rules')):
        text = read(path)
        rules[family] = None if text is None else {
            'loopback_in_rules': len(re.findall(r'^-A ufw6?-user-input -i lo -j ACCEPT', text, re.M)),
            'loopback_out_rules': len(re.findall(r'^-A ufw6?-user-output -o lo -j ACCEPT', text, re.M))}
    return {'enabled': None if enabled is None else enabled.lower() == 'yes',
            'default_incoming': policy.get(setting(defaults, 'DEFAULT_INPUT_POLICY') or ''),
            'default_outgoing': policy.get(setting(defaults, 'DEFAULT_OUTPUT_POLICY') or ''),
            'user_rules': rules}


def ssh():
    """`sshd -T` with an explicit connection spec: SAME TOOL as the collector (no other effective-config reader)."""
    code, out = run('sshd', '-T', '-C', 'user=root,host=localhost,addr=127.0.0.1')
    if code != 0:
        return None
    values = dict(line.split(None, 1) for line in out.splitlines() if ' ' in line)
    return {option: (number(values[option]) if values.get(option, '').isdigit() else values.get(option))
            for option in SSH}


def login_defs():
    """Own parser of /etc/login.defs and /etc/default/useradd (the collector uses `useradd -D` and its parser)."""
    text, useradd = read('/etc/login.defs') or '', read('/etc/default/useradd') or ''

    def value(source, name):
        match = re.search(r'^\s*%s\s+(-?\d+)' % name, source, re.M) or re.search(r'^\s*%s=(-?\d+)' % name, source, re.M)
        return int(match.group(1)) if match else None
    raw_useradd = read('/etc/default/useradd')
    inactive = None if raw_useradd is None else value(raw_useradd, 'INACTIVE')
    return {'maximum': value(text, 'PASS_MAX_DAYS'), 'minimum': value(text, 'PASS_MIN_DAYS'),
            'warning': value(text, 'PASS_WARN_AGE'),
            # 'unset': the file is readable but sets no INACTIVE (useradd then uses -1); None: unreadable.
            'inactive': 'unset' if raw_useradd is not None and inactive is None else inactive}


def accounts():
    """Password-bearing accounts from /etc/shadow, ages from `chage -l` (the collector parses /etc/shadow)."""
    shadow = read('/etc/shadow')
    if shadow is None:
        return None
    result = {}
    for line in shadow.splitlines():
        fields = line.split(':')
        if len(fields) < 2 or not fields[1] or fields[1][0] in '!*' or fields[0].startswith('-'):
            continue  # no password, or a name that chage could read as an option
        _, out = run('chage', '-l', fields[0])
        info = dict((k.strip(), v.strip()) for k, v in (l.split(':', 1) for l in out.splitlines() if ':' in l))

        def days(label):
            text = info.get(label, '')
            return -1 if text in ('never', '-1') else number(text)
        result[fields[0]] = {'maximum': days('Maximum number of days between password change'),
                             'minimum': days('Minimum number of days between password change'),
                             'warning': days('Number of days of warning before password expires'),
                             'inactive': days('Password inactive')}
    return result


def audit():
    """Loaded: `auditctl -l` (same tool as the collector). Persistent: the generated /etc/audit/audit.rules
    (the collector reads the rules.d files). Counted per CIS key."""
    code, loaded = run('auditctl', '-l')
    generated = read('/etc/audit/audit.rules')

    def count(text):
        return {key: sum(1 for line in text.splitlines() if re.search(r'(-k |key=)%s\b' % re.escape(key), line))
                for key in AUDIT_KEYS}
    return {'loaded': None if code != 0 else count(loaded), 'persistent_generated': None if generated is None else count(generated)}


def boot():
    """/proc/cmdline and the linux lines of /boot/grub/grub.cfg."""
    cmdline = read('/proc/cmdline') or ''
    match = re.search(r'\baudit=(\S+)', cmdline)
    grub = read('/boot/grub/grub.cfg')
    entries = None if grub is None else [line for line in grub.splitlines() if re.match(r'\s*linux\s', line)]
    return {'current_audit_argument': 'audit=' + match.group(1) if match else 'audit=missing',
            'boot_entries': None if entries is None else len(entries),
            'boot_entries_with_audit_1': None if entries is None else sum('audit=1' in e for e in entries)}


def updates():
    """`apt list --upgradable`, holds from dpkg selections (the collector uses apt-get -s and apt-mark)."""
    code, listing = run('apt', 'list', '--upgradable', timeout=120)
    _, selections = run('dpkg', '--get-selections')
    return {'pending_updates': None if code != 0 else sum('[upgradable from' in l for l in listing.splitlines()),
            'held_packages': sum(1 for l in selections.splitlines() if l.split()[-1:] == ['hold']),
            'reboot_required': Path('/var/run/reboot-required').exists()}


def sudoers():
    """Defaults lines in /etc/sudoers and /etc/sudoers.d (the collector resolves sudoers with visudo checks)."""
    texts = [read('/etc/sudoers') or ''] + [read(p) or '' for p in sorted(Path('/etc/sudoers.d').glob('*'))
                                             if p.is_file() and not p.name.endswith('~') and '.' not in p.name]
    lines = [l.split('#', 1)[0] for t in texts for l in t.splitlines() if re.match(r'\s*Defaults\b', l)]
    return {'use_pty': any(re.search(r'\buse_pty\b', l) and '!use_pty' not in l for l in lines),
            'logfile': sorted(set(m for l in lines for m in re.findall(r'logfile\s*=\s*"?([^",\s]+)', l)))}


def pam_minlen():
    """minlen from pam_pwquality arguments and pwquality.conf(.d) (the collector resolves PAM effective minlen)."""
    common = read('/etc/pam.d/common-password') or ''
    pam_arg = re.search(r'pam_pwquality\.so\b.*\bminlen=(\d+)', common)
    conf = None
    for path in [Path('/etc/security/pwquality.conf')] + sorted(Path('/etc/security/pwquality.conf.d').glob('*.conf')):
        for line in (read(path) or '').splitlines():
            match = re.match(r'\s*minlen\s*=\s*(\d+)', line)
            if match:
                conf = int(match.group(1))
    return {'pwquality_in_pam': 'pam_pwquality.so' in common, 'pam_argument': int(pam_arg.group(1)) if pam_arg else None,
            'pwquality_conf': conf}


def main():
    readers = {'runtime_sysctl': runtime_sysctl, 'persistent_sysctl': persistent_sysctl, 'packages': packages,
               'units': units, 'ufw': ufw, 'ssh': ssh, 'login_defs': login_defs, 'accounts': accounts,
               'audit': audit, 'boot': boot, 'updates': updates, 'sudoers': sudoers, 'pam_minlen': pam_minlen}
    values, errors = {}, {}
    for name, reader in readers.items():
        try:
            values[name] = reader()
        except Exception as error:  # report, never guess
            values[name], errors[name] = None, type(error).__name__
    document = {'schema': SCHEMA, 'collected_at': datetime.now(timezone.utc).isoformat(),
                'hostname': (read('/proc/sys/kernel/hostname') or '').strip(),
                'machine_id': (read('/etc/machine-id') or '').strip(), 'root': getattr(os, 'geteuid', lambda: -1)() == 0,
                'values': values, 'errors': errors}
    json.dump(document, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
