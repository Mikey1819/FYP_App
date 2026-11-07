"""Compare the latest stored Ubuntu scan with the independent second reading taken on the VM (task 17).

The administrator runs ../scripts/vm/ubuntu_cross_check_values.py on the VM (read-only) and copies its JSON here.
Each row pairs one stored-scan fact with the value read another way, names the second method, and is Agree, Disagree
or Not readable (never counted as agreement). A reading from another machine is refused; a large time gap between
the two readings is reported, because a setting may have changed in between. Reads a temporary copy of the store.

Usage (from the app directory):
  ..\\.venv-integration\\Scripts\\python.exe -B -m tools.ubuntu_value_cross_check crosscheck.json [--write]
  (--write: docs/evaluation/VALUE_CROSS_CHECK.md)
"""
from contextlib import closing
from datetime import datetime
from pathlib import Path
import argparse
import json
import shutil
import sqlite3
import tempfile

APP = Path(__file__).resolve().parents[1]
SCHEMA = 'fyp-ubuntu-crosscheck-v1'
STALE_MINUTES = 60
UNIT_FACTS = {'avahi-daemon.service': ('2.1.2', 'avahi-daemon.service'), 'avahi-daemon.socket': ('2.1.2', 'avahi-daemon.socket'),
              'ufw.service': ('4.1.3', 'ufw.service'), 'auditd.service': ('6.3.1.2', 'auditd')}
# Documented equivalences (live 2026-11-07 11:24): sshd_config(5) calls without-password a deprecated alias of
# prohibit-password; useradd(8) uses INACTIVE -1 when /etc/default/useradd does not set it.
SSH_ALIASES = {'without-password': 'prohibit-password'}
AUDIT_CONTROLS = {'time-change': '6.3.3.4', 'privileged': '6.3.3.6', 'identity': '6.3.3.8'}


def _value(observation):
    return observation['value'] if observation and observation.get('state') == 'ok' else None


def _verdict(scan, checked):
    if scan is None or checked is None:
        return 'Not readable'
    return 'Agree' if type(scan) is type(checked) and scan == checked else 'Disagree'


def compare(scan, second, machine_id, hostname):
    """Rows for one stored scan's observations (control -> facts) against one second-reading document."""
    if second.get('schema') != SCHEMA:
        raise ValueError('Not a second-reading document from scripts/vm/ubuntu_cross_check_values.py')
    if second.get('machine_id') != machine_id or second.get('hostname', '').casefold() != hostname.casefold():
        raise ValueError('The second reading comes from another machine; nothing is compared')
    values, rows = second['values'], []

    def add(cid, item, scan_value, checked, method):
        if cid in scan:
            rows.append({'control_id': cid, 'item': item, 'scan': scan_value, 'second': checked, 'method': method,
                         'verdict': _verdict(scan_value, checked)})

    section = lambda name: values.get(name) or {}  # noqa: E731
    for cid, facts in scan.items():
        for fact, observation in facts.items():
            for kind, source, method in (('runtime', 'runtime_sysctl', '/proc/sys file read directly'),
                                         ('persistent', 'persistent_sysctl', 'own sysctl.d precedence parser')):
                if fact.startswith(kind + '.'):
                    key = fact[len(kind) + 1:]
                    add(cid, '%s %s' % (kind, key), _value(observation),
                        section(source).get(key) if values.get(source) is not None else None, method)
            if fact.startswith('package.'):
                name = fact[len('package.'):]
                add(cid, 'package ' + name, _value(observation),
                    section('packages').get(name) if values.get('packages') is not None else None, 'apt-cache policy')
    for unit, (cid, prefix) in UNIT_FACTS.items():
        for part in ('enabled', 'active'):
            fact = scan.get(cid, {}).get('%s.%s' % (prefix, part))
            if fact is not None:
                add(cid, '%s %s' % (unit, part), _value(fact), (section('units').get(unit) or {}).get(part),
                    'systemctl is-%s' % part)
    ufw = values.get('ufw')
    for cid, fact, key in (('4.1.3', 'ufw.active', 'enabled'), ('4.1.7', 'ufw.default.incoming', 'default_incoming'),
                           ('4.1.7', 'ufw.default.outgoing', 'default_outgoing')):
        if fact in scan.get(cid, {}):
            add(cid, fact, _value(scan[cid][fact]), None if ufw is None else ufw.get(key),
                '/etc/ufw/ufw.conf, /etc/default/ufw (configured state)')
    ssh = values.get('ssh')
    for cid, facts in scan.items():
        contexts = _value(facts.get('ssh_contexts'))
        for context in contexts or ():
            if context.get('context_id') != 'global':
                continue
            for option, value in context.items():
                if option != 'context_id':
                    checked = None if ssh is None else ssh.get(option)
                    method = 'sshd -T -C connection spec (same tool as the collector)'
                    if checked in SSH_ALIASES:
                        checked, method = SSH_ALIASES[checked], method + '; %s is the OpenSSH alias' % ssh.get(option)
                    add(cid, 'sshd -T ' + option, value, checked, method)
    defs = values.get('login_defs')
    for cid, fact, key in (('5.4.1.1', 'default.maximum', 'maximum'), ('5.4.1.1', 'default.minimum', 'minimum'),
                           ('5.4.1.3', 'default.warning', 'warning'), ('5.4.1.5', 'default.inactive', 'inactive')):
        if fact in scan.get(cid, {}):
            checked, method = None if defs is None else defs.get(key), 'own parser of /etc/login.defs, /etc/default/useradd'
            if key == 'inactive' and checked == 'unset':
                checked, method = -1, method + ' (not set there: the useradd default -1)'
            add(cid, fact, _value(scan[cid][fact]), checked, method)
    accounts = values.get('accounts')
    for cid, fields in (('5.4.1.1', ('maximum', 'minimum')), ('5.4.1.3', ('warning',)), ('5.4.1.5', ('inactive',))):
        for account in _value(scan.get(cid, {}).get('accounts')) or ():
            if account.get('password_bearing'):
                for field in fields:
                    checked = None if accounts is None or account['name'] not in accounts else accounts[account['name']].get(field)
                    add(cid, '%s %s' % (account['name'], field), account.get(field), checked, 'chage -l')
    audit = values.get('audit') or {}
    for key, cid in AUDIT_CONTROLS.items():
        facts = scan.get(cid, {})
        for fact, part, label, method in (('loaded_audit_rules', 'loaded', 'loaded', 'auditctl -l (same tool)'),
                                          ('persistent_audit_rules', 'persistent_generated', 'persistent',
                                           'generated /etc/audit/audit.rules (collector reads rules.d)')):
            if fact in facts:
                rules = _value(facts[fact])
                counted = None if rules is None else sum(r.get('key') == key for r in rules)
                checked = None if audit.get(part) is None else audit[part].get(key)
                add(cid, '%s rules with key %s' % (label, key), counted, checked, method)
    boot = values.get('boot')
    if '6.3.1.3' in scan:
        facts = scan['6.3.1.3']
        entries = _value(facts.get('boot_entries'))
        add('6.3.1.3', 'current audit argument', _value(facts.get('current_audit_argument')),
            None if boot is None else boot.get('current_audit_argument'), '/proc/cmdline')
        add('6.3.1.3', 'boot entries with audit=1', None if entries is None else sum('audit=1' in e for e in entries),
            None if boot is None else boot.get('boot_entries_with_audit_1'), 'linux lines of /boot/grub/grub.cfg')
    updates = values.get('updates')
    for fact, method in (('pending_updates', 'apt list --upgradable'), ('held_packages', 'dpkg --get-selections'),
                         ('reboot_required', '/var/run/reboot-required')):
        if fact in scan.get('1.2.2.1', {}):
            add('1.2.2.1', fact, _value(scan['1.2.2.1'][fact]), None if updates is None else updates.get(fact), method)
    sudo = values.get('sudoers')
    if '5.2.2' in scan:
        pty = _value(scan['5.2.2'].get('sudoers_use_pty'))
        add('5.2.2', 'Defaults use_pty', None if pty is None else 'enabled' in pty,
            None if sudo is None else sudo.get('use_pty'), 'Defaults lines in /etc/sudoers, /etc/sudoers.d')
    if '5.2.3' in scan:
        logs = _value(scan['5.2.3'].get('sudoers_logfiles'))
        add('5.2.3', 'Defaults logfile', None if logs is None else sorted(logs),
            None if sudo is None else sudo.get('logfile'), 'Defaults lines in /etc/sudoers, /etc/sudoers.d')
    return rows


def latest_scan():
    """(collected_at, observations, machine_id, hostname) of the latest stored live scan, from a temporary copy."""
    folder = tempfile.mkdtemp()
    try:
        copy = Path(folder) / 'scans.sqlite3'
        shutil.copyfile(APP / 'data' / 'ubuntu' / 'integration_imports.sqlite3', copy)
        with closing(sqlite3.connect(copy)) as db:
            at, raw = db.execute("SELECT collected_at, raw FROM imported_assessments WHERE evidence_mode='Live (SSH)' "
                                 'ORDER BY collected_at DESC LIMIT 1').fetchone()
        doc = json.loads(raw)
        return at, doc['observations'], doc['machine_id'], doc['hostname']
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def markdown(rows, scan_at, second_at):
    gap = abs((datetime.fromisoformat(second_at) - datetime.fromisoformat(scan_at)).total_seconds()) / 60
    counts = {}
    for row in rows:
        counts[row['verdict']] = counts.get(row['verdict'], 0) + 1
    lines = ['# Ubuntu independent value cross-check (second reading on the VM)', '',
             'Generated by `tools/ubuntu_value_cross_check.py` from the stored scan of %s and the read-only second '
             'reading of %s (`scripts/vm/ubuntu_cross_check_values.py`). Each value was read another way where one '
             'exists; rows marked "same tool" share the collector\'s tool and are not independent.' % (scan_at, second_at),
             '', 'Time between the readings: %.0f minutes%s.' % (gap, ' (**over %d: a setting may have changed in '
                                                                   'between**)' % STALE_MINUTES if gap > STALE_MINUTES else ''),
             '', 'Summary: ' + ', '.join('%s %d' % kv for kv in sorted(counts.items())), '',
             '| Control | Value | Scan | Second reading | Method | Verdict |', '| --- | --- | --- | --- | --- | --- |']
    for row in sorted(rows, key=lambda r: ([int(x) for x in r['control_id'].split('.')], r['item'])):
        lines.append('| %s | %s | %s | %s | %s | %s |' % (
            row['control_id'], row['item'], json.dumps(row['scan']), json.dumps(row['second']), row['method'],
            '**Disagree**' if row['verdict'] == 'Disagree' else row['verdict']))
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('reading', help='JSON written by scripts/vm/ubuntu_cross_check_values.py on the VM')
    parser.add_argument('--write', action='store_true', help='write docs/evaluation/VALUE_CROSS_CHECK.md')
    args = parser.parse_args()
    second = json.loads(Path(args.reading).read_text(encoding='utf-8-sig'))
    scan_at, observations, machine_id, hostname = latest_scan()
    text = markdown(compare(observations, second, machine_id, hostname), scan_at, second['collected_at'])
    if args.write:
        (APP / 'docs' / 'evaluation' / 'VALUE_CROSS_CHECK.md').write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
