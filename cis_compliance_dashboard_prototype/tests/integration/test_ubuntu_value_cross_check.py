"""Comparing the stored scan with the independent second reading taken on the VM (scripts/vm/ubuntu_cross_check_values.py).
Synthetic documents shaped like the 2026-11-07 scan; no VM or store is opened."""
import unittest

MACHINE, HOST = 'f1d16ae7e6bc4d2488f9410fcd858e36', 'FYP-Ubuntu2204'


def ok(value):
    return {'state': 'ok', 'value': value}


SCAN = {
    '3.3.2': {'runtime.net.ipv4.conf.all.send_redirects': ok(0), 'persistent.net.ipv4.conf.all.send_redirects': ok(0)},
    '6.3.1.1': {'package.auditd': ok('installed'), 'package.audispd-plugins': ok('installed')},
    '6.3.1.2': {'auditd.enabled': ok('enabled'), 'auditd.active': ok('active')},
    '4.1.7': {'ufw.default.incoming': ok('deny'), 'ufw.default.outgoing': ok('allow')},
    '5.1.20': {'ssh_contexts': ok([{'context_id': 'global', 'permitrootlogin': 'prohibit-password'}])},
    '5.4.1.1': {'default.maximum': ok(365), 'accounts': ok([
        {'name': 'root', 'maximum': 365, 'minimum': 0, 'warning': 7, 'inactive': -1, 'password_bearing': True},
        {'name': 'daemon', 'maximum': 99999, 'minimum': 0, 'warning': 7, 'inactive': -1, 'password_bearing': False}])},
    '6.3.3.4': {'loaded_audit_rules': ok([{'key': 'time-change'}] * 3), 'persistent_audit_rules': ok([{'key': 'time-change'}] * 3)},
    '1.2.2.1': {'pending_updates': ok(10), 'held_packages': ok(0), 'reboot_required': ok(False)},
}
SECOND = {'schema': 'fyp-ubuntu-crosscheck-v1', 'collected_at': '2026-11-07T11:10:00+00:00', 'hostname': HOST,
          'machine_id': MACHINE, 'root': True, 'errors': {}, 'values': {
              'runtime_sysctl': {'net.ipv4.conf.all.send_redirects': 0},
              'persistent_sysctl': {'net.ipv4.conf.all.send_redirects': 0},
              'packages': {'auditd': 'installed', 'audispd-plugins': 'installed'},
              'units': {'auditd.service': {'enabled': 'enabled', 'active': 'active'}},
              'ufw': {'enabled': True, 'default_incoming': 'deny', 'default_outgoing': 'allow', 'user_rules': {}},
              'ssh': {'permitrootlogin': 'prohibit-password'},
              'login_defs': {'maximum': 365},
              'accounts': {'root': {'maximum': 365, 'minimum': 0, 'warning': 7, 'inactive': -1}},
              'audit': {'loaded': {'time-change': 3}, 'persistent_generated': {'time-change': 3}},
              'updates': {'pending_updates': 10, 'held_packages': 0, 'reboot_required': False}}}


def second(**changes):
    import copy
    doc = copy.deepcopy(SECOND)
    for path, value in changes.items():
        section, key = path.split('__')
        doc['values'][section][key] = value
    return doc


class ValueCrossCheckTests(unittest.TestCase):
    def rows(self, doc=None):
        from tools.ubuntu_value_cross_check import compare
        return {(r['control_id'], r['item']): r for r in compare(SCAN, doc or SECOND, MACHINE, HOST)}

    def test_matching_readings_agree_and_name_their_method(self):
        rows = self.rows()
        self.assertTrue(rows)
        self.assertEqual({r['verdict'] for r in rows.values()}, {'Agree'})
        self.assertIn('/proc/sys', rows[('3.3.2', 'runtime net.ipv4.conf.all.send_redirects')]['method'])
        self.assertIn('same tool', rows[('5.1.20', 'sshd -T permitrootlogin')]['method'])

    def test_a_different_value_is_a_disagreement(self):
        rows = self.rows(second(packages__auditd='absent'))
        self.assertEqual(rows[('6.3.1.1', 'package auditd')]['verdict'], 'Disagree')

    def test_an_unreadable_second_value_is_not_counted_as_agreement(self):
        rows = self.rows(second(audit__loaded=None))
        self.assertEqual(rows[('6.3.3.4', 'loaded rules with key time-change')]['verdict'], 'Not readable')

    def test_only_password_bearing_accounts_are_compared(self):
        rows = self.rows()
        self.assertIn(('5.4.1.1', 'root maximum'), rows)
        self.assertNotIn(('5.4.1.1', 'daemon maximum'), rows)

    def test_a_reading_from_another_machine_is_refused(self):
        from tools.ubuntu_value_cross_check import compare
        with self.assertRaises(ValueError):
            compare(SCAN, dict(SECOND, machine_id='0' * 32), MACHINE, HOST)
        with self.assertRaises(ValueError):
            compare(SCAN, dict(SECOND, schema='other'), MACHINE, HOST)


if __name__ == '__main__':
    unittest.main()


class LiveFindingTests(unittest.TestCase):
    """First live run, 2026-11-07 11:24 (68 agree): two rows needed a documented equivalence, not a different verdict."""

    def test_openssh_alias_without_password_equals_prohibit_password(self):
        from tools.ubuntu_value_cross_check import compare
        doc = second(ssh__permitrootlogin='without-password')
        row = {(r['control_id'], r['item']): r for r in compare(SCAN, doc, MACHINE, HOST)}[('5.1.20', 'sshd -T permitrootlogin')]
        self.assertEqual(row['verdict'], 'Agree')
        self.assertIn('alias', row['method'])

    def test_an_unset_useradd_inactive_means_the_useradd_default(self):
        from tools.ubuntu_value_cross_check import compare
        scan = {'5.4.1.5': {'default.inactive': ok(-1)}}
        rows = compare(scan, second(login_defs__inactive='unset'), MACHINE, HOST)
        self.assertEqual([(r['item'], r['verdict']) for r in rows], [('default.inactive', 'Agree')])

    def test_the_script_reports_unset_apart_from_unreadable(self):
        import importlib.util
        from pathlib import Path
        from unittest import mock
        path = Path(__file__).resolve().parents[3] / 'scripts' / 'vm' / 'ubuntu_cross_check_values.py'
        spec = importlib.util.spec_from_file_location('crosscheck_script', path)
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        files = {'/etc/login.defs': 'PASS_MAX_DAYS\t365\n', '/etc/default/useradd': '# INACTIVE=-1\n'}
        with mock.patch.object(script, 'read', files.get):
            self.assertEqual(script.login_defs()['inactive'], 'unset')
        with mock.patch.object(script, 'read', {'/etc/login.defs': ''}.get):
            self.assertIsNone(script.login_defs()['inactive'])
