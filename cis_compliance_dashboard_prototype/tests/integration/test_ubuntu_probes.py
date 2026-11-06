"""Parser fixtures only. No target commands or privileged file reads occur here."""
import unittest


class UbuntuProbeTests(unittest.TestCase):
    def test_sysctl_precedence_ufw_override_and_duplicate_last_value(self):
        from vm.ubuntu.probes import resolve_sysctl
        merged = '# /usr/lib/sysctl.d/10-default.conf\nkernel.randomize_va_space = 2\n# /etc/sysctl.d/99-local.conf\nkernel.randomize_va_space=2\nkernel.randomize_va_space=0\n'
        self.assertEqual(resolve_sysctl(merged,'kernel.randomize_va_space'),0)
        self.assertEqual(resolve_sysctl(merged,'kernel.randomize_va_space',ufw='kernel/randomize_va_space = 2'),2)
        with self.assertRaises(ValueError):resolve_sysctl('kernel.randomize_va_space=bad','kernel.randomize_va_space')

    def test_shadow_aging_exports_no_hash_and_rejects_truncation(self):
        from vm.ubuntu.probes import account_aging
        passwd = 'fixtureuser:x:1000:1000:Fixture:/home/fixture:/bin/bash\nlocked:x:1001:1001::/none:/usr/sbin/nologin\n'
        shadow = 'fixtureuser:$6$SECRET-SENTINEL:20000:1:365:7:45::\nlocked:!:20000:0:99999:7:::\n'
        values = account_aging(passwd,shadow)
        self.assertEqual(values[0]['maximum'],365)
        self.assertFalse(values[1]['password_bearing'])
        self.assertNotIn('SECRET-SENTINEL',repr(values))
        with self.assertRaises(ValueError):account_aging(passwd,'fixtureuser:TRUNCATED')

    def test_ssh_normalizes_only_selected_options_and_requires_every_context(self):
        from vm.ubuntu.probes import ssh_context
        text = 'permitrootlogin no\nmaxauthtries 3\nclientaliveinterval 15\nclientalivecountmax 3\nsetenv SECRET-SENTINEL\n'
        self.assertEqual(ssh_context(text,'global',('maxauthtries',)),{'context_id':'global','maxauthtries':3})
        with self.assertRaises(ValueError):ssh_context(text,'global',('permitemptypasswords',))
        with self.assertRaises(ValueError):ssh_context(text+'maxauthtries 2\n','global',('maxauthtries',))

    def test_semantic_audit_parser_preserves_filters_and_never_substring_matches(self):
        from vm.ubuntu.probes import audit_rules
        rows = audit_rules('-w /etc/passwd -p aw -k identity\n-a always,exit -F arch=b64 -S adjtimex,clock_settime -k time\n-a always,exit -F path=/usr/bin/passwd-extra -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged\n')
        self.assertEqual(rows[0]['path'],'/etc/passwd')
        self.assertEqual(set(rows[1]['syscalls']),{'adjtimex','clock_settime'})
        self.assertEqual(rows[2]['path'],'/usr/bin/passwd-extra')
        self.assertTrue(rows[2]['exclude_unset'])
        with self.assertRaises(ValueError):audit_rules('-a always,exit -F strange=secret -S all')

    def test_pwquality_pam_wins_and_main_file_overrides_dropins(self):
        from vm.ubuntu.probes import password_minlen
        self.assertEqual(password_minlen([('10.conf','minlen=18')],'minlen=16','password requisite pam_pwquality.so minlen=12'),12)
        self.assertEqual(password_minlen([('10.conf','minlen=18')],'minlen=16','password requisite pam_pwquality.so'),16)
        with self.assertRaises(ValueError):password_minlen([], '', 'password requisite pam_unix.so')
        with self.assertRaises(ValueError):password_minlen([], 'minlen=14',
            'password sufficient pam_permit.so\npassword requisite pam_pwquality.so')
