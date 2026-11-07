"""Audit-rule families for CIS 6.3.3.4 (pp.784-787), 6.3.3.6 (pp.792-795) and 6.3.3.8 (pp.800-802). IN-MEMORY auditd."""
import json
import re
import unittest

BASE = b'-D\n-b 8192\n--backlog_wait_time 60000\n-f 1\n'
PRIVILEGED = {'/usr/bin/passwd', '/usr/bin/sudo', '/usr/bin/su'}


def auditctl_form(line):
    """How `auditctl -l` prints a rule: -F key=, auid!=-1, -S all, syscalls in its own order."""
    line = re.sub(r' -k (\S+)$', r' -F key=\1', line) if not line.startswith('-w ') else line
    line = line.replace('auid!=unset', 'auid!=-1').replace('-a always,exit -F path=', '-a always,exit -S all -F path=')
    return line.replace('-S adjtimex,settimeofday,clock_settime', '-S settimeofday,adjtimex,clock_settime')


class FakeAudit:
    def __init__(self, files=None, enabled=1, installed=True, load_fails=False):
        self.files, self.enabled, self.installed, self.load_fails = dict(files or {'10-base-config.rules': BASE}), enabled, installed, load_fails
        self.loaded, self.calls = [], []
        self.load()

    def audit_files(self):
        return sorted(self.files.items())

    def audit_status(self):
        return {'installed': self.installed, 'enabled': self.enabled}

    def audit_loaded(self):
        return '\n'.join(self.loaded) + '\n' if self.loaded else 'No rules\n'

    def is_privileged(self, path):
        return path in PRIVILEGED

    def load(self):
        if self.enabled == 2:
            return  # augenrules gives no warning; the loaded set simply does not change
        rules = []
        for _, data in sorted(self.files.items()):
            for line in data.decode().splitlines():
                if line.startswith(('-a', '-w')):
                    rules.append(auditctl_form(line))
        self.loaded = rules

    def install_rules(self, name, content):
        if self.load_fails:
            raise OSError('augenrules --load failed; the previous file was put back')
        self.calls.append(name)
        if content is None:
            self.files.pop(name, None)
        else:
            self.files[name] = content
        self.load()


class AuditRulesCase(unittest.TestCase):
    CONTROL, PARAMS, FILE = None, None, None

    def family(self, system):
        from vm.ubuntu.family_audit import AuditRulesFamily
        return AuditRulesFamily(self.CONTROL, system)

    def cycle(self, system):
        family = self.family(system)
        family.validate(self.PARAMS)
        family.check_eligible(self.PARAMS)
        before = family.read_state(self.PARAMS)
        expected = family.expected_after(self.PARAMS, before)
        family.apply(self.PARAMS)
        self.assertEqual(family.read_state(self.PARAMS), expected)
        return family, before

    def refused(self, system):
        with self.assertRaises(ValueError):self.family(system).check_eligible(self.PARAMS)

    def collected(self, system):
        """The collector's own parser over persistent files and the loaded set."""
        from vm.ubuntu.probes import audit_rules
        return (audit_rules('\n'.join(d.decode() for _, d in system.audit_files())), audit_rules(system.audit_loaded()))


class TimeChangeTests(AuditRulesCase):
    CONTROL, PARAMS, FILE = '6.3.3.4', {'ruleset': 'time-change'}, '60-fyp-cis-time-change.rules'

    def test_writes_the_cis_rules_loads_them_and_the_predicate_passes(self):
        from backends.ubuntu.predicates import evaluate
        from tests.integration.ubuntu_fixtures import observation
        system = FakeAudit()
        family, before = self.cycle(system)
        text = system.files[self.FILE].decode()
        for line in ('-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change',
                     '-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change',
                     '-w /etc/localtime -p wa -k time-change'):
            self.assertIn(line + '\n', text)
        persistent, loaded = self.collected(system)
        facts = {'audit_architectures': observation(['b32', 'b64']), 'persistent_audit_rules': observation(persistent),
                 'loaded_audit_rules': observation(loaded)}
        self.assertEqual(evaluate('6.3.3.4', facts).status.value, 'Compliant')
        family.restore(self.PARAMS, before)
        self.assertEqual((family.read_state(self.PARAMS), self.FILE in system.files), (before, False))

    def test_locked_missing_wiping_or_unparseable_configurations_are_refused(self):
        for system in (FakeAudit(enabled=2), FakeAudit(installed=False),
                       FakeAudit(files={'10-base-config.rules': BASE, '99-finalize.rules': b'-e 2\n'}),
                       # A -D with options stays in place under augenrules and may delete these rules; the collector parser
                       # refuses it. (A bare -D is moved to the top: StockUbuntuFileTests.)
                       FakeAudit(files={'10-base-config.rules': BASE, '90-reset.rules': b'-D -k time-change\n'}),
                       FakeAudit(files={'10-base-config.rules': BASE, '20-x.rules': b'-a never,exit -S all\n'})):
            with self.subTest(files=sorted(system.files), enabled=system.enabled), self.assertRaises(ValueError):
                self.family(system).check_eligible(self.PARAMS)

    def test_a_failed_load_is_raised(self):
        with self.assertRaises(OSError):self.family(FakeAudit(load_fails=True)).apply(self.PARAMS)


class StockUbuntuFileTests(AuditRulesCase):
    """Live 2026-11-07 10:1x: the 6.3.3.4 preview was refused right after auditd was installed. Ubuntu ships its base
    rules as /etc/audit/rules.d/audit.rules (bare -D first), which sorts after 60-fyp-cis-*.rules. augenrules (audit
    3.0.7, init.d/augenrules) moves the last bare -D to the first line of the generated file, so it never deletes
    rules from another file; the family refused it, and the collector cleared the earlier files' rules."""
    CONTROL, PARAMS, FILE = '6.3.3.4', {'ruleset': 'time-change'}, '60-fyp-cis-time-change.rules'

    def test_the_stock_audit_rules_file_does_not_block_the_change(self):
        self.family(FakeAudit(files={'audit.rules': BASE})).check_eligible(self.PARAMS)

    def test_a_bare_minus_d_in_a_later_file_keeps_the_earlier_rules_in_the_scan(self):
        from vm.ubuntu.probes import audit_rules
        text = '-w /etc/localtime -p wa -k time-change' + chr(10) + BASE.decode()  # our file, then audit.rules
        self.assertEqual([r['path'] for r in audit_rules(text)], ['/etc/localtime'])

    def test_after_the_fix_the_collected_rules_read_compliant_beside_the_stock_file(self):
        from backends.ubuntu.predicates import evaluate
        from tests.integration.ubuntu_fixtures import observation
        system = FakeAudit(files={'audit.rules': BASE})
        self.cycle(system)
        persistent, loaded = self.collected(system)
        facts = {'audit_architectures': observation(['b32', 'b64']), 'persistent_audit_rules': observation(persistent),
                 'loaded_audit_rules': observation(loaded)}
        self.assertEqual(evaluate('6.3.3.4', facts).status.value, 'Compliant')


class IdentityTests(AuditRulesCase):
    CONTROL, PARAMS, FILE = '6.3.3.8', {'ruleset': 'identity'}, '60-fyp-cis-identity.rules'

    def test_all_eight_identity_paths_are_watched(self):
        from vm.ubuntu.spec import IDENTITY_PATHS
        system = FakeAudit()
        self.cycle(system)
        text = system.files[self.FILE].decode()
        for path in IDENTITY_PATHS:
            self.assertIn('-w %s -p wa -k identity\n' % path, text)
        with self.assertRaises(ValueError):self.family(system).validate({'ruleset': 'time-change'})


class PrivilegedTests(AuditRulesCase):
    CONTROL, FILE = '6.3.3.6', '60-fyp-cis-privileged.rules'
    PARAMS = {'paths': sorted(PRIVILEGED), 'uid_min': 1000}

    def test_one_rule_per_inventoried_binary_and_restore(self):
        system = FakeAudit()
        family, before = self.cycle(system)
        text = system.files[self.FILE].decode()
        for path in PRIVILEGED:
            self.assertIn('-a always,exit -F path=%s -F perm=x -F auid>=1000 -F auid!=unset -k privileged\n' % path, text)
        family.restore(self.PARAMS, before)
        self.assertEqual(family.read_state(self.PARAMS), before)

    def test_parameters_are_bounded_and_the_inventory_rechecked(self):
        family = self.family(FakeAudit())
        for bad in ({'paths': ['/usr/bin/su', '/usr/bin/passwd'], 'uid_min': 1000},  # not sorted
                    {'paths': ['/usr/bin/../bin/sh'], 'uid_min': 1000}, {'paths': ['relative'], 'uid_min': 1000},
                    {'paths': [], 'uid_min': 1000}, {'paths': ['/usr/bin/su'], 'uid_min': True},
                    {'paths': ['/usr/bin/su'], 'uid_min': 1000, 'x': 1}, {'paths': ['/usr/bin/su a'], 'uid_min': 1000}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):family.validate(bad)
        params = {'paths': sorted(PRIVILEGED | {'/usr/bin/gone'}), 'uid_min': 1000}
        with self.assertRaises(ValueError):self.family(FakeAudit()).check_eligible(params)


class AuditRegistryTests(unittest.TestCase):
    def test_host_and_target_registries_agree_and_planners_use_the_evidence(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())
        expected = {'6.3.3.4': {'ruleset': 'time-change'}, '6.3.3.8': {'ruleset': 'identity'},
                    '6.3.3.6': {'paths': ['/usr/bin/passwd'], 'uid_min': 1000}}
        ev = evidence(list(expected))
        obs = cases()
        for cid in expected:
            key, value = FAILURES[cid]
            obs[cid][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        for cid, params in expected.items():
            action = 'ubuntu.%s.v1' % cid
            self.assertEqual((FAMILIES[action].version, FAMILIES[action].implementation_sha256),
                             (target[action].version, target[action].implementation_sha256))
            self.assertEqual(FAMILIES[action].propose(cid, ev), params, cid)
        obs['6.3.3.6']['privileged_inventory'] = observation('incomplete')
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES['ubuntu.6.3.3.6.v1'].propose('6.3.3.6', ev))
