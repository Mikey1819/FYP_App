"""CIS 2.4.1.2 replaces 1.2.2.1 in the 30-control selection (administrator decision 2026-11-08; same "System and software
security" area). CIS v2.0.0 p.324: if cron is installed, /etc/crontab is owned by uid 0 and gid 0 and grants no group or
other permissions (`stat -Lc`); remediation `chown root:root` and `chmod og-rwx`; default 644. The selection is versioned:
new scans are catalogue v2, stored v1 scans (with 1.2.2.1) still verify exactly and are shown under the current selection.
Fixtures only; no VM."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tests.integration.ubuntu_fixtures import observation

V1, V2 = 'ubuntu2204-cis2-selected30-v1', 'ubuntu2204-cis2-selected30-v2'


def crontab_facts(mode=0o644, uid=0, gid=0, cron='installed'):
    return {'package.cron': observation(cron), 'crontab.mode': observation(mode), 'crontab.uid': observation(uid),
            'crontab.gid': observation(gid)}


class SelectionTests(unittest.TestCase):
    def test_2_4_1_2_replaces_1_2_2_1_and_old_scans_keep_their_selection(self):
        from backends.ubuntu.catalogue import CATALOGUE_ID, CATALOGUE_IDS, EXPECTED_IDS, RETIRED
        self.assertEqual(CATALOGUE_ID, V2)
        self.assertEqual(len(EXPECTED_IDS), 30)
        self.assertIn('2.4.1.2', EXPECTED_IDS)
        self.assertNotIn('1.2.2.1', EXPECTED_IDS)
        self.assertEqual(CATALOGUE_IDS[V1], (EXPECTED_IDS - {'2.4.1.2'}) | {'1.2.2.1'})
        self.assertEqual(RETIRED, frozenset({'1.2.2.1'}))

    def test_the_catalogue_entry_comes_from_the_pinned_sources(self):
        from backends.ubuntu.adapter import _controls
        control = _controls()['2.4.1.2']
        self.assertEqual(control.title, 'Ensure permissions on /etc/crontab are configured')
        raw = json.loads((Path(__file__).resolve().parents[2] / 'catalogues' / 'ubuntu2204.json').read_text(encoding='utf-8'))
        entry = next(c for c in raw['controls'] if c['control_id'] == '2.4.1.2')
        self.assertEqual((entry['area'], entry['server_level'], entry['cis_assessment_type'], entry['source_pages']),
                         ('System and software security', 1, 'Automated', [324]))
        self.assertEqual(sorted(entry['scap_rule_ids']), ['xccdf_org.ssgproject.content_rule_file_groupowner_crontab',
                                                          'xccdf_org.ssgproject.content_rule_file_owner_crontab',
                                                          'xccdf_org.ssgproject.content_rule_file_permissions_crontab'])

    def test_the_risk_entry_uses_the_documented_categories(self):
        from backends.ubuntu.risk import load_policy
        policy = load_policy()
        self.assertTrue(policy.activated)
        raw = json.loads((Path(__file__).resolve().parents[2] / 'catalogues' / 'ubuntu2204-risk.json').read_text(encoding='utf-8'))
        self.assertNotIn('1.2.2.1', raw['controls'])
        entry = raw['controls']['2.4.1.2']
        self.assertEqual((entry['consequence'], entry['privilege_scope'], entry['surface'], entry['level'], entry['assessment']),
                         ('misuse_easier', 'privilege_escalation_path', 'local_account', 1, 'Automated'))

    def test_the_selected_scap_rules_and_pinned_tailoring_include_the_crontab_rules(self):
        import hashlib
        from backends.ubuntu.scap_tailoring import build_tailoring
        from vm.ubuntu.spec import SCAP_RULES, SCAP_TAILORING_SHA256
        self.assertEqual(len(SCAP_RULES['2.4.1.2']), 3)
        self.assertNotIn('1.2.2.1', SCAP_RULES)
        self.assertEqual(hashlib.sha256(build_tailoring()).hexdigest(), SCAP_TAILORING_SHA256)


class PredicateTests(unittest.TestCase):
    def status(self, facts):
        from backends.ubuntu.predicates import evaluate
        return evaluate('2.4.1.2', facts).status.value

    def test_cis_default_644_fails_and_600_root_root_passes(self):
        self.assertEqual(self.status(crontab_facts(0o644)), 'Non-Compliant')
        self.assertEqual(self.status(crontab_facts(0o600)), 'Compliant')
        self.assertEqual(self.status(crontab_facts(0o400)), 'Compliant')  # more restrictive is fine

    def test_wrong_owner_or_group_fails(self):
        self.assertEqual(self.status(crontab_facts(0o600, uid=1000)), 'Non-Compliant')
        self.assertEqual(self.status(crontab_facts(0o600, gid=4)), 'Non-Compliant')

    def test_without_cron_the_control_is_not_assessed_as_a_pass(self):
        self.assertEqual(self.status(crontab_facts(cron='absent')), 'Unknown')

    def test_an_unreadable_file_is_an_error(self):
        facts = crontab_facts()
        facts['crontab.mode'] = {'state': 'error', 'value': None}
        self.assertEqual(self.status(facts), 'Error')


class FakeCronSystem:
    def __init__(self, path):
        self.path = path

    def crontab_stat(self):
        info = os.lstat(self.path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ValueError('not a regular file')
        return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}

    def set_crontab(self, mode, uid, gid):
        self.calls = getattr(self, 'calls', []) + [(mode, uid, gid)]
        os.chmod(self.path, mode)  # ownership is not changeable in the test; recorded instead
        self.owner = (uid, gid)


class FamilyTests(unittest.TestCase):
    PARAMS = {'path': '/etc/crontab', 'owner': 0, 'group': 0, 'remove': 'og-rwx'}

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.file = Path(folder.name) / 'crontab'
        self.file.write_text('# m h dom mon dow user command\n')
        os.chmod(self.file, 0o644)

    def family(self, system):
        from vm.ubuntu.family_cron import CrontabPermissionFamily
        return CrontabPermissionFamily(system)

    def test_plan_matches_chown_root_and_chmod_og_rwx(self):
        system = FakeCronSystem(self.file)
        family = self.family(system)
        family.validate(self.PARAMS)
        before = json.loads(family.read_state(self.PARAMS))
        after = json.loads(family.expected_after(self.PARAMS, family.read_state(self.PARAMS)))
        self.assertEqual(after, dict(before, mode=before['mode'] & ~0o077, uid=0, gid=0))  # og-rwx keeps owner bits
        family.apply(self.PARAMS)
        self.assertEqual(system.calls, [(before['mode'] & ~0o077, 0, 0)])
        self.assertEqual(system.owner, (0, 0))

    def test_restore_returns_the_recorded_mode_and_ownership(self):
        system = FakeCronSystem(self.file)
        family = self.family(system)
        before = family.read_state(self.PARAMS)
        family.apply(self.PARAMS)
        family.restore(self.PARAMS, before)
        recorded = json.loads(before)
        self.assertEqual(system.calls[-1], (recorded['mode'], recorded['uid'], recorded['gid']))

    def test_only_the_registered_change_is_managed(self):
        family = self.family(FakeCronSystem(self.file))
        for params in (dict(self.PARAMS, path='/etc/passwd'), dict(self.PARAMS, owner=1000), dict(self.PARAMS, remove='o-rwx')):
            with self.subTest(params=params), self.assertRaises(ValueError):
                family.validate(params)

    def test_a_symlinked_crontab_is_refused(self):
        link = self.file.with_name('link')
        try:
            link.symlink_to(self.file)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable on this host')
        with self.assertRaises(ValueError):
            self.family(FakeCronSystem(link)).check_eligible(self.PARAMS)

    def test_host_and_target_registries_agree_and_the_spec_proposes_from_evidence(self):
        from types import SimpleNamespace as N
        from backends.ubuntu.actions import FAMILIES
        from backends.ubuntu.predicates import evaluate
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        target = build(FakeCoreSystem())['ubuntu.2.4.1.2.v1']
        spec = FAMILIES['ubuntu.2.4.1.2.v1']
        self.assertEqual((spec.version, spec.implementation_sha256), (target.version, target.implementation_sha256))
        self.assertEqual(spec.recovery['scope'], ['/etc/crontab'])
        facts = crontab_facts()
        ev = N(raw=json.dumps({'observations': {'2.4.1.2': facts}}).encode(), assessments=[evaluate('2.4.1.2', facts)])
        self.assertEqual(spec.propose('2.4.1.2', ev), self.PARAMS)
        compliant = crontab_facts(0o600)
        ev = N(raw=json.dumps({'observations': {'2.4.1.2': compliant}}).encode(), assessments=[evaluate('2.4.1.2', compliant)])
        self.assertIsNone(spec.propose('2.4.1.2', ev))

    def test_the_patch_job_and_its_host_spec_are_retired(self):
        from backends.ubuntu.actions import FAMILIES
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_core_family import FakeCoreSystem
        self.assertNotIn('ubuntu.1.2.2.1.v1', FAMILIES)
        self.assertNotIn('ubuntu.1.2.2.1.v1', build(FakeCoreSystem()))


class StoredSelectionTests(unittest.TestCase):
    def test_a_v1_scan_still_verifies_and_is_shown_under_the_current_selection(self):
        from datetime import datetime, timezone
        from backends.ubuntu.envelope import ExpectedEvidence
        from backends.ubuntu.storage import UbuntuStore
        from tests.integration.test_ubuntu_evidence import envelope
        doc = envelope(catalogue=V1)
        self.assertIn('1.2.2.1', doc['observations'])
        raw = json.dumps(doc).encode()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        with tempfile.TemporaryDirectory() as folder:
            store = UbuntuStore(Path(folder) / 'ubuntu.sqlite3')
            store.save_evidence(raw, expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
            loaded = store.get_evidence(__import__('hashlib').sha256(raw).hexdigest(), expected.target_id,
                                        expected.registration_epoch)
        shown = {a.control_id for a in loaded.assessments}
        self.assertNotIn('1.2.2.1', shown)  # retired: verified, not shown
        self.assertEqual(len(shown), 29)

    def test_a_v2_scan_carries_2_4_1_2(self):
        from backends.ubuntu.envelope import ExpectedEvidence, parse_bundle
        from datetime import datetime, timezone
        from tests.integration.test_ubuntu_evidence import envelope
        doc = envelope()
        self.assertEqual(doc['catalogue'], V2)
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        bundle = parse_bundle(json.dumps(doc).encode(), expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
        self.assertIn('2.4.1.2', {a.control_id for a in bundle.assessments})
        self.assertEqual(len(bundle.assessments), 30)


if __name__ == '__main__':
    unittest.main()
