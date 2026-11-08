"""6.3.3.4 OpenSCAP wording (administrator decision 2026-11-07, "Follow CIS"): CIS v2.0.0 (PDF pp. 784-786) requires
`-S adjtimex,settimeofday,clock_settime -k time-change` for b64 and b32 plus the /etc/localtime watch; the pinned
ComplianceAsCode rule audit_rules_time_clock_settime only accepts `-S clock_settime -F a0=0x0`, a narrower form the CIS
rule already covers. When the persistent and loaded CIS rules both pass, that one SCAP failure is advisory, not a
conflict. Live 11:01 and 11:03: the fix applied, both direct checks passed, and the control read Unknown.
Stored evidence evaluated under the earlier rule still loads. Fixture data; no VM."""
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.integration.ubuntu_fixtures import FAILURES, cases, observation

PREFIX = 'xccdf_org.ssgproject.content_rule_'
LIVE_SCAP = {'audit_rules_time_adjtimex': 'pass', 'audit_rules_time_clock_settime': 'fail',
             'audit_rules_time_settimeofday': 'pass', 'audit_rules_time_watch_localtime': 'pass'}


def facts(scap=None, *, failing=False):
    obs = cases()['6.3.3.4']
    if failing:
        key, value = FAILURES['6.3.3.4']
        obs[key] = observation(value)
    obs['scap_rules'] = observation({PREFIX + rule: result for rule, result in (scap or LIVE_SCAP).items()})
    return obs


class AuditInterpretationTests(unittest.TestCase):
    def status(self, obs, **kwargs):
        from backends.ubuntu.predicates import evaluate
        return evaluate('6.3.3.4', obs, **kwargs).status.value

    def test_the_live_scan_reads_compliant_with_the_narrower_scap_rule_advisory(self):
        from backends.ubuntu.predicates import evaluate
        result = evaluate('6.3.3.4', facts())
        self.assertEqual(result.status.value, 'Compliant')
        advisory = [c for c in result.checks if c.name == 'scap.audit_rules_time_clock_settime']
        self.assertEqual([c.state for c in advisory], ['advisory'])

    def test_the_earlier_rule_still_reads_the_conflict(self):
        self.assertEqual(self.status(facts(), cis_audit_authority=False), 'Unknown')

    def test_any_other_failing_scap_rule_is_still_a_conflict(self):
        self.assertEqual(self.status(facts(dict(LIVE_SCAP, audit_rules_time_adjtimex='fail'))), 'Unknown')

    def test_a_direct_failure_is_still_non_compliant(self):
        self.assertEqual(self.status(facts(failing=True)), 'Non-Compliant')

    def test_the_cross_check_labels_it_as_a_documented_difference(self):
        from tools.scap_cross_check import compare
        row = compare('6.3.3.4', facts())
        self.assertEqual((row['direct'], row['scap'], row['verdict']),
                         ('Compliant', 'Non-Compliant', 'Expected disagreement (CIS wording)'))
        other = compare('6.3.3.4', facts(dict(LIVE_SCAP, audit_rules_time_adjtimex='fail')))
        self.assertEqual(other['verdict'], 'Disagree')


class StoredAuditEvidenceTests(unittest.TestCase):
    def test_scans_stored_before_the_decision_load_and_show_the_current_reading(self):
        # The live 11:01/11:03 scans were stored under the SSH decision but before this one.
        from backends.ubuntu import predicates
        from backends.ubuntu.envelope import ExpectedEvidence
        from backends.ubuntu.storage import UbuntuStore
        from tests.integration.test_ubuntu_evidence import envelope
        doc = envelope()
        doc['observations']['6.3.3.4'] = facts()
        raw = json.dumps(doc).encode()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        earlier = predicates.evaluate
        with tempfile.TemporaryDirectory() as folder:
            store = UbuntuStore(Path(folder) / 'ubuntu.sqlite3')
            with mock.patch('backends.ubuntu.envelope.evaluate',
                            lambda cid, obs, **kw: earlier(cid, obs, **{**kw, 'cis_audit_authority': False})):
                old = store.save_evidence(raw, expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
            self.assertEqual(next(a for a in old.assessments if a.control_id == '6.3.3.4').status.value, 'Unknown')
            loaded = store.get_evidence(old.raw_sha256, expected.target_id, expected.registration_epoch)
            self.assertEqual(next(a for a in loaded.assessments if a.control_id == '6.3.3.4').status.value, 'Compliant')
            with mock.patch('backends.ubuntu.storage._snapshot', lambda assessments: 'tampered'):
                with self.assertRaises(ValueError):
                    store.get_evidence(old.raw_sha256, expected.target_id, expected.registration_epoch)


if __name__ == '__main__':
    unittest.main()


PAMD_SCAP = {'audit_rules_usergroup_modification_' + n: 'pass' for n in
             ('group', 'gshadow', 'nsswitch_conf', 'opasswd', 'pam_conf', 'passwd', 'shadow')}
PAMD_SCAP['audit_rules_usergroup_modification_pamd'] = 'fail'  # live 11:20: CIS writes /etc/pam.d, SCAP wants /etc/pam.d/


def identity_facts(scap=None):
    obs = cases()['6.3.3.8']
    obs['scap_rules'] = observation({PREFIX + rule: result for rule, result in (scap or PAMD_SCAP).items()})
    return obs


class IdentityWordingTests(unittest.TestCase):
    """Live 11:20: 6.3.3.8 applied, both direct checks passed, and only audit_rules_usergroup_modification_pamd failed.
    CIS v2.0.0 (PDF p. 801) writes `-w /etc/pam.d -p wa -k identity`; the SCAP watch pattern matches `/etc/pam.d/`
    literally. Same administrator decision (Follow CIS)."""

    def test_the_live_scan_reads_compliant(self):
        from backends.ubuntu.predicates import evaluate
        self.assertEqual(evaluate('6.3.3.8', identity_facts()).status.value, 'Compliant')

    def test_another_failing_identity_rule_is_still_a_conflict(self):
        from backends.ubuntu.predicates import evaluate
        scap = dict(PAMD_SCAP, audit_rules_usergroup_modification_shadow='fail')
        self.assertEqual(evaluate('6.3.3.8', identity_facts(scap)).status.value, 'Unknown')

    def test_scans_stored_under_the_first_wording_list_still_load(self):
        # The 11:20 scan was stored with 6.3.3.4 advisory but 6.3.3.8 not yet: it must load and read 6.3.3.8 Compliant.
        from backends.ubuntu import predicates
        from backends.ubuntu.envelope import ExpectedEvidence
        from backends.ubuntu.storage import UbuntuStore
        from tests.integration.test_ubuntu_evidence import envelope
        doc = envelope()
        doc['observations']['6.3.3.4'] = facts()
        doc['observations']['6.3.3.8'] = identity_facts()
        raw = json.dumps(doc).encode()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        earlier = predicates.evaluate
        with tempfile.TemporaryDirectory() as folder:
            store = UbuntuStore(Path(folder) / 'ubuntu.sqlite3')
            with mock.patch('backends.ubuntu.envelope.evaluate', lambda cid, obs, **kw: earlier(
                    cid, obs, **{**kw, 'audit_wording': predicates.CIS_AUDIT_WORDING_V1})):
                old = store.save_evidence(raw, expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
            statuses = {a.control_id: a.status.value for a in old.assessments}
            self.assertEqual((statuses['6.3.3.4'], statuses['6.3.3.8']), ('Compliant', 'Unknown'))
            loaded = store.get_evidence(old.raw_sha256, expected.target_id, expected.registration_epoch)
            self.assertEqual(next(a for a in loaded.assessments if a.control_id == '6.3.3.8').status.value, 'Compliant')


def minlen_facts(minlen=14, scap='fail'):
    return {'pam_resolution': observation('complete'), 'effective_minlen': observation({'common-password': minlen}),
            'scap_rules': observation({PREFIX + 'accounts_password_pam_minlen': scap})}


class PasswordLengthWordingTests(unittest.TestCase):
    """Live 15:17 and 15:18: 5.3.3.2.2 applied `minlen = 14` in /etc/security/pwquality.conf.d/60-fyp-hardening-cis.conf,
    the effective minlen read 14, and the control read Unknown. CIS v2.0.0 (PDF pp. 607-608) recommends a .conf file in
    pwquality.conf.d and audits both locations; the pinned SCAP rule reads only /etc/security/pwquality.conf. Same
    administrator decision (Follow CIS)."""

    def status(self, obs, **kwargs):
        from backends.ubuntu.predicates import evaluate
        return evaluate('5.3.3.2.2', obs, **kwargs).status.value

    def test_the_live_scan_reads_compliant(self):
        self.assertEqual(self.status(minlen_facts()), 'Compliant')

    def test_a_short_effective_minlen_is_still_non_compliant(self):
        self.assertEqual(self.status(minlen_facts(minlen=8)), 'Non-Compliant')

    def test_an_unresolved_pam_stack_is_never_made_compliant_by_the_advisory(self):
        obs = minlen_facts()
        obs['pam_resolution'] = observation('incomplete')
        self.assertNotEqual(self.status(obs), 'Compliant')

    def test_scans_stored_under_the_second_wording_list_still_load(self):
        from backends.ubuntu import predicates
        from backends.ubuntu.envelope import ExpectedEvidence
        from backends.ubuntu.storage import UbuntuStore
        from tests.integration.test_ubuntu_evidence import envelope
        doc = envelope()
        doc['observations']['6.3.3.8'] = identity_facts()
        doc['observations']['5.3.3.2.2'] = minlen_facts()
        raw = json.dumps(doc).encode()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        earlier = predicates.evaluate
        with tempfile.TemporaryDirectory() as folder:
            store = UbuntuStore(Path(folder) / 'ubuntu.sqlite3')
            with mock.patch('backends.ubuntu.envelope.evaluate', lambda cid, obs, **kw: earlier(
                    cid, obs, **{**kw, 'audit_wording': predicates.CIS_AUDIT_WORDING_V2})):
                old = store.save_evidence(raw, expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
            statuses = {a.control_id: a.status.value for a in old.assessments}
            self.assertEqual((statuses['6.3.3.8'], statuses['5.3.3.2.2']), ('Compliant', 'Unknown'))
            loaded = store.get_evidence(old.raw_sha256, expected.target_id, expected.registration_epoch)
            self.assertEqual(next(a for a in loaded.assessments if a.control_id == '5.3.3.2.2').status.value, 'Compliant')
