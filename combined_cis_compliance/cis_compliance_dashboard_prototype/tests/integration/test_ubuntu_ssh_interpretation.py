"""SSH SCAP conflicts (CIS 5.1.x): CIS audits the effective `sshd -T` value; a SCAP rule that also demands an explicit
config line is advisory when every audited context complies. Stored evidence evaluated under the earlier rule still
loads. Fixture data mirrors the 2026-11-06 live scan of 5.1.10/5.1.19/5.1.21."""
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from tests.integration.ubuntu_fixtures import cases, observation

PREFIX = 'xccdf_org.ssgproject.content_rule_'
LIVE = {'5.1.10': ('hostbasedauthentication', 'disable_host_auth'),
        '5.1.19': ('permitemptypasswords', 'sshd_disable_empty_passwords'),
        '5.1.21': ('permituserenvironment', 'sshd_do_not_permit_user_env')}


def ssh_facts(cid, *, value='no', resolution='complete', scap='fail', contexts=True):
    option, rule = LIVE[cid]
    facts = {'ssh_context_resolution': observation(resolution), 'scap_rules': observation({PREFIX + rule: scap})}
    if contexts:
        facts['ssh_contexts'] = observation([{'context_id': 'global', option: value}])
    return facts


class InterpretationTests(unittest.TestCase):
    def evaluate(self, cid, facts, **kwargs):
        from backends.ubuntu.predicates import evaluate
        return evaluate(cid, facts, **kwargs)

    def test_effective_value_decides_and_the_scap_rule_is_kept_as_an_advisory_subcheck(self):
        for cid in LIVE:
            with self.subTest(cid=cid):
                result = self.evaluate(cid, ssh_facts(cid))
                self.assertEqual(result.status.value, 'Compliant')
                [scap] = [c for c in result.checks if c.name.startswith('scap.')]
                self.assertEqual(scap.state, 'advisory')
                self.assertIn('sshd -T', scap.reason)
                # The earlier rule, kept for stored evidence, still reports the conflict.
                self.assertEqual(self.evaluate(cid, ssh_facts(cid), ssh_effective_authority=False).status.value, 'Unknown')

    def test_guards_are_unchanged(self):
        cid = '5.1.10'
        self.assertEqual(self.evaluate(cid, ssh_facts(cid, value='yes')).status.value, 'Non-Compliant')  # direct fail wins
        self.assertEqual(self.evaluate(cid, ssh_facts(cid, resolution='unsupported')).status.value, 'Unknown')  # Match blocks
        self.assertEqual(self.evaluate(cid, ssh_facts(cid, contexts=False)).status.value, 'Unknown')  # no audited context
        for facts in (ssh_facts(cid, resolution='unsupported'), ssh_facts(cid, contexts=False)):
            [scap] = [c for c in self.evaluate(cid, facts).checks if c.name.startswith('scap.')]
            self.assertEqual(scap.state, 'conflict')  # never advisory without complete, audited contexts
        self.assertEqual(self.evaluate(cid, ssh_facts(cid, scap='error')).status.value, 'Error')
        self.assertEqual(self.evaluate(cid, ssh_facts(cid, scap='pass')).status.value, 'Compliant')

    def test_non_ssh_conflicts_stay_unknown(self):
        facts = dict(cases()['1.5.1'])  # fixture observations: direct sysctl checks all pass
        facts['scap_rules'] = observation({PREFIX + 'sysctl_kernel_randomize_va_space': 'fail'})
        self.assertEqual(self.evaluate('1.5.1', facts).status.value, 'Unknown')


class StoredEvidenceTests(unittest.TestCase):
    def test_evidence_stored_under_the_earlier_rule_loads_and_is_shown_under_the_current_one(self):
        from backends.ubuntu import predicates
        from backends.ubuntu.envelope import ExpectedEvidence
        from backends.ubuntu.storage import UbuntuStore
        from tests.integration.test_ubuntu_evidence import envelope
        doc = envelope()
        doc['observations']['5.1.10'] = ssh_facts('5.1.10')
        raw = json.dumps(doc).encode()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        earlier = predicates.evaluate
        with tempfile.TemporaryDirectory() as folder:
            store = UbuntuStore(Path(folder) / 'ubuntu.sqlite3')
            with mock.patch('backends.ubuntu.envelope.evaluate',
                            lambda cid, facts, **kw: earlier(cid, facts, ssh_effective_authority=False)):
                old = store.save_evidence(raw, expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
            self.assertEqual(next(a for a in old.assessments if a.control_id == '5.1.10').status.value, 'Unknown')
            loaded = store.get_evidence(old.raw_sha256, expected.target_id, expected.registration_epoch)
            self.assertEqual(next(a for a in loaded.assessments if a.control_id == '5.1.10').status.value, 'Compliant')
            # A snapshot that matches neither rule is still rejected.
            with mock.patch('backends.ubuntu.storage._snapshot', lambda assessments: 'tampered'):
                with self.assertRaises(ValueError):
                    store.get_evidence(old.raw_sha256, expected.target_id, expected.registration_epoch)
