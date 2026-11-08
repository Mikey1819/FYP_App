"""Ubuntu risk derivation reuses the Windows rubric; synthetic fixtures only, attributes unreviewed."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
from backends.ubuntu.envelope import ExpectedEvidence
from system.contracts import RecordRef

APP = Path(__file__).resolve().parents[2]
MANIFEST = APP/'catalogues'/'ubuntu2204-risk.json'


def evidence(failing=(), *, time='2026-11-06T00:00:01+00:00', mode='Synthetic fixture', lock='c'*64, changes=None):
    from backends.ubuntu.predicates import evaluate
    facts = cases()
    for cid in failing:
        key, value = FAILURES[cid]
        facts[cid][key] = observation(value)
    for cid, (key, value) in (changes or {}).items():
        facts[cid][key] = value if isinstance(value, dict) and set(value) == {'state', 'value'} else observation(value)
    expected = ExpectedEvidence('ubuntu:fixture', 'epoch', 'UBUNTU-FIXTURE', 'a'*32, 'r', 'b'*64, lock, 'd'*64, mode)
    return SimpleNamespace(expected=expected, completed_at=time,
                           assessments=tuple(evaluate(cid, facts[cid]) for cid in sorted(facts)))


def item(name, round_id, ev):
    from backends.ubuntu.risk import RiskInput
    return RiskInput(RecordRef('ubuntu', 'ubuntu:fixture', name), round_id, ev)


def pending_policy():
    """The same manifest as an unreviewed draft, for tests of the pending-review behaviour."""
    from backends.ubuntu.risk import validate_policy
    doc = json.loads(MANIFEST.read_text(encoding='utf-8'))
    doc.update(review_status='pending_human_review', reviewer=None, reviewed_at=None)
    return validate_policy(doc)


class RiskPolicyTests(unittest.TestCase):
    def test_manifest_covers_30_controls_matches_catalogue_and_records_its_approval(self):
        # Superseded "is not activated": the user approved the manifest in chat on 2026-11-06 (recorded as a
        # blanket approval, not an itemized review). A draft copy still refuses scoring (RankTests).
        from backends.ubuntu.risk import load_policy
        policy = load_policy()
        self.assertEqual(len(policy.controls), 30)
        self.assertTrue(policy.activated)
        self.assertIn('reviewed by Teoh Kai Hong', policy.version_label)
        self.assertIn('not an itemized review', policy.version_label)
        self.assertFalse(pending_policy().activated)

    def test_likelihood_follows_windows_level_classification_mapping(self):
        from backends.ubuntu.risk import load_policy, derive
        policy = load_policy()
        values = {cid: derive(policy, cid).likelihood for cid in policy.controls}
        self.assertEqual(values['2.4.1.2'], 4)  # L1 Automated (catalogue v2 has no Manual control)
        self.assertTrue(all(values[c] == 3 for c in values if c.startswith('6.3.')))  # L2 Automated
        self.assertEqual(sorted(values.values()).count(4), 24)  # the 24 L1 Automated controls (v2)
        from hardening.risk import LIKELIHOOD
        self.assertEqual(LIKELIHOOD, {(1, True): 4, (1, False): 3, (2, True): 3, (2, False): 2})

    def test_reused_categories_give_identical_windows_factors(self):
        from backends.ubuntu.risk import load_policy, derive
        from hardening.risk import CONSEQUENCE, PRIVILEGE_SCOPE, SURFACE_EXPOSURE
        policy = load_policy()
        for cid, attrs in policy.controls.items():
            with self.subTest(control=cid):
                d = derive(policy, cid)
                if attrs['consequence'] in CONSEQUENCE:
                    self.assertEqual(d.impact, CONSEQUENCE[attrs['consequence']][0])
                if attrs['privilege_scope'] in PRIVILEGE_SCOPE:
                    self.assertEqual(d.privilege, PRIVILEGE_SCOPE[attrs['privilege_scope']][0])
                if attrs['surface'] in SURFACE_EXPOSURE:
                    self.assertEqual(d.surface_score, SURFACE_EXPOSURE[attrs['surface']])

    def test_invalid_manifests_are_refused(self):
        from backends.ubuntu.risk import validate_policy
        raw = json.loads(MANIFEST.read_text(encoding='utf-8'))
        def broken(change):
            doc = deepcopy(raw); change(doc); return doc
        bad = [
            broken(lambda d: d['controls']['1.5.1'].update(consequence='invented')),
            broken(lambda d: d['controls']['1.5.1'].update(level=2)),
            broken(lambda d: d['controls']['2.4.1.2'].update(assessment='Manual')),
            broken(lambda d: d['controls'].pop('1.5.1')),
            broken(lambda d: d['controls'].update({'9.9.9': d['controls']['1.5.1']})),
            broken(lambda d: d['extensions']['surface'].update(network_logon={'score': 5, 'reason': 'x'})),
            broken(lambda d: next(iter(d['extensions']['surface'].values())).update(score=6)),
            broken(lambda d: d['controls']['1.5.1'].update(rationale='')),
            broken(lambda d: d.update(review_status='approved', reviewer=None)),  # approval without a named reviewer
            broken(lambda d: d.update(review_status='approved', reviewed_at='2026-11-06T06:55:55')),  # naive time
            broken(lambda d: d.update(review_status='pending_human_review')),  # pending yet carrying a reviewer
        ]
        for doc in bad:
            with self.subTest(), self.assertRaises(ValueError):validate_policy(doc)


class RankTests(unittest.TestCase):
    def setUp(self):
        self.policy = pending_policy()  # arithmetic is policy-state independent; the draft also tests refusal

    def rank(self, current, previous=()):
        from backends.ubuntu.risk import rank
        return rank(current, previous, self.policy, allow_draft=True)

    def test_unreviewed_policy_refuses_without_explicit_draft(self):
        from backends.ubuntu.risk import rank
        with self.assertRaisesRegex(ValueError, 'review'):rank(item('now', 'r2', evidence(['1.5.1'])), (), self.policy)

    def test_only_confirmed_failures_are_scored_with_parity_arithmetic(self):
        from hardening.domain import RiskFactors, risk_level
        current = evidence(['1.5.1', '5.1.20', '6.3.1.2'])
        rows = self.rank(item('now', 'r2', current))
        self.assertEqual({r.control_id for r in rows}, {'1.5.1', '5.1.20', '6.3.1.2'})
        for r in rows:
            factors = RiskFactors(r.I, r.E, r.P, r.L, r.D)
            self.assertEqual(r.score, factors.score)
            self.assertEqual(r.level, risk_level(r.score))
            self.assertEqual(r.D, 1)
            self.assertIn('DRAFT', r.risk_policy_version)
            self.assertTrue(any('heuristic' in reason for reason in r.derivation_reasons))
        self.assertEqual([r.rank for r in rows], [1, 2, 3])
        self.assertEqual(rows, tuple(sorted(rows, key=lambda r: (-r.score, r.control_id))))
        statuses = {a.control_id: a.status.value for a in current.assessments}
        self.assertTrue(all(statuses[r.control_id] == 'Non-Compliant' for r in rows))  # only confirmed failures

    def test_drift_1_3_5_and_persistent_failure_with_changed_value_is_3(self):
        current = item('now', 'r3', evidence(['1.5.1', '5.1.20'], time='2026-11-06T02:00:00+00:00'))
        prior = item('before', 'r2', evidence(['5.1.20'], time='2026-11-06T01:00:00+00:00',
                                               changes={'1.5.1': ('runtime.kernel.randomize_va_space', 2)}))
        rows = {r.control_id: r for r in self.rank(current, (prior,))}
        self.assertEqual(rows['1.5.1'].D, 5)  # Compliant before, failing now
        self.assertEqual(rows['5.1.20'].D, 3)
        self.assertEqual(rows['5.1.20'].history_reference, prior.reference)
        changed = item('before', 'r2', evidence(['1.5.1'], time='2026-11-06T01:00:00+00:00',
                                                 changes={'1.5.1': ('persistent.kernel.randomize_va_space', 1)}))
        self.assertEqual({r.control_id: r.D for r in self.rank(current, (changed,))}['1.5.1'], 3)

    def test_unknown_prior_is_skipped_and_incompatible_history_gives_d1(self):
        later = '2026-11-06T02:00:00+00:00'
        current = item('now', 'r3', evidence(['1.5.1'], time=later))
        unknown_prior = item('mid', 'r2', evidence(time='2026-11-06T01:30:00+00:00',
                                                    changes={'1.5.1': ('runtime.kernel.randomize_va_space', {'state': 'missing', 'value': None})}))
        compliant_prior = item('old', 'r1', evidence(time='2026-11-06T01:00:00+00:00'))
        self.assertEqual(self.rank(current, (unknown_prior, compliant_prior))[0].D, 5)
        early = '2026-11-06T01:00:00+00:00'
        for prior in (item('p', 'r2', evidence(['1.5.1'], time=early, mode='Live (SSH)')),
                      item('p', 'r2', evidence(['1.5.1'], time=early, lock='e'*64)),
                      item('p', 'r3', evidence(['1.5.1'], time=early)),            # same round: superseded
                      item('p', 'r2', evidence(['1.5.1'], time='2026-11-06T03:00:00+00:00')),  # not earlier
                      item('now', 'r2', evidence(['1.5.1'], time=early))):         # same record
            with self.subTest(prior=prior.reference.record_id):
                self.assertEqual(self.rank(current, (prior,))[0].D, 1)
        other = item('p', 'r2', evidence(['1.5.1'], time=early))
        object.__setattr__(other, 'reference', RecordRef('ubuntu', 'ubuntu:other', 'p'))
        self.assertEqual(self.rank(current, (other,))[0].D, 1)

    def test_band_edges_on_draft_scores(self):
        rows = {r.control_id: r for r in self.rank(item('now', 'r2', evidence(['6.3.1.2', '5.2.3', '5.1.7', '4.1.3'])))}
        self.assertEqual((rows['6.3.1.2'].score, rows['6.3.1.2'].level), (37, 'Low'))
        self.assertEqual((rows['5.2.3'].score, rows['5.2.3'].level), (40, 'Moderate'))
        self.assertEqual((rows['5.1.7'].score, rows['5.1.7'].level), (62, 'High'))
        self.assertEqual((rows['4.1.3'].score, rows['4.1.3'].level), (80, 'Critical'))
        from hardening.domain import risk_level
        self.assertEqual([risk_level(s) for s in (39, 40, 59, 60, 79, 80)],
                         ['Low', 'Moderate', 'Moderate', 'High', 'High', 'Critical'])

    def test_exposure_uses_only_linux_surface_never_windows_firewall_context(self):
        rows = self.rank(item('now', 'r2', evidence(['5.1.20', '4.1.3'])))
        for r in rows:
            reasons = ' '.join(r.derivation_reasons)
            self.assertNotIn('Public firewall', reasons)
            self.assertNotIn('RDP', reasons)


class AdapterRiskTests(unittest.TestCase):
    def test_snapshot_withholds_unreviewed_risk_and_says_why(self):
        from unittest import mock
        from tests.integration.test_ubuntu_backend_history import UbuntuBackendHistoryTests
        case = UbuntuBackendHistoryTests('test_history_and_snapshot_show_stored_counts_and_fixture_label')
        case.setUp()
        def fail(doc):doc['observations']['1.5.1']['persistent.kernel.randomize_va_space']['value'] = 0
        try:
            case.store_round('fixture-request', fail)
            with mock.patch('backends.ubuntu.adapter._risk_policy', return_value=pending_policy()):
                backend = case.backend()
                self.assertEqual(backend.snapshot('c', 'workflow').findings, ())
                self.assertTrue(any('risk' in r.lower() and 'review' in r.lower()
                                    for r in backend.capabilities('c').blocked_reasons))
            # With the recorded approval the same failure is scored and nothing says "withheld".
            backend = case.backend()
            self.assertEqual([f.control_id for f in backend.snapshot('c', 'workflow').findings], ['1.5.1'])
            self.assertFalse(any('withheld' in r.lower() for r in backend.capabilities('c').blocked_reasons))
        finally:
            case.doCleanups()

    def test_reviewed_policy_path_ranks_with_prior_round_drift(self):
        """In-memory fixture reviewer, independent of the recorded manifest approval."""
        from unittest import mock
        from backends.ubuntu.risk import validate_policy
        from tests.integration.test_ubuntu_backend_history import UbuntuBackendHistoryTests
        doc = json.loads(MANIFEST.read_text(encoding='utf-8'))
        doc.update(review_status='approved', reviewer='Fixture reviewer (test only)', reviewed_at='2026-11-06T00:00:00+00:00')
        approved = validate_policy(doc)
        case = UbuntuBackendHistoryTests('test_history_and_snapshot_show_stored_counts_and_fixture_label')
        case.setUp()
        def fail(doc):doc['observations']['1.5.1']['persistent.kernel.randomize_va_space']['value'] = 0
        try:
            case.store_round('fixture-request', fail)
            def later(doc):fail(doc);doc['completed_at'] = '2026-11-06T00:00:02+00:00'
            case.store_round('fixture-request-2', later)  # strictly later, so the first round is history
            with mock.patch('backends.ubuntu.adapter._risk_policy', return_value=approved):
                backend = case.backend()
                snap = backend.snapshot('c', 'workflow')
                self.assertFalse(any('risk' in r.lower() for r in backend.capabilities('c').blocked_reasons))
        finally:
            case.doCleanups()
        self.assertEqual([f.control_id for f in snap.findings], ['1.5.1'])
        self.assertEqual(snap.findings[0].D, 3)
        self.assertIn('Fixture reviewer', snap.findings[0].risk_policy_version)
        self.assertEqual(snap.step_states[:2], ('done', 'done'))


class ReviewReportTests(unittest.TestCase):
    def test_report_lists_every_control_extension_and_draft_status(self):
        from tools.ubuntu_risk_report import render
        from backends.ubuntu.risk import load_policy
        self.assertIn('DRAFT, pending human review', render(pending_policy()))
        text = render(load_policy())
        self.assertIn('reviewed by Teoh Kai Hong', text)
        for cid in load_policy().controls:
            self.assertIn('| ' + cid + ' |', text)
        for name in ('remote_shell', 'privilege_escalation_path', 'session_hygiene'):
            self.assertIn(name, text)
        self.assertIn('not a measured exploit probability', text)
