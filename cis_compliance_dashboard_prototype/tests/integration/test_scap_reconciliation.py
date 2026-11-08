"""SCAP rule results as conflict-checked subchecks next to direct probes. Synthetic fixtures only."""
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from tests.integration.ubuntu_fixtures import cases, observation
from tests.integration.test_ubuntu_evidence import envelope

APP = Path(__file__).resolve().parents[2]
PREFIX = 'xccdf_org.ssgproject.content_rule_'


def with_scap(cid, results=None, *, base=None, default='pass'):
    from vm.ubuntu.spec import SCAP_RULES
    facts = dict(base if base is not None else cases()[cid])
    facts['scap_rules'] = observation({r: (results or {}).get(r[len(PREFIX):], default) for r in SCAP_RULES[cid]})
    return facts


def status(cid, facts, **kwargs):
    from backends.ubuntu.predicates import evaluate
    return evaluate(cid, facts, **kwargs).status.value


class ScapMappingTests(unittest.TestCase):
    def test_helper_rule_map_equals_pinned_catalogue_and_lock(self):
        from vm.ubuntu.spec import SCAP_RULES, SCAP_PROFILE, SCAP_DATASTREAM_SHA256
        catalogue = json.loads((APP/'catalogues'/'ubuntu2204.json').read_text(encoding='utf-8'))
        lock = json.loads((APP/'catalogues'/'source-lock.json').read_text(encoding='utf-8'))
        self.assertEqual({c['control_id']: tuple(c['scap_rule_ids']) for c in catalogue['controls'] if c['scap_rule_ids']},
                         SCAP_RULES)
        self.assertNotIn('1.2.2.1', SCAP_RULES)
        self.assertEqual(SCAP_PROFILE, lock['profile_id'])
        self.assertEqual(SCAP_DATASTREAM_SHA256, lock['datastream_sha256'])


class ReconciliationTests(unittest.TestCase):
    def test_agreeing_pass_is_compliant_and_scap_subchecks_are_shown(self):
        from backends.ubuntu.predicates import evaluate
        result = evaluate('1.5.1', with_scap('1.5.1'))
        self.assertEqual(result.status.value, 'Compliant')
        self.assertIn('scap.sysctl_kernel_randomize_va_space', [c.name for c in result.checks])

    def test_scap_failure_without_direct_failure_is_conflict_unknown(self):
        from backends.ubuntu.predicates import evaluate
        result = evaluate('1.5.1', with_scap('1.5.1', {'sysctl_kernel_randomize_va_space': 'fail'}))
        self.assertEqual(result.status.value, 'Unknown')
        self.assertIn('conflict', [c.state for c in result.checks])

    def test_scap_pass_never_cancels_direct_failure(self):
        base = cases()['1.5.1']; base['persistent.kernel.randomize_va_space'] = observation(0)
        self.assertEqual(status('1.5.1', with_scap('1.5.1', base=base)), 'Non-Compliant')
        self.assertEqual(status('1.5.1', with_scap('1.5.1', base=base, default='fail')), 'Non-Compliant')

    def test_unresolved_and_error_results_never_pass(self):
        for result, expected in (('notchecked', 'Unknown'), ('unknown', 'Unknown'), ('informational', 'Unknown'),
                                 ('fixed', 'Unknown'), ('notselected', 'Unknown'), ('error', 'Error')):
            with self.subTest(result=result):
                self.assertEqual(status('1.5.1', with_scap('1.5.1', default=result)), expected)
        failed = dict(cases()['1.5.1']); failed['scap_rules'] = {'state': 'error', 'value': None}
        self.assertEqual(status('1.5.1', failed), 'Error')

    def test_rule_set_must_match_pinned_mapping(self):
        from backends.ubuntu.predicates import evaluate
        facts = with_scap('1.5.1'); facts['scap_rules']['value'][PREFIX+'sysctl_fs_suid_dumpable'] = 'pass'
        with self.assertRaises(ValueError):evaluate('1.5.1', facts)
        facts = with_scap('1.5.1'); facts['scap_rules']['value'] = {}
        with self.assertRaises(ValueError):evaluate('1.5.1', facts)
        # Retired 1.2.2.1 (read only from stored v1 scans) has no rules, so any SCAP result for it is refused.
        with self.assertRaises(ValueError):evaluate('1.2.2.1', dict(cases(legacy=True)['1.2.2.1'], scap_rules=observation({})))

    def test_not_applicable_is_neutral_and_cannot_pass_alone(self):
        self.assertEqual(status('6.3.1.3', with_scap('6.3.1.3', {'zipl_audit_argument': 'notapplicable'})), 'Compliant')
        self.assertEqual(status('6.3.1.3', with_scap('6.3.1.3', base={}, default='notapplicable')), 'Unknown')

    def test_reviewed_avahi_retention_explains_removal_rule_failure(self):
        base = {'package.avahi-daemon': observation('installed')}
        for unit in ('avahi-daemon.service', 'avahi-daemon.socket'):
            base[unit+'.active'] = observation('inactive'); base[unit+'.enabled'] = observation('masked')
        facts = with_scap('2.1.2', {'package_avahi_removed': 'fail'}, base=base)
        self.assertEqual(status('2.1.2', facts, reviewed_avahi_retention=True), 'Compliant')
        self.assertEqual(status('2.1.2', facts), 'Unknown')


class LiveEnvelopeTests(unittest.TestCase):
    def parse(self, doc):
        from backends.ubuntu.envelope import ExpectedEvidence, parse_bundle
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        return parse_bundle(json.dumps(doc).encode(), expected, now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))

    def test_live_evidence_must_account_for_scap_rules_but_fixtures_need_not(self):
        from vm.ubuntu.spec import SCAP_RULES
        self.assertEqual(len(self.parse(envelope()).assessments), 30)
        doc = envelope(); doc['evidence_mode'] = 'Live (SSH)'
        with self.assertRaises(ValueError):self.parse(doc)
        for cid in SCAP_RULES:
            doc['observations'][cid] = with_scap(cid, base=doc['observations'][cid])
        bundle = self.parse(doc)
        self.assertEqual(sum(a.status.value == 'Compliant' for a in bundle.assessments), 30)  # v2: no Manual control


class TargetSanitizerTests(unittest.TestCase):
    RULES = (PREFIX+'a_rule', PREFIX+'b_rule')

    def xml(self, rows, *, target='fixture-host', profile='p'):
        body = ''.join(f'<rule-result idref="{r}"><result>{v}</result><message>SECRET-SENTINEL</message></rule-result>'
                       for r, v in rows)
        return (f'<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult id="t"><target>{target}</target>'
                f'<profile idref="{profile}"/>{body}<set-value idref="x">SECRET-SENTINEL</set-value></TestResult></Benchmark>').encode()

    def sanitize(self, raw, **kwargs):
        from vm.ubuntu.scap_results import sanitize_results
        return sanitize_results(raw, rule_ids=self.RULES, profile_id='p', expected_target='FIXTURE-HOST', **kwargs)

    def test_selected_results_only_and_missing_is_notchecked(self):
        result = self.sanitize(self.xml([(self.RULES[0], 'pass'), (PREFIX+'other', 'notselected')]))
        self.assertEqual(result, {self.RULES[0]: 'pass', self.RULES[1]: 'notchecked'})
        self.assertNotIn('SECRET-SENTINEL', repr(result))

    def test_unsafe_mismatched_duplicate_or_out_of_scope_xml_refused(self):
        for raw in (b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/shadow">]><x>&e;</x>',
                    self.xml([(self.RULES[0], 'pass'), (self.RULES[0], 'fail')]),
                    self.xml([(PREFIX+'other', 'fail')]),
                    self.xml([(self.RULES[0], 'bogus')]),
                    self.xml([(self.RULES[0], 'pass')], target='other'),
                    self.xml([(self.RULES[0], 'pass')], profile='q'),
                    b'<not-xml', b' ' * (100*1024*1024 + 1)):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):self.sanitize(raw)

    def test_target_argv_is_fixed_read_only_and_bound_to_request(self):
        from vm.ubuntu.scap_results import scan_argv, RESULT_ROOT, DATASTREAM
        from vm.ubuntu.spec import SCAP_RULES, SCAP_PROFILE
        from vm.ubuntu.spec import SCAP_TAILORED_PROFILE
        argv = scan_argv('a'*32)
        self.assertEqual(argv[:3], ('/usr/bin/oscap', 'xccdf', 'eval'))
        self.assertEqual(argv[argv.index('--profile')+1], SCAP_TAILORED_PROFILE)  # extends SCAP_PROFILE
        self.assertEqual(argv[argv.index('--results')+1], RESULT_ROOT+'/'+'a'*32+'/xccdf.xml')
        self.assertEqual(argv[-1], DATASTREAM)
        self.assertNotIn('--rule', argv)  # OpenSCAP 1.2.17 honours only one; see test_scap_tailoring
        for forbidden in ('--remediate', '--fetch-remote-resources', '--report', '--oval-results'):
            self.assertNotIn(forbidden, argv)
        for bad in ('../x', 'A'*32, 'a'*31):
            with self.subTest(bad=bad), self.assertRaises(ValueError):scan_argv(bad)


class CollectionScapTests(unittest.TestCase):
    def io(self, results):
        from tests.integration.test_collection import FakeIO
        io = FakeIO()
        io.scap_results = results
        return io

    def test_scan_results_become_per_control_observations_once(self):
        from vm.ubuntu.collection import collect_observations
        from vm.ubuntu.spec import SCAP_RULES
        calls = []
        def results(request_id, engine_version):
            calls.append((request_id, engine_version))
            return {r: 'pass' for rules in SCAP_RULES.values() for r in rules}
        facts = collect_observations(self.io(results), registered_firewall_manager='ufw',
                                     scap_request=('a'*32, '1.3.7'))
        self.assertEqual(calls, [('a'*32, '1.3.7')])
        for cid, rules in SCAP_RULES.items():
            self.assertEqual(set(facts[cid]['scap_rules']['value']), set(rules))

    def test_failed_scan_is_explicit_error_and_no_request_means_no_scan(self):
        from vm.ubuntu.collection import collect_observations
        from vm.ubuntu.spec import SCAP_RULES
        def broken(request_id, engine_version):raise OSError('fixture engine failure')
        facts = collect_observations(self.io(broken), scap_request=('a'*32, '1.3.7'))
        for cid in SCAP_RULES:
            self.assertEqual(facts[cid]['scap_rules'], {'state': 'error', 'value': None})
        untouched = collect_observations(self.io(broken))
        self.assertFalse(any('scap_rules' in facts for facts in untouched.values()))
        with self.assertRaises(ValueError):collect_observations(self.io(broken), scap_request=('../x', '1.3.7'))

    def test_host_plan_and_target_argv_are_identical(self):
        from backends.ubuntu.scap_plan import prepare_scan
        from vm.ubuntu.scap_results import scan_argv
        self.assertEqual(prepare_scan(APP/'catalogues', 'a'*32, engine_version='1.3.7', fixture=True).argv, scan_argv('a'*32))

    def test_live_collection_without_scap_engine_is_refused_on_target(self):
        from vm.ubuntu.provenance import run_collection
        from tests.integration.test_provenance import request, clock, verified_io
        with self.assertRaises(ValueError):run_collection(verified_io(), request(evidence_mode='Live (SSH)'), clock=clock())
