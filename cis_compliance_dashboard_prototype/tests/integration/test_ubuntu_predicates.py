from copy import deepcopy
import unittest
from system.contracts import ComplianceStatus as Status
from tests.integration.ubuntu_fixtures import cases, observation, FAILURES


class UbuntuPredicateTests(unittest.TestCase):
    def test_all_30_pass_fail_missing_error_cases(self):
        from backends.ubuntu.predicates import evaluate
        self.assertEqual(len(cases()),30)
        for cid, facts in cases().items():
            with self.subTest(control=cid, state='pass'):
                expected = Status.UNKNOWN if cid == '1.2.2.1' else Status.COMPLIANT
                self.assertEqual(evaluate(cid,facts).status,expected)
            with self.subTest(control=cid, state='fail'):
                failed = deepcopy(facts)
                key, value = FAILURES[cid]
                failed[key] = observation(value)
                if cid == '2.1.2':
                    failed['avahi-daemon.service.active'] = observation('active')
                self.assertEqual(evaluate(cid,failed).status,Status.NON_COMPLIANT)
            with self.subTest(control=cid, state='missing'):
                self.assertEqual(evaluate(cid,{}).status,Status.UNKNOWN)
            with self.subTest(control=cid, state='error'):
                errors = {key:{'state':'error','value':None} for key in facts}
                self.assertEqual(evaluate(cid,errors).status,Status.ERROR)

    def test_conditional_and_compound_requirements(self):
        from backends.ubuntu.predicates import evaluate
        fixtures = cases()
        facts = fixtures['3.3.1']
        facts.pop('runtime.net.ipv6.conf.all.forwarding')
        facts.pop('persistent.net.ipv6.conf.all.forwarding')
        self.assertEqual(evaluate('3.3.1',facts).status,Status.UNKNOWN)
        facts['ipv6_enabled'] = observation(False)
        self.assertEqual(evaluate('3.3.1',facts).status,Status.COMPLIANT)
        for cid, field, value in [('5.4.1.1','maximum',99999),('5.4.1.3','warning',0),('5.4.1.5','inactive',-1)]:
            facts = fixtures[cid]
            facts['accounts']['value'][0][field] = value
            self.assertEqual(evaluate(cid,facts).status,Status.NON_COMPLIANT)
        facts = fixtures['5.1.7']
        facts['ssh_contexts']['value'][1]['clientalivecountmax'] = 0
        self.assertEqual(evaluate('5.1.7',facts).status,Status.NON_COMPLIANT)

    def test_secret_fields_forged_status_and_boolean_numbers_rejected(self):
        from backends.ubuntu.predicates import evaluate
        for extra in ('password','shadow','risk_score','compliance_status'):
            facts = cases()['1.5.1']
            facts[extra] = observation('SECRET-SENTINEL')
            with self.subTest(extra=extra),self.assertRaises(ValueError) as error:
                evaluate('1.5.1',facts)
            self.assertNotIn('SECRET-SENTINEL',str(error.exception))
        facts = cases()['1.5.1'];facts['runtime.kernel.randomize_va_space'] = observation(True)
        with self.assertRaises(ValueError): evaluate('1.5.1',facts)
        facts = cases()['5.4.1.1'];facts['accounts']['value'][0]['shadow_hash'] = 'SECRET-SENTINEL'
        with self.assertRaises(ValueError): evaluate('5.4.1.1',facts)

    def test_conflict_unknown_known_failure_dominates_error(self):
        from backends.ubuntu.predicates import evaluate
        facts = cases()['1.3.1.1']
        facts['package.apparmor-utils'] = {'state':'conflict','value':None}
        self.assertEqual(evaluate('1.3.1.1',facts).status,Status.UNKNOWN)
        facts['package.apparmor-utils'] = {'state':'error','value':None}
        facts['package.apparmor'] = observation('absent')
        self.assertEqual(evaluate('1.3.1.1',facts).status,Status.NON_COMPLIANT)

    def test_filtered_identity_watch_cannot_satisfy_unrestricted_required_watch(self):
        from backends.ubuntu.predicates import evaluate
        facts = cases()['6.3.3.8']
        for source in ('persistent_audit_rules','loaded_audit_rules'):
            for rule in facts[source]['value']:
                rule.update(action='always,exit',auid_min=1000,exclude_unset=True,unrestricted=False)
        self.assertEqual(evaluate('6.3.3.8',facts).status,Status.NON_COMPLIANT)
