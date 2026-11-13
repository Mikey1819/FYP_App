"""A shorter execution and the last open control (administrator, 13 November 2026).

Measured on the 07:01-07:10 execution of 18 fixes: about 2 minutes of server work, but a full verification scan after
each of the 7 fixes that ran one by one (about 6 minutes) and a new AI step before each (about 1.4 minutes). Now:
- one verification scan when the execution has settled, covering every applied fix, instead of one per fix;
- the rest of an execution continues by code in plan order, without a new AI step each time;
- the remediation line gives the real time from Confirm and execute to the last scan, with the agents' share;
- "waits for its confirmation over a fresh login" is no longer shown: the dashboard does it, and once everything has
  settled the outcome is decided again by code from the final scan;
- no reboot is offered for 6.3.1.3 (its CIS check passes from the boot entries);
- 4.1.4 (live 08:25: "Earlier ufw rules would still decide loopback traffic differently"): the SSH rule 4.1.3 adds
  (`ufw allow 22/tcp`, from anywhere) also covers spoofed 127.0.0.0/8 traffic to port 22, so appending the CIS rules
  behind it cannot comply. They are now put in front (`ufw prepend`, ufw 0.36) when appending would not comply.
Fakes only; the VM is never contacted.
"""
import json
import unittest
from types import SimpleNamespace as N
from unittest import mock

from tests.integration import test_ubuntu_execution_continue_ui as continue_ui
from tests.integration import test_ubuntu_ufw_enable_loopback as ufw_tests
from tests.integration.test_ubuntu_ufw_loopback import LO_IN4, LO_OUT4, SPOOF4

SSH4, SSH6 = 'allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in', 'allow tcp 22 ::/0 any ::/0 in'
LO_IN6, LO_OUT6, SPOOF6 = ('allow any any ::/0 any ::/0 in_lo', 'allow any any ::/0 any ::/0 out_lo',
                           'deny any any ::/0 any ::1 in')


class LoopbackInFrontTests(ufw_tests.Case):
    CLASS, PARAMS = 'UfwLoopbackFamily', {'rules': 'cis-loopback'}

    def test_behind_an_ssh_rule_from_anywhere_the_cis_rules_go_in_front(self):
        from vm.ubuntu.probes import ufw_loopback
        system = ufw_tests.FakeFirewall(rules4=(SSH4,), rules6=(SSH6,))
        family, before = self.cycle(system)  # before: refused ("Earlier ufw rules would still decide ...")
        self.assertTrue(all(call[0] == 'prepend' for call in system.calls), system.calls)
        self.assertEqual(system.rules4, [LO_IN4, LO_OUT4, SPOOF4, SSH4])  # CIS order, then the SSH rule
        self.assertEqual(system.rules6, [LO_IN6, LO_OUT6, SPOOF6, SSH6])
        expected = {'loopback_in': 'allow', 'loopback_out': 'allow', 'spoofed_in': 'deny'}
        self.assertEqual(ufw_loopback(system.rules4, system.rules6), {'ipv4': expected, 'ipv6': expected})
        self.assertIn('ufw prepend allow in on lo', family.summary(self.PARAMS, before)['commands'])
        family.restore(self.PARAMS, before)
        self.assertEqual((system.rules4, system.rules6), ([SSH4], [SSH6]))

    def test_appending_is_kept_when_it_complies(self):
        system = ufw_tests.FakeFirewall()  # an SSH rule from the host network only: appending complies
        self.cycle(system)
        self.assertFalse([c for c in system.calls if c[0] == 'prepend'])

    def test_in_front_is_refused_when_one_address_family_has_no_rules(self):
        # One ufw command adds both families; `prepend` into an empty list is not relied on.
        system = ufw_tests.FakeFirewall(rules4=(SSH4,), rules6=())
        with self.assertRaises(ValueError):
            self.family(system).check_eligible(self.PARAMS)


class NoRebootTests(unittest.TestCase):
    def test_no_reboot_is_offered_for_6_3_1_3(self):
        from hardening.agentic_view import REBOOT_COMPLETES, _ubuntu_maintenance_needs
        self.assertEqual(REBOOT_COMPLETES, frozenset())
        card = {'control_id': '6.3.1.3', 'state': 'Fixed, re-scan: Compliant',
                'proposals': [N(kind='control_remediation', reference='p', approved_request_id='r')]}
        self.assertEqual(_ubuntu_maintenance_needs([card], {'p'}), ((), ()))


class TimeLineTests(unittest.TestCase):
    def finished(self, role, seconds):
        from system.contracts import AgentEvent
        return AgentEvent('run-' + role, role, 'finished', '', '', 'Completed: done', '', 't', 'Local Ollama',
                          'Remediation phase', 1, seconds)

    def test_the_line_gives_the_whole_execution(self):
        from hardening.agentic_view import _ubuntu_phase_lines
        events = [self.finished('remediation', 96), self.finished('scanner', 21),
                  self.finished('orchestrator (review)', 149)]
        [line] = _ubuntu_phase_lines(events, remediation_seconds=600)
        self.assertTrue(line.startswith('Remediation took 10 min 00 s from Confirm and execute to the last '
                                        'verification scan'), line)  # before: "took 2 min 29 s"
        self.assertIn('agents 2 min 29 s', line)
        self.assertIn('server jobs, confirmations and scans 7 min 31 s', line)

    def test_the_span_comes_from_the_stored_times(self):
        from backends.ubuntu.adapter import execution_seconds
        self.assertEqual(execution_seconds(['2026-11-13T07:01:24+00:00'], ['2026-11-13T07:01:47+00:00'],
                                           ['2026-11-13T07:10:44+00:00', '2026-11-13T07:02:26+00:00']), 560.0)
        self.assertIsNone(execution_seconds([], [], ['2026-11-13T07:10:44+00:00']))
        # A scan from before the execution (an earlier one) is not its end.
        self.assertIsNone(execution_seconds(['2026-11-13T07:01:24+00:00'], [], ['2026-11-13T06:59:00+00:00']))


class FinalReviewTests(unittest.TestCase):
    def test_once_everything_settled_code_decides_from_the_final_scan(self):
        from backends.ubuntu.remediation_agents import settled_review
        review = settled_review(results={'4.1.3': 'applied', '5.1.7': 'applied'},
                                status={'4.1.3': 'Compliant', '5.1.7': 'Compliant'}, unverified=[], remaining=[])
        self.assertEqual((review['next_step'], review['reason_code']), ('finish', 'all_verified'))
        self.assertNotIn('waits for its confirmation', review['reason'])
        review = settled_review(results={'4.1.3': 'applied'}, status={'4.1.3': 'Compliant'}, unverified=[],
                                remaining=['4.1.4'])
        self.assertEqual((review['next_step'], review['reason_code']), ('next_round', 'remaining_findings'))
        review = settled_review(results={'4.1.3': 'applied', '1.3.1.1': 'refused'}, status={'4.1.3': 'Compliant'},
                                unverified=[], remaining=[])
        self.assertEqual((review['next_step'], review['reason_code']), ('remediation_review', 'fix_refused'))
        review = settled_review(results={'4.1.3': 'applied'}, status={'4.1.3': 'Non-Compliant'}, unverified=[],
                                remaining=[])
        self.assertEqual((review['next_step'], review['reason_code']), ('remediation_review', 'verification_failed'))

    def test_the_page_never_shows_the_waiting_sentence(self):
        from streamlit.testing.v1 import AppTest

        def page():
            from hardening.agentic_view import _ubuntu_review_line
            _ubuntu_review_line({'next_step': 'remediation_review', 'reason_code': 'awaiting_confirmation',
                                 'reason': 'Waiting for confirmation or reboot: 5.1.7.'})
        app = AppTest.from_function(page, default_timeout=30)
        app.run()
        self.assertEqual([i.value for i in app.info] + [s.value for s in app.success], [])


class SettledReviewWiringTests(unittest.TestCase):
    def backend(self, last_outcome):
        from backends.ubuntu.adapter import UbuntuBackend
        from backends.ubuntu.remediation_agents import REVIEW_ROLE
        backend = UbuntuBackend.__new__(UbuntuBackend)
        latest = N(round_id='r', kind='assessment', evidence_sha256='e')
        proposal = N(decision='approved', receipts=({'outcome': last_outcome, 'request_id': 'q'},),
                     payload={'action': {'action_id': 'ubuntu.5.1.7.v1'}, 'fields': {'control_id': '5.1.7'}})
        store = N(rounds=lambda binding: [latest], proposals=lambda binding, round_id: [proposal])
        review = {'outcome': 'remediation_review', 'reason_code': 'awaiting_confirmation',
                  'reason': '5.1.7 waits for its confirmation over a fresh login'}
        run = {'agent_role': REVIEW_ROLE, 'events': [{'kind': 'finished', 'data': {'outcome': review}}]}
        patches = mock.patch.multiple(backend, create=True, check=lambda *a: 'binding', _store=lambda: store,
                                      _phase_runs=lambda store_, round_id: [run], _unverified=lambda *a: [],
                                      _eligible=lambda evidence: {})
        return backend, patches

    def test_once_settled_the_review_is_decided_again_by_code(self):
        backend, patches = self.backend('applied')
        with patches:
            review = backend.remediation_review('c', 'w')
        self.assertNotIn('waits for its confirmation', review['reason'])  # before: the stale waiting sentence
        self.assertEqual(review['reason_code'], 'verification_unavailable')  # no final scan stored in this stub

    def test_while_it_still_waits_the_review_stays(self):
        backend, patches = self.backend('running')
        with patches:
            review = backend.remediation_review('c', 'w')
        self.assertEqual(review['reason_code'], 'awaiting_confirmation')


class ContinueByCodeTests(unittest.TestCase):
    def test_the_rest_runs_by_code_even_with_the_model_up(self):
        from streamlit.testing.v1 import AppTest
        calls = []

        def page():
            from types import SimpleNamespace as N
            from unittest import mock
            import streamlit as st
            from hardening import agentic_view as view
            from system.bootstrap import WORKFLOW_KEY
            st.session_state[WORKFLOW_KEY] = 'w'
            backend = N(continuation=lambda c, w: ('r1',),
                        continue_execution=lambda *a: st.session_state.setdefault('calls', []).append(a))
            snapshot = N(current_round_reference=N(record_id='round'), plan=True)
            capabilities = N(can_remediate=True, can_use_model=True)
            with mock.patch.object(view, '_start', lambda label, work, after: (
                    st.session_state.__setitem__('label', label), work())):
                view._ubuntu_continue(backend, 'c', snapshot, capabilities)
        app = AppTest.from_function(page, default_timeout=30)
        app.run()
        self.assertFalse(app.exception, [e.value for e in app.exception])
        from hardening.agentic_view import UBUNTU_CONTINUE_LABEL
        [args] = app.session_state['calls']
        self.assertIs(args[3], True)  # deterministic: no new AI step (before: the agents again for each fix)
        self.assertEqual(app.session_state['label'], UBUNTU_CONTINUE_LABEL)

    def test_the_continuation_still_shows_the_three_agents(self):
        from hardening.agentic_view import UBUNTU_CONTINUE_LABEL, _stage_for
        from hardening import live_progress
        roles, state = _stage_for(N(label=UBUNTU_CONTINUE_LABEL), None)
        self.assertEqual(roles, (live_progress.ORCHESTRATOR, live_progress.REMEDIATION, live_progress.SCANNER))
        self.assertEqual(state['active'], live_progress.REMEDIATION)


class OneScanTests(continue_ui.ContinueUiTests):
    def scans(self):
        import sqlite3
        from contextlib import closing
        found = []
        for path in (self.root / 'ubuntu').glob('*agentic*.sqlite3'):
            with closing(sqlite3.connect(path)) as db:
                for (payload,) in db.execute('SELECT payload FROM agentic_rounds ORDER BY created_at').fetchall():
                    doc = json.loads(payload)
                    if doc['kind'] == 'verification':
                        found.append(sorted(doc['details']['request_ids']))
        return found

    def test_one_verification_scan_once_the_execution_has_settled(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.page()
            for _ in range(2):
                self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
            self.model_up = False
            app.button(key='ubuntu_execute_review').click().run()
            app.button(key='ubuntu_execute').click().run()
            [job] = list(self.launcher.active)
            self.job(job)
            for _ in range(3):  # the job settles; the confirm fix is sent by itself
                app.run()
            self.assertEqual(self.scans(), [])  # before: a scan right after the job, with the confirm fix still to run
            [confirm] = list(self.launcher.active)
            self.job(confirm)
            for _ in range(3):  # confirmed over a fresh login; the execution has settled
                app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
        [covered] = self.scans()
        self.assertEqual(len(covered), 2)  # one scan covering both fixes


for _name in [n for n in dir(continue_ui.ContinueUiTests) if n.startswith('test')]:
    setattr(OneScanTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
