"""Module 1 (Ubuntu): Complete hardening and exceptions, as on the Windows page (teammate's commit 72c52260).

A final read-only scan completes the session when every control is Compliant or accepted as an exception (with a
reason and the administrator's name). The session is then read-only, Overview says so, and there is a completion
report. Exceptions belong to one session. TEST-ONLY family and fake server (1.5.1 Non-Compliant; 4.1.4, 6.3.3.4,
6.3.3.6, 6.3.3.8 Error; 4.1.7 Unknown); the VM is never contacted.
"""
from unittest import mock
from tests.integration import test_ubuntu_maintenance_ui as maintenance_ui
from tests.integration import test_ubuntu_proposals as proposals

OPEN = ['1.5.1', '4.1.4', '4.1.7', '6.3.3.4', '6.3.3.6', '6.3.3.8']


class CompletionBackendTests(proposals.BackendRemediationTests):
    def started(self):
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        return backend, handle.binding.workflow_session_id, snap

    def complete(self, backend, workflow, operation='op-final'):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            return backend.complete_hardening('c', workflow, 'fixture-operator', operation)

    def test_the_final_scan_completes_only_when_every_control_is_compliant_or_accepted(self):
        backend, workflow, snap = self.started()
        state = backend.completion_state('c', workflow)
        self.assertEqual([i['control_id'] for i in state['items']], OPEN)
        self.assertIn('approve and execute its fix', state['items'][0]['why'])
        scans = len(backend.history('ubuntu:fixture'))
        result = self.complete(backend, workflow)
        self.assertEqual((result['completed'], [i['control_id'] for i in result['items']]), (False, OPEN))
        self.assertEqual(len(backend.history('ubuntu:fixture')), scans + 1)  # the final scan was taken and stored
        self.assertIsNone(backend.completion('c', workflow))
        with self.assertRaisesRegex(ValueError, 'reason'):
            backend.accept_exception('c', workflow, '1.5.1', 'fixture-operator', '  ')
        with self.assertRaisesRegex(ValueError, 'not open'):
            backend.accept_exception('c', workflow, '3.3.2', 'fixture-operator', 'Compliant already')
        for cid in OPEN:
            backend.accept_exception('c', workflow, cid, 'fixture-operator', 'TEST-ONLY reason for ' + cid)
        self.assertEqual(backend.completion_state('c', workflow)['items'], [])
        result = self.complete(backend, workflow, 'op-final-2')
        self.assertEqual((result['completed'], result['compliant'], result['total']), (True, 24, 30))
        self.assertEqual([e['control_id'] for e in result['exceptions']], OPEN)
        self.assertEqual(result['exceptions'][0]['reason'], 'TEST-ONLY reason for 1.5.1')
        record = backend.completion('c', workflow)
        self.assertEqual((record['operator'], record['compliant'], record['total']), ('fixture-operator', 24, 30))
        with self.assertRaisesRegex(ValueError, 'already completed'):
            self.complete(backend, workflow, 'op-final-3')
        self.assertEqual(len(self.executes()), 0)  # read-only throughout

    def test_a_completed_session_is_read_only(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow, snap = self.started()
        backend.decide('c', workflow, snap.proposals[0].reference, False, 'fixture-operator', '', 'op-reject')
        for cid in OPEN:
            backend.accept_exception('c', workflow, cid, 'fixture-operator', 'TEST-ONLY')
        self.assertTrue(self.complete(backend, workflow)['completed'])
        with self.assertRaisesRegex(ValueError, 'completed'):
            backend.accept_exception('c', workflow, '1.5.1', 'fixture-operator', 'again')
        with self.assertRaisesRegex(ValueError, 'completed'), open_gate():
            backend.start_round('c', workflow, None, 'deterministic', 'op-next')
        with self.assertRaisesRegex(ValueError, 'completed'), \
                mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            backend.execute_approved('c', workflow, snap.current_round_reference, ('a' * 32,), True, 'op-exec')
        with self.assertRaisesRegex(ValueError, 'completed'):
            backend.decide('c', workflow, snap.proposals[0].reference, True, 'fixture-operator', '', 'op-approve')

    def test_exceptions_belong_to_one_session(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        backend, workflow, snap = self.started()
        backend.accept_exception('c', workflow, '1.5.1', 'fixture-operator', 'TEST-ONLY')
        with open_gate():
            other = backend.start_round('c', None, None, 'deterministic', 'op-new-session').binding.workflow_session_id
        self.assertNotEqual(other, workflow)
        self.assertIn('1.5.1', [i['control_id'] for i in backend.completion_state('c', other)['items']])
        self.assertNotIn('1.5.1', [i['control_id'] for i in backend.completion_state('c', workflow)['items']])


class CompletionPageTests(maintenance_ui.MaintenanceUiTests):
    def text(self, app):
        return ' '.join(e.value for kind in (app.markdown, app.caption, app.info, app.warning, app.success, app.error)
                        for e in kind)

    def round_with_fix_rejected(self):
        app, _ = self.page()
        app.button(key='agentic_run').click().run()
        self.assertNotIn('ubuntu_complete', self.keys(app))  # a fix still awaits a decision
        app.text_input(key='agentic_operator').input('fixture-operator').run()
        [reject] = [b for b in app.button if b.key and b.key.startswith('ubuntu_reject_') and b.key != 'ubuntu_reject_all']
        reject.click().run()
        return app

    def test_complete_hardening_with_exceptions_then_the_session_is_read_only(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        from hardening.agentic_view import GO_OVERVIEW
        from hardening.overview_view import COMPLETED
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.round_with_fix_rejected()
            app.button(key='ubuntu_complete').click().run()
            app.text_input(key='ubuntu_complete_operator').input('fixture-operator').run()
            app.button(key='ubuntu_complete_run').click().run()  # something is still open: not completed
            self.assertIn('Not completed', self.text(app))
            for cid in OPEN:
                app.text_input(key='ubuntu_complete_reason_' + cid).input('TEST-ONLY reason ' + cid).run()
                app.button(key='ubuntu_complete_accept_' + cid).click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertIn('every control is Compliant or accepted as an exception', self.text(app))
            app.button(key='ubuntu_complete_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertTrue(app.session_state[GO_OVERVIEW])
            self.assertIn('Hardening complete for', app.session_state[COMPLETED])
            self.assertIn('24 of 30', app.session_state[COMPLETED])
            app.run()
            text = self.text(app)
            self.assertIn('Hardening complete.', text)
            self.assertIn('read-only', text)
            keys = self.keys(app)
            self.assertFalse({'agentic_run', 'ubuntu_execute_review', 'ubuntu_complete'} & keys)
            self.assertIn('agentic_reset', keys)  # New session
            self.assertEqual([d.label for d in app.get('download_button') if 'Completion' in d.label],
                             ['Completion report'])

    def test_no_name_no_exception(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.round_with_fix_rejected()
            app.button(key='ubuntu_complete').click().run()
            app.text_input(key='ubuntu_complete_operator').input('').run()
            self.assertTrue(app.button(key='ubuntu_complete_accept_1.5.1').disabled)
            self.assertTrue(app.button(key='ubuntu_complete_run').disabled)


class CompletionReportTests(proposals.BackendRemediationTests):
    def test_the_completion_report_names_who_completed_it_and_each_exception(self):
        from types import SimpleNamespace as N
        from system.ui.round_report import ubuntu_round_report
        snapshot = N(summary=None, current_round_reference=None, plan=(), findings=(), controls=(), proposals=(),
                     results=(), events=(), target=N(hostname='UBUNTU-FIXTURE'))
        completion = {'operator': 'fixture-operator', 'completed_at': '2026-11-12T10:00:00+00:00',
                      'final_run_id': 'run-final', 'compliant': 29, 'total': 30,
                      'exceptions': [{'control_id': '4.1.7', 'title': 'UFW default deny', 'status': 'Unknown',
                                      'reason': 'TEST-ONLY site firewall', 'operator': 'fixture-operator'}]}
        html = ubuntu_round_report(snapshot, (), None, None, completion=completion)
        for words in ('Hardening completed', 'fixture-operator', '29 of 30', 'run-final', 'TEST-ONLY site firewall'):
            self.assertIn(words, html)


for _name in [n for n in dir(proposals.BackendRemediationTests) if n.startswith('test')]:
    setattr(CompletionBackendTests, _name, None)
    setattr(CompletionReportTests, _name, None)
for _name in [n for n in dir(maintenance_ui.MaintenanceUiTests) if n.startswith('test')]:
    setattr(CompletionPageTests, _name, None)  # only the harnesses are inherited
