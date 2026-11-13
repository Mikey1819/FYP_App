"""A status that cannot be read no longer looks like "running" forever (administrator, 13 November 2026).

Live 18:57 MYT: 1.3.1.1 (supervised apt job) waited for apt's lock; after the program and the VM were restarted and
the VM re-paired, the page still showed "running on the server as a supervised job", and no status had been stored
since 18:58:26. Two causes: the running view swallowed every failed status check, and the runner's reconcile failed
outright when the family could not read its state (apt's read-only simulation refuses while dpkg is interrupted, for
example after a restart during an install). Now the runner answers "unresolved, state_unreadable" (nothing settled,
nothing re-run), and after three failed checks in a row the page leaves the animation and shows the error with
Check status. An unreadable state is checked again by itself, and settles once apt can read it.
TEST-ONLY families, fake launcher and fake server; the VM is never contacted.
"""
import unittest
from types import SimpleNamespace as N
from unittest import mock

from tests.integration import test_ubuntu_remediation_flow_1113 as flow
from tests.integration.test_ubuntu_supervision import JobFamily, SupervisionCase, outcome


class UnreadableJobFamily(JobFamily):
    broken = False

    def read_state(self, params):
        if self.broken:
            raise ValueError('apt could not plan this change')  # as family_package while dpkg is interrupted
        return super().read_state(params)


class RunnerUnreadableTests(SupervisionCase):
    FAMILY = UnreadableJobFamily

    def test_an_unreadable_state_is_reported_not_a_failure_and_settles_later(self):
        a, runner, first = self.start()
        rid = a.request['request_id']
        self.assertEqual(outcome(first), ('running', 'job_started'))
        self.launcher.active.discard(rid)  # the VM restarted: the job unit is gone, nothing was written
        self.family.broken = True
        self.assertEqual(outcome(runner.reconcile(rid)), ('unresolved', 'state_unreadable'))  # before: an exception
        self.assertTrue((self.state / 'active').exists())  # nothing settled: the change stays open
        self.family.broken = False
        self.assertEqual(outcome(runner.reconcile(rid)), ('reconciled_not_applied', 'before_state'))
        self.assertFalse((self.state / 'active').exists())
        self.assertEqual(self.writes(), [])


for _name in [n for n in dir(SupervisionCase) if n.startswith('test')]:
    setattr(RunnerUnreadableTests, _name, None)


class FailingStatusTests(flow.HeldRemediationTests):
    def test_three_failed_checks_leave_the_animation_and_show_the_error(self):
        from backends.ubuntu.adapter import UbuntuBackend
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.page()
            app.button(key='agentic_run').click().run()
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            [b for b in app.button if b.key and b.key.startswith('ubuntu_approve_') and b.key != 'ubuntu_approve_all'][0] \
                .click().run()
            self.model_up = False
            app.button(key='ubuntu_execute_review').click().run()
            app.button(key='ubuntu_execute').click().run()
            app.run()
            self.assertTrue(self.held(app))
            failing = mock.patch.object(UbuntuBackend, 'refresh_execution',
                                        side_effect=ValueError('TEST-ONLY the runner exited with status 1'))
            with failing:
                for _ in range(3):  # the third failure itself redraws the page (the watcher runs on its own)
                    app.run()
            self.assertFalse(self.held(app))  # before: the animation forever, the error never shown
            shown = ' '.join(e.value for e in app.error).replace(chr(92), '')  # without Markdown escapes
            self.assertIn('could not be read', shown)
            self.assertIn('TEST-ONLY the runner exited with status 1', shown)
            self.assertTrue([b for b in app.button if b.key and b.key.startswith('ubuntu_status_')])


for _name in [n for n in dir(flow.HeldRemediationTests) if n.startswith('test')]:
    setattr(FailingStatusTests, _name, None)


class UnreadableWarningTests(unittest.TestCase):
    def test_the_page_says_why_and_checks_again_by_itself(self):
        from streamlit.testing.v1 import AppTest

        def page():
            from types import SimpleNamespace as N
            import streamlit as st
            from backends.ubuntu.adapter import PendingChange
            from hardening.agentic_view import _ubuntu_watch_changes
            from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
            item = PendingChange('w', N(record_id='r'), 'q' * 32, '1.3.1.1', 'Install AppArmor', 'unresolved',
                                 'state_unreadable')
            backend = N(session=N(channel=N()), pending_supervised=lambda c: [item],
                        refresh_execution=lambda *a: st.session_state.setdefault('checks', []).append(a)
                        or N(state='unresolved'))
            st.session_state[SERVICE_KEY] = N(backend_for=lambda c: backend, session=lambda c: N(channel=N()))
            st.session_state[CONNECTION_KEY] = 'c'
            _ubuntu_watch_changes()
        app = AppTest.from_function(page, default_timeout=30)
        app.run()
        self.assertFalse(app.exception, [e.value for e in app.exception])
        warning = ' '.join(w.value for w in app.warning)
        self.assertIn('could not read', warning)
        self.assertIn('dpkg', warning)
        self.assertEqual(len(app.session_state['checks']), 1)  # checked again, without a click


if __name__ == '__main__':
    unittest.main()
