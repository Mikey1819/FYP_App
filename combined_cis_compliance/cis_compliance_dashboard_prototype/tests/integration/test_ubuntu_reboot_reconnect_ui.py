"""Task 6: after an approved reboot the page reconnects by itself, instead of asking the administrator to connect
again. While the server restarts the page only checks its SSH port (a TCP connect: no login, nothing sent); once the
port has answered twice it logs in again with the remembered login and checks the new boot ID. A deliberate
Disconnect never reconnects, and after ten minutes the page gives up and says so.

TEST-ONLY: in-process runner, fake launcher, fake maintenance system and fake SSH channels; the VM is never contacted.
"""
from unittest import mock
from tests.integration import test_ubuntu_maintenance_ui as maintenance_ui


class RebootReconnectUiTests(maintenance_ui.MaintenanceUiTests):
    """While the administrator waits for the restart, only the page's 5-second watcher runs (a fragment; the sidebar's
    connection check in app.py runs on full redraws only), so the watcher is the first to see the link drop. AppTest
    always runs the whole script, so `drop()` models that order: the sidebar's check still sees the link, the
    watcher's check moments later does not."""

    def make_channel(self):
        channel = super().make_channel()
        channel.dead, channel.checks_left = False, None

        def alive():
            if channel.checks_left:  # the drop happens right after the sidebar's check of this run
                channel.checks_left -= 1
                return True
            return not channel.dead

        def drop():
            channel.dead, channel.checks_left = True, 1
        channel.alive, channel.drop = alive, drop
        for name in ('invoke_runner', 'invoke_helper'):
            original = getattr(channel, name)

            def call(data, _original=original, **kwargs):
                if channel.dead:
                    raise OSError('TEST-ONLY: the SSH connection closed')
                return _original(data, **kwargs)
            setattr(channel, name, call)
        return channel

    def reboot_pending(self, app):
        """Run a round, execute its fix, then prepare, approve and run the reboot; the server now waits for it."""
        from tests.integration.pairing_fixture import SECRET
        from tests.integration.test_ubuntu_live_path import TARGET as LIVE
        from hardening.reconnect import RECONNECT
        from system.bootstrap import SERVICE_KEY
        app.session_state[SERVICE_KEY]._ssh_factory = lambda *a: self.make_channel()  # each login: a new channel
        app.session_state[RECONNECT] = dict(host='fixture.invalid', port=22, hostname=LIVE[1], identity=LIVE[0],
                                            username='fixture-user', password=SECRET, key_path=None, sudo=None)
        app.button(key='agentic_run').click().run()
        app.text_input(key='agentic_operator').input('fixture-operator').run()
        self.keyed(app, 'ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
        self.model_up = False
        app.button(key='ubuntu_execute_review').click().run()
        app.button(key='ubuntu_execute').click().run()
        app.run()
        app.button(key='ubuntu_prepare_reboot').click().run()
        self.run_maintenance(app)
        [status] = self.keyed(app, 'ubuntu_status_')
        rid = status.key.removeprefix('ubuntu_status_')
        self.runner().run_job(rid)  # the reboot job ran: the runner now holds it as awaiting_reboot
        self.launcher.active.discard(rid)
        app.run()
        self.assertFalse(list(app.error), [e.value for e in app.error])
        return rid

    def patches(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        return (open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()),
                mock.patch('hardening.agentic_view.REBOOT_COMPLETES', frozenset({'1.5.1'})),
                mock.patch('hardening.agentic_view._ssh_answers', side_effect=lambda host, port: self.up))

    def test_the_page_reconnects_by_itself_after_the_restart_and_settles_the_reboot(self):
        from contextlib import ExitStack
        from system.bootstrap import CONNECTION_KEY
        self.up = True
        with ExitStack() as stack:
            for patch in self.patches():
                stack.enter_context(patch)
            app, channel = self.page()
            rid = self.reboot_pending(app)
            first = app.session_state[CONNECTION_KEY]
            self.up, self.maintenance.boot = False, 'boot-2'
            channel.drop()  # the server restarts
            app.run()
            self.assertNotIn(CONNECTION_KEY, app.session_state)
            self.assertIn('reconnects by itself', self.text(app))
            self.assertFalse(list(app.error), [e.value for e in app.error])
            app.run()  # still down: only the port is checked, no login is tried
            self.assertNotIn(CONNECTION_KEY, app.session_state)
            self.up = True
            app.run()  # the port answers once: not yet
            self.assertNotIn(CONNECTION_KEY, app.session_state)
            app.run()  # twice: log in again, check the new boot ID
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertIn(CONNECTION_KEY, app.session_state)
            self.assertNotEqual(app.session_state[CONNECTION_KEY], first)
            self.assertTrue(any('back after the restart' in s.value for s in app.success), [s.value for s in app.success])
            self.assertEqual(self.keyed(app, 'ubuntu_status_'), [])  # the reboot settled: nothing pending
            self.assertNotIn('connect again', self.text(app).lower())
        from tests.integration.test_ubuntu_live_path import open_gate
        self.assertEqual(self.ledger_state(rid), 'completed')

    def test_a_deliberate_disconnect_never_reconnects(self):
        from contextlib import ExitStack
        from hardening.agentic_view import REBOOT_LOGIN
        from system.bootstrap import CONNECTION_KEY
        self.up = True
        with ExitStack() as stack:
            for patch in self.patches():
                stack.enter_context(patch)
            app, channel = self.page()
            self.reboot_pending(app)
            app.button(key='agentic_disconnect').click().run()
            channel.drop()
            for _ in range(3):
                app.run()
            self.assertNotIn(REBOOT_LOGIN, app.session_state)
            self.assertNotIn(CONNECTION_KEY, app.session_state)
            self.assertNotIn('reconnects by itself', self.text(app))

    def test_after_ten_minutes_the_page_gives_up_and_forgets_the_login(self):
        from contextlib import ExitStack
        from hardening.agentic_view import REBOOT_LOGIN
        from hardening.reconnect import RECONNECT
        from system.bootstrap import CONNECTION_KEY
        self.up = True
        with ExitStack() as stack:
            for patch in self.patches():
                stack.enter_context(patch)
            app, channel = self.page()
            self.reboot_pending(app)
            self.up = False
            channel.drop()
            app.run()
            self.assertIn(REBOOT_LOGIN, app.session_state)
            since = app.session_state[REBOOT_LOGIN]['since']
            with mock.patch('hardening.agentic_view._reboot_clock', return_value=since + 601):
                app.run()
            self.assertNotIn(REBOOT_LOGIN, app.session_state)
            self.assertNotIn(RECONNECT, app.session_state)
            self.assertNotIn(CONNECTION_KEY, app.session_state)
            self.assertIn('did not come back within 10 minutes', ' '.join(e.value for e in app.error))

    def ledger_state(self, request_id):
        from system.ledger import CoordinationLedger
        return CoordinationLedger(self.root / 'integration.sqlite3').operation_state('ubuntu-execute:' + request_id).state


for _name in [n for n in dir(maintenance_ui.MaintenanceUiTests) if n.startswith('test')]:
    setattr(RebootReconnectUiTests, _name, None)  # only the harness is inherited
