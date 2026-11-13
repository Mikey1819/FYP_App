"""Remediation without page changes (administrator, 13 November 2026, after the snapshot-restored VM's first round).

- 1.3.1.1 and 6.3.1.1 were planned, approved and started, ran about two minutes each and ended "not applied" with the
  server unchanged (receipts 06:17 and 06:20 UTC). The apt install waited only 120 s for the package lock, which
  Ubuntu's automatic updates hold for minutes on a VM just restored from a snapshot. The install now waits up to
  15 minutes inside a 30-minute job, and a not-applied result says what usually causes it.
- One safety-check button runs both acceptance tests, so the page shows one message while they are pending.
- While remediation carries on by itself (a supervised job running, a change confirmed over a fresh login, the next
  approved fixes starting, the server restarting for an approved reboot), the page keeps showing the running
  animation instead of switching to the full page, the Servers page or Overview with messages.
Fakes only; the VM is never contacted.
"""
import unittest
from types import SimpleNamespace as N
from unittest import mock

from tests.integration import test_ubuntu_confirm_ui as confirm_ui


class PackageLockTests(unittest.TestCase):
    def test_the_install_waits_up_to_fifteen_minutes_for_the_package_lock(self):
        from vm.ubuntu.family_package import LinuxPackageIO
        self.assertIn('DPkg::Lock::Timeout=300', LinuxPackageIO._APT)  # 120, then 900; 300 since the busy check
        io, calls = LinuxPackageIO(), []
        io._exec = lambda argv, seconds: calls.append((argv, seconds)) or (0, '')
        io.install(['auditd', 'audispd-plugins'])
        io.purge(['prelink'])
        self.assertTrue(all(seconds >= 300 + 600 for _, seconds in calls), calls)  # room to install after the wait

    def test_the_job_deadlines_leave_room_for_the_wait(self):
        from backends.ubuntu.actions import AUXILIARY, FAMILIES
        from vm.ubuntu.family_maintenance import AptRefreshFamily
        from vm.ubuntu.family_package import PackageFamily
        from vm.ubuntu.remediation_schema import MAX_JOB_SECONDS
        for control in ('1.3.1.1', '6.3.1.1', '1.5.4'):
            family = PackageFamily(control, None)
            self.assertEqual(family.max_seconds, MAX_JOB_SECONDS)
            self.assertEqual(FAMILIES[family.action_id].max_seconds, family.max_seconds)
        self.assertEqual(AptRefreshFamily(None).max_seconds, MAX_JOB_SECONDS)
        self.assertEqual(AUXILIARY['maintenance.apt_refresh.v1'].max_seconds, MAX_JOB_SECONDS)

    def test_a_not_applied_result_says_what_usually_causes_it(self):
        from backends.ubuntu.adapter import refusal_detail
        words = refusal_detail('before_state')
        self.assertNotIn('(before_state)', words)
        self.assertIn('package lock', words)
        self.assertIn('nothing changed', words.lower())


class SafetyMessageTests(unittest.TestCase):
    def reasons(self, runs):
        from backends.ubuntu.adapter import UbuntuBackend
        fake = N(deployment_status=lambda connection: N(ok=True, reasons=(), runner_digest='d'),
                 session=N(connection_session_id='c'), _acceptance_runs=lambda: runs)
        return UbuntuBackend._execution_reasons(fake)

    def test_one_message_while_the_safety_check_has_not_passed(self):
        for runs in ([], [dict(scenario='confirm', outcome='confirmed', runner_digest='d')],
                     [dict(scenario='rollback', outcome='rolled_back', runner_digest='d')]):
            with self.subTest(runs=runs):
                [reason] = self.reasons(runs)  # before: one message per test
                self.assertIn('Run safety check', reason)
        self.assertEqual(self.reasons([dict(scenario='confirm', outcome='confirmed', runner_digest='d'),
                                       dict(scenario='rollback', outcome='rolled_back', runner_digest='d')]), ())


class HeldRemediationTests(confirm_ui.ConfirmUiTests):
    def page(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import TARGET as LIVE
        from tests.integration.pairing_fixture import SECRET, paired_connect
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from hardening.reconnect import RECONNECT
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY confirm value',
                          recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']})
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': spec.action_id, 'reason_code': 'highest_risk'}
            clients = team([call('delegate_scanner'), call('delegate_analysis'), plan_call([fix])],
                           scanner_ok(), RankingAware())
            for client in clients.values():
                if isinstance(client, Scripted):
                    for item in client.script:
                        item['tool_calls'][0]['function']['arguments']['target_id'] = session.target_id
            RankingAware.target = session.target_id
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                                 model_probe=lambda: getattr(self, 'model_up', True))

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service
        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0], run=False).state,
                         'connected')
        app.session_state[RECONNECT] = dict(host='fixture.invalid', port=22, hostname=LIVE[1], identity=LIVE[0],
                                            username='fixture-user', password=SECRET, key_path=None, sudo=None)
        app.run()
        return app

    @staticmethod
    def held(app):
        return any('Remediation' in m.value and 'Running' in m.value for m in app.markdown)

    def test_the_running_animation_stays_while_the_change_runs_and_is_confirmed(self):
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
            self.assertFalse(list(app.error), [e.value for e in app.error])
            # The supervised job runs on the server: the animation, not the full page with a "running" message.
            self.assertTrue(self.held(app), [m.value for m in app.markdown])
            self.assertFalse([b for b in app.button if b.key and b.key.startswith(('ubuntu_status_', 'agentic_run'))])
            self.assertNotIn('is running on the server. This page checks it', ' '.join(i.value for i in app.info))
            [rid] = list(self.launcher.active)
            self.runner().run_job(rid)  # applied; it now waits for confirmation over a fresh login
            self.launcher.active.discard(rid)
            app.run()  # the watcher confirms it by itself, still behind the animation
            app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertFalse(self.held(app))  # all settled: the page is back
            self.assertFalse([s.value for s in app.success if 'confirmed after a fresh login' in s.value])  # no message
        self.assertEqual((self.work / 'alpha').read_bytes(), b'new')


for _name in [n for n in dir(confirm_ui.ConfirmUiTests) if n.startswith('test')]:
    setattr(HeldRemediationTests, _name, None)  # only the harness is inherited


class RebootStaysOnPageTests(unittest.TestCase):
    """The whole app (app.py): a reboot drops the SSH link; before, the sidebar's connection check disconnected
    with "Connect again under Servers" and the app moved to the Servers page, then to Overview after a reconnect."""

    def setUp(self):
        import tempfile
        from pathlib import Path
        from streamlit.testing.v1 import AppTest
        from streamlit.util import calc_hash
        from system.bootstrap import SERVICE_KEY
        from system.config import IntegrationPaths
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        from tests.integration.pairing_fixture import paired_connect
        from tests.test_app_navigation import APP, FixtureSsh
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        data = Path(folder.name)
        paths = IntegrationPaths(APP.parent, data / 'windows' / 'imports.sqlite3', data / 'ubuntu' / 'imports.sqlite3',
                                 data / 'integration.sqlite3')
        for target in (mock.patch('system.config.PATHS', paths),
                       mock.patch('hardening.reachability.answers', return_value=True),
                       mock.patch('hardening.agentic_view._ssh_answers', return_value=False)):  # still restarting
            target.start()
            self.addCleanup(target.stop)
        self.service = ConnectionService(CoordinationLedger(paths.coordination), ssh_factory=lambda *a: FixtureSsh())
        self.app = AppTest.from_file(str(APP), default_timeout=30)
        self.app.session_state[SERVICE_KEY] = self.service
        self.app.run()
        self.assertEqual(paired_connect(self.app, platform='ubuntu', hostname='ubuntu-web01', identity='b' * 32).state,
                         'connected')
        self.app._page_hash = calc_hash('agentic')
        self.app.run()
        self.assertEqual(self.app.title[0].value, 'Agentic hardening')

    def drop(self):
        from system.bootstrap import CONNECTION_KEY
        self.service.session(self.app.session_state[CONNECTION_KEY]).channel.alive = lambda: False

    def login(self):
        return dict(host='fixture.invalid', port=22, hostname='ubuntu-web01', identity='b' * 32,
                    username='fixture-user', password='TEST-ONLY', key_path=None, sudo=None)

    def check_held(self):
        app = self.app
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(app.title[0].value, 'Agentic hardening')  # before: the Servers page
        self.assertFalse([w.value for w in app.warning if 'was lost' in w.value])
        self.assertTrue(any('Remediation' in m.value and 'Running' in m.value for m in app.markdown))
        self.assertIn('restarting', ' '.join(c.value for c in app.caption))

    def test_a_dropped_link_during_an_approved_reboot_keeps_the_page(self):
        from hardening.agentic_view import REBOOT_LOGIN
        from hardening.reconnect import RECONNECT
        self.app.session_state[RECONNECT] = self.login()
        self.drop()
        reboot = N(workflow_session_id='w', round_reference=N(record_id='r'))
        with mock.patch('backends.ubuntu.adapter.UbuntuBackend.pending_reboot', return_value=reboot):
            self.app.run()  # a full redraw sees the drop first: the reboot is held, not a lost connection
        self.assertIn(REBOOT_LOGIN, self.app.session_state)
        self.check_held()
        self.app.run()  # still down
        self.check_held()

    def test_after_the_restart_the_new_login_keeps_the_page(self):
        from system.bootstrap import CONNECTION_KEY
        from system.contracts import ConnectionRequest, Endpoint
        from system.session import Credentials
        from hardening.agentic_view import REBOOT_LOGIN
        from hardening.reconnect import RECONNECT
        self.app.session_state[RECONNECT] = self.login()
        session = self.service.session(self.app.session_state[CONNECTION_KEY])
        self.drop()
        reboot = N(workflow_session_id='w', round_reference=N(record_id='r'))
        with mock.patch('backends.ubuntu.adapter.UbuntuBackend.pending_reboot', return_value=reboot):
            self.app.run()
        self.check_held()
        # The server is back and the page has logged in again (what _ubuntu_reboot_wait does).
        self.app.session_state[REBOOT_LOGIN] = None
        reference = self.service.vault.put(Credentials('fixture-user', 'TEST-ONLY', None, None))
        result = self.service.connect(ConnectionRequest(Endpoint(session.host, session.port, 'ssh'), 'ubuntu-web01',
                                                        'b' * 32, reference))
        self.app.session_state[CONNECTION_KEY] = result.connection_session_id
        self.app.run()
        self.assertEqual(len(self.app.exception), 0, [e.value for e in self.app.exception])
        self.assertEqual(self.app.title[0].value, 'Agentic hardening')  # before: Overview

    def test_a_lost_link_without_a_reboot_still_disconnects(self):
        from hardening.agentic_view import REBOOT_LOGIN
        self.drop()
        self.app.run()
        self.assertNotIn(REBOOT_LOGIN, self.app.session_state)
        self.assertEqual(self.app.title[0].value, 'Servers')  # unchanged: connect again there


if __name__ == '__main__':
    unittest.main()
