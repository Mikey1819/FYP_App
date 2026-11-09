"""Page flow for execution acceptance: both scenarios through the real page until the execution gate opens.
TEST-ONLY: in-process runner, fake systemd launcher and marker; the VM is never contacted."""
from tests.integration.test_ubuntu_acceptance_target import FakeMarker, LauncherProbe
from tests.integration.test_ubuntu_confirm_ui import ConfirmUiTests
from tests.integration.pairing_fixture import paired_connect


class AcceptanceUiTests(ConfirmUiTests):
    def setUp(self):
        super().setUp()
        self.launcher, self.marker = LauncherProbe(), FakeMarker()

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.family_acceptance import AcceptanceMarkerFamily
        from vm.ubuntu.runner import Runner
        family = family or self.family
        marker = AcceptanceMarkerFamily(self.marker)
        from vm.ubuntu.family_maintenance import AptRefreshFamily, RebootFamily
        from tests.integration.test_ubuntu_maintenance_target import FakeMaintenance
        maintenance = FakeMaintenance()  # a real runner registers every auxiliary the host expects
        return Runner(self.state, {family.action_id: family, marker.action_id: marker,
                       'maintenance.apt_refresh.v1': AptRefreshFamily(maintenance),
                       'maintenance.reboot.v1': RebootFamily(maintenance)},
                      lambda: identity or ('a' * 32, 'ubuntu-fixture'), clock=clock or self.now,
                      require_root_owned=False, launcher=self.launcher)


    def test_one_button_runs_both_tests_with_its_own_fresh_login(self):
        """Run safety check: the confirm test is confirmed over a fresh login the dashboard makes, and the rollback
        test is left to the server's timer. The server side is driven between the page's waits."""
        from unittest import mock
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, team, scanner_ok, RankingAware
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from tests.integration.pairing_fixture import SECRET
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from hardening.reconnect import RECONNECT
        from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60)
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            clients = team([call('delegate_scanner')], scanner_ok(), RankingAware())
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                                 model_probe=lambda: True)

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service
        ran, rolled = set(), set()
        real_sleep = __import__('time').sleep

        def server_tick(seconds):
            """What the server does while the page waits: run started jobs; fire the rollback test's timer.
            Streamlit's own short waits pass through to the real sleep."""
            if seconds < 1:
                return real_sleep(seconds)
            session = service.session(app.session_state[CONNECTION_KEY]) if CONNECTION_KEY in app.session_state else None
            for rid in list(self.launcher.active):
                self.runner().run_job(rid)
                self.launcher.active.discard(rid)
                ran.add(rid)
            for run in ledger.acceptance_runs(session.target_id, session.registration_epoch) if session else ():
                if run['scenario'] == 'rollback' and run['outcome'] is None and run['request_id'] in ran - rolled:
                    self.runner().rollback(run['request_id'])
                    rolled.add(run['request_id'])

        with open_gate(), mock.patch('time.sleep', server_tick):
            app.run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0],
                                            run=False).state, 'connected')
            app.session_state[RECONNECT] = dict(host='fixture.invalid', port=22, hostname=LIVE[1], identity=LIVE[0],
                                                username='fixture-user', password=SECRET, key_path=None, sudo=None)
            app.run()
            first = app.session_state[CONNECTION_KEY]
            app.text_input(key='ubuntu_acceptance_operator').input('fixture-operator').run()
            app.button(key='ubuntu_safety_check').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertTrue(any('Safety check passed' in s.value for s in app.success), [s.value for s in app.success])
            self.assertNotEqual(app.session_state[CONNECTION_KEY], first)
            # Once passed, the safety check is no longer shown (administrator request 2026-11-09); the result line
            # above shows once, then the page carries nothing of it.
            self.assertEqual([e.label for e in app.expander if 'acceptance' in e.label.lower()], [])
            self.assertEqual([b.key for b in app.button if b.key and b.key.startswith(('ubuntu_acceptance',
                                                                                      'ubuntu_safety'))], [])
            app.run()
            self.assertFalse([s.value for s in app.success if 'Safety check' in s.value])
            session = service.session(app.session_state[CONNECTION_KEY])
            outcomes = [(r['scenario'], r['outcome']) for r in ledger.acceptance_runs(session.target_id,
                                                                                     session.registration_epoch)]
        self.assertEqual(outcomes, [('confirm', 'confirmed'), ('rollback', 'rolled_back')])
        self.assertTrue(self.marker.content.startswith('confirm:'))

    def test_page_runs_both_scenarios_and_the_gate_reasons_disappear(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, team, scanner_ok, RankingAware
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60)
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            clients = team([call('delegate_scanner')], scanner_ok(), RankingAware())
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                                 model_probe=lambda: True)

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service

        def connect():
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            self.assertFalse(list(app.error), [e.value for e in app.error])

        def keyed(prefix):
            return [b for b in app.button if b.key and b.key.startswith(prefix)]

        def gate_text():
            return ' '.join(i.value for i in app.info).lower()

        with open_gate():
            app.run()
            connect()
            self.assertIn('confirm scenario', gate_text())
            self.assertTrue(app.button(key='ubuntu_acceptance_confirm').disabled)  # operator name first
            app.text_input(key='ubuntu_acceptance_operator').input('fixture-operator').run()
            app.button(key='ubuntu_acceptance_confirm').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            [status] = keyed('ubuntu_acceptance_status_')
            rid = status.key.removeprefix('ubuntu_acceptance_status_')
            self.runner().run_job(rid)
            self.launcher.active.discard(rid)
            status.click().run()
            app.run()
            [confirm] = keyed('ubuntu_acceptance_confirm_run_')
            confirm.click().run()
            self.assertIn('fresh login', ' '.join(e.value for e in app.error).lower())
            app.button(key='agentic_disconnect').click().run()
            connect()
            keyed('ubuntu_acceptance_confirm_run_')[0].click().run()
            app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertNotIn('confirm scenario', gate_text())
            self.assertIn('rollback scenario', gate_text())
            # Rollback scenario: start it, let the job finish, do NOT confirm; the timer restores it.
            app.text_input(key='ubuntu_acceptance_operator').input('fixture-operator').run()
            app.button(key='ubuntu_acceptance_rollback').click().run()
            [status] = keyed('ubuntu_acceptance_status_')
            rid = status.key.removeprefix('ubuntu_acceptance_status_')
            self.runner().run_job(rid)
            self.launcher.active.discard(rid)
            status.click().run()
            app.run()
            self.assertEqual(keyed('ubuntu_acceptance_confirm_run_'), [])  # never offered for the rollback scenario
            self.runner().rollback(rid)
            keyed('ubuntu_acceptance_status_')[0].click().run()  # the operator checks status once the timer fired
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertNotIn('not enabled', gate_text())
            # Both scenarios passed for this runner: the panel is gone (administrator requests 2026-11-08 and
            # 2026-11-09). A reinstalled runner changes its digest, which makes the check needed, and shown, again.
            app.run()
            self.assertEqual([e.label for e in app.expander if 'acceptance' in e.label.lower()], [])
            self.assertEqual(keyed('ubuntu_acceptance_') + keyed('ubuntu_safety'), [])
        # The rollback run restored its before-state: the marker the confirmed run left, never its own.
        self.assertTrue(self.marker.content.startswith('confirm:'))
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())


for _name in [n for n in dir(ConfirmUiTests) if n.startswith('test')]:
    setattr(AcceptanceUiTests, _name, None)  # only the harness is inherited
del ConfirmUiTests
