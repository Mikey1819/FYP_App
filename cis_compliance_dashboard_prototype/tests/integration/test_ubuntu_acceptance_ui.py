"""Page flow for execution acceptance: both scenarios through the real page until the execution gate opens.
TEST-ONLY: in-process runner, fake systemd launcher and marker; the VM is never contacted."""
from tests.integration.test_ubuntu_acceptance_target import FakeMarker, LauncherProbe
from tests.integration.test_ubuntu_confirm_ui import ConfirmUiTests


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
            for key, value in (('agentic_hostname', LIVE[1]), ('agentic_uuid', LIVE[0]), ('agentic_host', 'fixture.invalid'),
                               ('agentic_user', 'fixture-user'), ('agentic_password', 'FIXTURE-SECRET-SENTINEL')):
                app.text_input(key=key).input(value)
            app.number_input(key='agentic_port').set_value(22)
            app.selectbox(key='agentic_method').select('SSH')
            app.run()
            app.button(key='agentic_connect').click().run()
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
            # Both scenarios passed for this runner: the panel is no longer shown (administrator request 2026-11-08).
            app.run()
            self.assertEqual([e for e in app.expander if e.label.startswith('Execution acceptance')], [])
            self.assertEqual(keyed('ubuntu_acceptance_'), [])
        # The rollback run restored its before-state: the marker the confirmed run left, never its own.
        self.assertTrue(self.marker.content.startswith('confirm:'))
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())


for _name in [n for n in dir(ConfirmUiTests) if n.startswith('test')]:
    setattr(AcceptanceUiTests, _name, None)  # only the harness is inherited
del ConfirmUiTests
