"""Page flow for maintenance: prepare -> approve -> confirm -> run, for a package-list refresh and a reboot.
TEST-ONLY: in-process runner, fake launcher and fake maintenance system; the VM is never contacted."""
from unittest import mock
from tests.integration.test_ubuntu_fix_ui import FixUiTests
from tests.integration.test_ubuntu_maintenance_target import FakeMaintenance
from tests.integration.test_ubuntu_supervision import FakeLauncher


class MaintenanceUiTests(FixUiTests):
    def setUp(self):
        super().setUp()
        self.launcher, self.maintenance = FakeLauncher(), FakeMaintenance()

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.family_maintenance import AptRefreshFamily, RebootFamily
        from vm.ubuntu.runner import Runner
        family = family or self.family
        families = {family.action_id: family, 'maintenance.apt_refresh.v1': AptRefreshFamily(self.maintenance),
                    'maintenance.reboot.v1': RebootFamily(self.maintenance)}
        return Runner(self.state, families, lambda: identity or ('a' * 32, 'ubuntu-fixture'), clock=clock or self.now,
                      require_root_owned=False, launcher=self.launcher)

    def test_page_prepares_approves_and_runs_maintenance(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        channel = self.make_channel()
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY fixture value',
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
                                 model_probe=lambda: True)

        service = ConnectionService(ledger, ssh_factory=lambda *a: channel, backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service

        def keyed(prefix):
            return [b for b in app.button if b.key and b.key.startswith(prefix)]

        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app.run()
            for key, value in (('agentic_hostname', LIVE[1]), ('agentic_uuid', LIVE[0]), ('agentic_host', 'fixture.invalid'),
                               ('agentic_user', 'fixture-user'), ('agentic_password', 'FIXTURE-SECRET-SENTINEL')):
                app.text_input(key=key).input(value)
            app.number_input(key='agentic_port').set_value(22)
            app.selectbox(key='agentic_method').select('SSH')
            app.run()
            app.button(key='agentic_connect').click().run()
            app.button(key='agentic_run').click().run()
            self.assertTrue(app.button(key='ubuntu_prepare_reboot').disabled)  # nothing applied yet
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            keyed('ubuntu_approve_')[0].click().run()
            app.checkbox(key='ubuntu_confirm_execute').check().run()
            app.button(key='ubuntu_execute').click().run()
            app.run()
            self.assertEqual(self.writes(), ['alpha'])
            # Package-list refresh: prepare, approve (operator named), confirm, run once.
            app.button(key='ubuntu_prepare_refresh').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            keyed('ubuntu_approve_')[0].click().run()
            [run] = keyed('ubuntu_run_maintenance_')
            self.assertTrue(run.disabled)  # confirmation first
            [confirm] = [c for c in app.checkbox if c.key and c.key.startswith('ubuntu_confirm_maintenance_')]
            confirm.check().run()
            keyed('ubuntu_run_maintenance_')[0].click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            app.run()
            self.assertEqual(keyed('ubuntu_run_maintenance_'), [])  # dispatched once; never offered again
            # Reboot completing the applied fix: now available.
            self.assertFalse(app.button(key='ubuntu_prepare_reboot').disabled)
            app.button(key='ubuntu_prepare_reboot').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(len(keyed('ubuntu_approve_')), 1)  # the reboot proposal waits for its own approval
        self.assertEqual(len([c for c in channel.runner_calls if c.startswith(b'{"op":"execute"}')]), 2)
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())


for _name in [n for n in dir(FixUiTests) if n.startswith('test')]:
    setattr(MaintenanceUiTests, _name, None)  # only the harness is inherited
del FixUiTests
