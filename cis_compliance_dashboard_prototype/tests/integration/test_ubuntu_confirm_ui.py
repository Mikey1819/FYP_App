"""Page flow for a commit-confirm fix: execute -> check status -> refused on the same login -> reconnect -> confirm.

TEST-ONLY confirm family and fake systemd launcher; the VM is never contacted.
"""
from unittest import mock
from tests.integration.test_ubuntu_fix_ui import FixUiTests
from tests.integration.test_ubuntu_supervision import ConfirmFamily, FakeLauncher
from tests.integration.pairing_fixture import paired_connect


class ConfirmUiTests(FixUiTests):
    def setUp(self):
        super().setUp()
        self.family, self.launcher = ConfirmFamily(self.work), FakeLauncher()

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.runner import Runner
        family = family or self.family
        return Runner(self.state, {family.action_id: family}, lambda: identity or ('a' * 32, 'ubuntu-fixture'),
                      clock=clock or self.now, require_root_owned=False, launcher=self.launcher)

    def test_page_execute_then_reconnect_and_confirm(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from system.bootstrap import SERVICE_KEY, WORKFLOW_KEY
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
                                 model_probe=lambda: True)

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service

        def connect():
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            self.assertFalse(list(app.error), [e.value for e in app.error])

        def keyed(prefix, exclude=None):
            return [b for b in app.button if b.key and b.key.startswith(prefix) and b.key != exclude]

        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app.run()
            connect()
            app.button(key='agentic_run').click().run()
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            keyed('ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
            app.button(key='ubuntu_execute_review').click().run()  # Windows-style: review, then confirm
            app.button(key='ubuntu_execute').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            app.run()
            [status] = keyed('ubuntu_status_')
            rid = status.key.removeprefix('ubuntu_status_')
            self.assertEqual(keyed('ubuntu_confirm_change_'), [])  # still running: nothing to confirm yet
            self.runner().run_job(rid)
            self.launcher.active.discard(rid)
            status.click().run()
            app.run()
            [confirm] = keyed('ubuntu_confirm_change_')
            self.assertIn('reconnect', ' '.join(w.value for w in app.warning).lower())
            confirm.click().run()  # the same login that dispatched the change proves nothing
            self.assertIn('fresh login', ' '.join(e.value for e in app.error).lower())
            app.button(key='agentic_disconnect').click().run()
            self.assertNotIn(WORKFLOW_KEY, app.session_state)
            connect()
            [confirm] = keyed('ubuntu_confirm_change_')  # found again without the old workflow key
            confirm.click().run()
            app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(keyed('ubuntu_confirm_change_'), [])
            self.assertIn(WORKFLOW_KEY, app.session_state)
        self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
        self.assertEqual(len([c for c in self.runner_calls() if c.startswith(b'{"op":"execute"}')]), 1)
        # The refused same-login attempt never reached the target; only the fresh login sent a confirm.
        self.assertEqual(len([c for c in self.runner_calls() if c.startswith(b'{"op":"confirm"')]), 1)
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())

    def make_channel(self):
        channel = super().make_channel()
        self._channels = getattr(self, '_channels', []) + [channel]
        return channel

    def runner_calls(self):
        return [c for channel in self._channels for c in channel.runner_calls]


for _name in [n for n in dir(FixUiTests) if n.startswith('test')]:
    setattr(ConfirmUiTests, _name, None)  # only the harness is inherited
del FixUiTests
