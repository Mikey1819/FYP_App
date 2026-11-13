"""Problem 7 on the page: one Execute click; after the fix that waited has settled, the rest of the execution runs
without a new click. TEST-ONLY families (a supervised job on 3.3.1, a commit-confirm value on 1.5.1), fake systemd
launcher and fake server; the VM is never contacted.
"""
from unittest import mock
from tests.integration import test_ubuntu_confirm_ui as confirm_ui
from tests.integration.test_ubuntu_execution_continue import SecondJobFamily, two_failures
from tests.integration.pairing_fixture import paired_connect


class ContinueUiTests(confirm_ui.ConfirmUiTests):
    def setUp(self):
        super().setUp()
        patch = two_failures()
        patch.start()
        self.addCleanup(patch.stop)
        self.job_family = SecondJobFamily(self.work)

    def runner(self, family=None, *, identity=None, clock=None):
        from vm.ubuntu.runner import Runner
        families = {f.action_id: f for f in (self.family, self.job_family)}
        return Runner(self.state, families, lambda: identity or ('a' * 32, 'ubuntu-fixture'),
                      clock=clock or self.now, require_root_owned=False, launcher=self.launcher)

    def page(self):
        """The page connected (login remembered, as the Servers page does) with one round of two proposed fixes."""
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from tests.integration.pairing_fixture import SECRET
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from hardening.reconnect import RECONNECT
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        confirm = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate,
                             60, propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'},
                             title='TEST-ONLY confirm value', recovery={'kind': 'restore_backup', 'scope': ['f:a']})
        job = ActionSpec(self.job_family.action_id, 1, self.job_family.implementation_sha256, ('3.3.1',),
                         self.job_family.validate, 60, propose=lambda cid, evidence: {'name': 'beta', 'value': 'new'},
                         title='TEST-ONLY job value', recovery={'kind': 'restore_backup', 'scope': ['f:b']})
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            fixes = [{'control_id': '1.5.1', 'decision': 'fix', 'action_id': confirm.action_id, 'reason_code': 'highest_risk'},
                     {'control_id': '3.3.1', 'decision': 'fix', 'action_id': job.action_id, 'reason_code': 'highest_risk'}]
            clients = team([call('delegate_scanner'), call('delegate_analysis'), plan_call(fixes)],
                           scanner_ok(), RankingAware())
            for client in clients.values():
                if isinstance(client, Scripted):
                    for item in client.script:
                        item['tool_calls'][0]['function']['arguments']['target_id'] = session.target_id
            RankingAware.target = session.target_id
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={confirm.action_id: confirm, job.action_id: job},
                                 model_client_factory=clients.__getitem__,
                                 model_probe=lambda: getattr(self, 'model_up', True))

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service

        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0],
                                        run=False).state, 'connected')
        app.session_state[RECONNECT] = dict(host='fixture.invalid', port=22, hostname=LIVE[1], identity=LIVE[0],
                                            username='fixture-user', password=SECRET, key_path=None, sudo=None)
        app.run()
        app.button(key='agentic_run').click().run()
        app.text_input(key='agentic_operator').input('fixture-operator').run()
        return app

    @staticmethod
    def keyed(app, prefix, exclude=None):
        return [b for b in app.button if b.key and b.key.startswith(prefix) and b.key != exclude]

    def test_after_the_job_settles_the_confirm_fix_runs_without_a_new_click(self):
        from tests.integration.test_ubuntu_live_path import open_gate

        def keyed(prefix, exclude=None):
            return self.keyed(app, prefix, exclude)

        def pending():
            # Behind the running animation since 13 November 2026: the job the server is running.
            self.assertEqual(keyed('ubuntu_status_'), [])
            [request_id] = list(self.launcher.active)
            return request_id

        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.page()
            for _ in range(2):
                keyed('ubuntu_approve_', exclude='ubuntu_approve_all')[0].click().run()
            self.model_up = False  # without the model, Confirm runs the fixes in code's order
            app.button(key='ubuntu_execute_review').click().run()
            app.button(key='ubuntu_execute').click().run()  # the only Execute click
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(self.sent(), ['beta'])  # the job first; the confirm fix waits for it
            self.job(pending())
            for _ in range(3):  # the watcher settles the job; the page then sends the rest by itself
                app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(self.sent(), ['beta', 'alpha'])
            self.job(pending())  # the confirm fix ran on the server and now waits for its fresh-login confirmation
            app.run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(keyed('ubuntu_status_'), [])
        self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
        self.assertEqual((self.work / 'beta').read_bytes(), b'new')
        self.assertEqual(self.sent(), ['beta', 'alpha'])  # each sent once
        self.assertEqual(len([c for c in self.runner_calls() if c.startswith(b'{"op":"confirm"')]), 1)

    def test_a_refused_continuation_is_shown_once_and_not_retried(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        from backends.ubuntu.adapter import UbuntuBackend
        refused = mock.Mock(side_effect=ValueError('TEST-ONLY continuation refused'))
        with open_gate(), mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            app = self.page()
            with mock.patch.object(UbuntuBackend, 'continuation', return_value=('TEST-ONLY-request',)), \
                    mock.patch.object(UbuntuBackend, 'continue_execution', refused):
                shown = []
                for _ in range(4):
                    app.run()
                    shown += [e.value for e in app.error]
        self.assertEqual(refused.call_count, 1)
        self.assertEqual(sum('continuation refused' in e for e in shown), 1, shown)  # shown once

    def job(self, request_id):
        self.runner().run_job(request_id)
        self.launcher.active.discard(request_id)

    def sent(self):
        import json
        return [json.loads(c.split(b'\n', 1)[1])['parameters']['name'] for c in self.runner_calls()
                if c.startswith(b'{"op":"execute"}')]


for _name in [n for n in dir(confirm_ui.ConfirmUiTests) if n.startswith('test')]:
    setattr(ContinueUiTests, _name, None)  # only the harness is inherited
