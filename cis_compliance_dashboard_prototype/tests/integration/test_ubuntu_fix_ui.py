"""Same-page Ubuntu Fixes flow with the TEST-ONLY file-value family: propose -> approve -> confirm -> execute once."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from tests.integration.test_ubuntu_proposals import StoreFixture


class FixUiTests(StoreFixture):
    def make_channel(self):
        from tests.integration.test_system_acceptance import FixtureSsh
        from tests.integration.test_ubuntu_live_path import CliChannel, run_cli, fake_io_factory, fake_preflight
        test = self

        class Channel(FixtureSsh, CliChannel):
            def __init__(self):
                CliChannel.__init__(self); self.runner_calls = []
            def invoke_helper(self, stdin_bytes, **kwargs):
                self.calls += 1
                def factory():
                    target = fake_io_factory()()
                    original = target.command
                    target.command = lambda key: (SimpleNamespace(returncode=0, stdout='0' + chr(10))
                                                  if key == 'sysctl.kernel.randomize_va_space' else original(key))
                    return target
                code, out, _ = run_cli(stdin_bytes, io_factory=factory, preflight=fake_preflight)
                if code:
                    raise ValueError('collector refused')
                return out
            def invoke_runner(self, data, **kwargs):
                self.runner_calls.append(data)
                from vm.ubuntu.runner_cli import main
                out, err = io.BytesIO(), io.BytesIO()
                if main(stdin=io.BytesIO(data), stdout=out, stderr=err, runner_factory=lambda: test.runner(clock=test.now)):
                    raise ValueError('runner refused')
                return out.getvalue()
        return Channel()

    def now(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)

    def test_page_approves_then_confirms_and_executes_the_exact_set_once(self):
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
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': spec.action_id, 'reason_code': 'high_risk'}
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
        with open_gate():
            app.run()
            for key, value in (('agentic_hostname', LIVE[1]), ('agentic_uuid', LIVE[0]), ('agentic_host', 'fixture.invalid'),
                               ('agentic_user', 'fixture-user'), ('agentic_password', 'FIXTURE-SECRET-SENTINEL')):
                app.text_input(key=key).input(value)
            app.number_input(key='agentic_port').set_value(22)
            app.selectbox(key='agentic_method').select('SSH')
            app.run()
            app.button(key='agentic_connect').click().run()
            self.assertEqual([t for t in app.text_input if t.key == 'agentic_goal'], [])  # round goals are disabled
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            approve = [b for b in app.button if b.key and b.key.startswith('ubuntu_approve_')]
            self.assertEqual(len(approve), 1)
            self.assertTrue(approve[0].disabled)  # no operator name yet
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            [b for b in app.button if b.key.startswith('ubuntu_approve_')][0].click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual([b for b in app.button if b.key and b.key.startswith('ubuntu_approve_')], [])
            execute = app.button(key='ubuntu_execute')
            self.assertTrue(execute.disabled)  # the real execution gate is closed
            self.assertEqual(self.writes(), [])
            with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
                app.run()
                self.assertTrue(app.button(key='ubuntu_execute').disabled)  # confirmation still required
                app.checkbox(key='ubuntu_confirm_execute').check().run()
                app.button(key='ubuntu_execute').click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                app.run()
                self.assertEqual(self.writes(), ['alpha'])
                self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
                # Restore: prepare -> approve -> confirm -> run, through the same page and gates.
                [prepare] = [b for b in app.button if b.key and b.key.startswith('ubuntu_prepare_restore_')]
                prepare.click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                app.text_input(key='agentic_operator').input('fixture-operator').run()  # a new decision names its operator
                [approve] = [b for b in app.button if b.key and b.key.startswith('ubuntu_approve_')]
                approve.click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                [run] = [b for b in app.button if b.key and b.key.startswith('ubuntu_run_restore_')]
                self.assertTrue(run.disabled)  # confirmation required
                [confirm] = [c for c in app.checkbox if c.key and c.key.startswith('ubuntu_confirm_restore_')]
                confirm.check().run()
                [b for b in app.button if b.key and b.key.startswith('ubuntu_run_restore_')][0].click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                app.run()
        self.assertEqual((self.work / 'alpha').read_bytes(), b'old')
        self.assertEqual(len([c for c in channel.runner_calls if c.startswith(b'{"op":"execute"}')]), 2)
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())
