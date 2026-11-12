"""Same-page Ubuntu Fixes flow with the TEST-ONLY file-value family: propose -> approve -> confirm -> execute once."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from tests.integration.test_ubuntu_proposals import StoreFixture
from tests.integration.pairing_fixture import paired_connect


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

    @staticmethod
    def text(app):
        return ' '.join(e.value.replace(chr(92), '') for kind in (app.markdown, app.caption, app.info, app.warning)
                        for e in kind)

    @staticmethod
    def approve_buttons(app):
        return [b for b in app.button if b.key and b.key.startswith('ubuntu_approve_') and b.key != 'ubuntu_approve_all']

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

        service = ConnectionService(ledger, ssh_factory=lambda *a: channel, backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service
        with open_gate():
            app.run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            self.assertEqual([t for t in app.text_input if t.key == 'agentic_goal'], [])  # round goals are disabled
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            approve = self.approve_buttons(app)
            self.assertEqual(len(approve), 1)
            # No "Refresh status" button (administrator request 2026-11-09): a rerun redraws from the stored records
            # and keeps the connection.
            self.assertEqual([b for b in app.button if b.key == 'ubuntu_refresh'], [])
            app.run()
            self.assertTrue([b for b in app.button if b.key == 'agentic_disconnect'])  # still connected
            self.assertEqual([b for b in app.button if b.key == 'ubuntu_verify_applied'], [])  # nothing applied yet
            # The Windows layout: one bordered row per proposed fix, numbered, with its decision on the right.
            self.assertIn('#1 · CIS 1.5.1 · TEST-ONLY fixture value', self.text(app))  # As on Windows: rank, then ID.
            self.assertIn('Why the Orchestrator chose it', self.text(app))
            self.assertTrue(approve[0].disabled)  # no operator name yet
            self.assertTrue(app.button(key='ubuntu_approve_all').disabled)
            self.assertIn('Press Enter after typing your name.', [c.value for c in app.caption])  # As on Windows.
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.assertNotIn('Press Enter after typing your name.', [c.value for c in app.caption])
            self.approve_buttons(app)[0].click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(self.approve_buttons(app), [])
            self.assertIn('by fixture-operator, valid until', self.text(app))  # As on Windows: who and until when.
            review = app.button(key='ubuntu_execute_review')
            self.assertTrue(review.disabled)  # the real execution gate is closed
            self.assertEqual(self.writes(), [])
            with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
                app.run()
                self.assertEqual([b for b in app.button if b.key == 'ubuntu_execute'], [])  # confirmation first
                self.model_up = False  # without the model, Confirm runs the fixes in plan order
                app.button(key='ubuntu_execute_review').click().run()
                self.assertIn('Confirm: change 1 setting(s) on', self.text(app))
                self.assertEqual(self.writes(), [])
                app.button(key='ubuntu_execute').click().run()  # the model is down: plan order (agentic: test_ubuntu_remediation_ui)
                self.assertFalse(list(app.error), [e.value for e in app.error])
                app.run()
                self.assertEqual(self.writes(), ['alpha'])
                self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
                self.assertIn(':red-badge[Failed]', self.text(app))  # fixture keeps ASLR 0, so the re-scan fails
                # Restore: prepare -> approve -> confirm -> run, through the same page and gates.
                [prepare] = [b for b in app.button if b.key and b.key.startswith('ubuntu_prepare_restore_')]
                prepare.click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                [approve] = self.approve_buttons(app)
                approve.click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                [run] = [b for b in app.button if b.key and b.key.startswith('ubuntu_run_restore_')]
                self.assertTrue(run.disabled)  # confirmation required
                [confirm] = [c for c in app.checkbox if c.key and c.key.startswith('ubuntu_confirm_restore_')]
                confirm.check().run()
                [b for b in app.button if b.key and b.key.startswith('ubuntu_run_restore_')][0].click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                app.run()
                self.assertIn(':gray-badge[Restored]', self.text(app))
        self.assertEqual((self.work / 'alpha').read_bytes(), b'old')
        self.assertEqual(len([c for c in channel.runner_calls if c.startswith(b'{"op":"execute"}')]), 2)
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())

    def test_next_round_starts_while_the_first_rounds_fix_is_still_undecided(self):
        """Ubuntu page (administrator request 2026-11-10): Run next round right after the first scan, without deciding
        its fix. The second round runs; the first round's fix stays there, read-only, and nothing is written."""
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
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY fixture value',
                          recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']})
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')

        def backend_factory(session):
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': spec.action_id, 'reason_code': 'highest_risk'}
            clients = team([call('delegate_scanner'), call('delegate_analysis'), plan_call([fix]),
                            call('delegate_scanner'), call('delegate_analysis'), plan_call([fix])],
                           scanner_ok() + scanner_ok(), RankingAware())
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
        with open_gate():
            app.run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(len(self.approve_buttons(app)), 1)  # the first round's fix awaits a decision
            app.button(key='agentic_run').click().run()  # Run next round without deciding it
            self.assertFalse(list(app.error), [e.value for e in app.error])
            picker = app.selectbox(key='ubuntu_round_view')
            self.assertEqual(len(picker.options), 2)  # the second round ran
            self.assertEqual(len(self.approve_buttons(app)), 1)  # the new round proposes the fix again
            picker.select_index(1).run()  # the first round: read-only, its fix undecided
            self.assertIn('An earlier round, read-only', self.text(app))
            self.assertEqual(self.approve_buttons(app), [])
        self.assertEqual(self.writes(), [])

    def test_next_round_stays_offered_with_open_fixes_comments_show_and_a_reconnect_resumes(self):
        """Ubuntu page (administrator request 2026-11-10): a new round can start while a fix awaits a decision or
        execution; decision comments are shown, maintenance waits for a round, and after a reconnect the earlier
        session can be resumed (or a new round started)."""
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
                                 model_probe=lambda: getattr(self, 'model_up', True))

        service = ConnectionService(ledger, ssh_factory=lambda *a: self.make_channel(), backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = service

        def keys():
            return {b.key for b in app.button if b.key}
        with open_gate():
            app.run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            self.assertEqual(app.button(key='agentic_run').label, 'Start agentic round')
            self.assertNotIn('ubuntu_prepare_refresh', keys())  # no maintenance before the first round
            self.assertNotIn('agentic_resume', keys())  # nothing to resume yet
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(app.button(key='agentic_run').label, 'Run next round')  # offered with a fix undecided
            self.assertIn('1 proposed fix(es) need your decision', self.text(app))
            # Nothing went wrong and no fix needs a restart: no Maintenance (administrator request 2026-11-09).
            self.assertFalse({'ubuntu_prepare_refresh', 'ubuntu_prepare_reboot'} & keys())
            self.assertNotIn('Maintenance', self.text(app))
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            app.text_input(key='agentic_comment').input('Approved for the Saturday window').run()
            self.approve_buttons(app)[0].click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertIn('Comment: Approved for the Saturday window (fixture-operator)', self.text(app))
            self.assertIn('agentic_run', keys())  # approved but not executed: a new round is still offered
            workflow = app.session_state[WORKFLOW_KEY]
            # Disconnect and connect again: the page offers the earlier session instead of a fresh round.
            app.button(key='agentic_disconnect').click().run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            self.assertNotIn(WORKFLOW_KEY, app.session_state)
            self.assertIn('1 fix(es) still open', self.text(app))
            self.assertEqual(app.button(key='agentic_run').label, 'Start agentic round')  # not held back
            self.assertNotIn('Resume the earlier session to decide or execute its open fixes first', self.text(app))
            app.button(key='agentic_resume').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(app.session_state[WORKFLOW_KEY], workflow)
            self.assertIn('by fixture-operator, valid until', self.text(app))
            self.assertIn('Comment: Approved for the Saturday window (fixture-operator)', self.text(app))
            self.assertIn('ubuntu_execute_review', keys())
        self.assertEqual(self.writes(), [])
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())
