"""The Ubuntu page follows the Windows page (administrator request 2026-11-09): a round picker (earlier rounds
read-only), a downloadable HTML round report, the configuration changes found by the verification scan in Results,
the finding details with "Explain with local AI" under Risk ranking, and "Execute remaining without AI" only once
the agents stopped early. TEST-ONLY file-value family and scripted models; no VM."""
import io
from types import SimpleNamespace
from unittest import mock

from tests.integration import test_ubuntu_fix_ui as base  # module import: base tests are not collected twice
from tests.integration.pairing_fixture import paired_connect

EXPLAIN = 'Explain with local AI'


class RoundViewTests(base.FixUiTests):
    def make_channel(self):
        """As the base channel, but the fixture's ASLR reads 2 once the approved fix wrote its value, so the
        verification scan sees a real configuration change."""
        from tests.integration.test_system_acceptance import FixtureSsh
        from tests.integration.test_ubuntu_live_path import CliChannel, run_cli, fake_io_factory, fake_preflight
        test = self

        def aslr():
            alpha = test.work / 'alpha'
            return '2' if alpha.exists() and alpha.read_bytes() == b'new' else '0'

        class Channel(FixtureSsh, CliChannel):
            def __init__(self):
                CliChannel.__init__(self); self.runner_calls = []
            def invoke_helper(self, stdin_bytes, **kwargs):
                self.calls += 1
                def factory():
                    target = fake_io_factory()()
                    original = target.command
                    target.command = lambda key: (SimpleNamespace(returncode=0, stdout=aslr() + chr(10))
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

    def page(self):
        """Connected page whose scripted agents run two rounds; the Remediation Agent stops without a decision."""
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import TARGET as LIVE
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from backends.ubuntu.remediation_agents import REMEDIATION
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        self.channel = self.make_channel()
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY fixture value',
                          recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']})
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')
        self.clients = clients = {}

        def backend_factory(session):
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': spec.action_id, 'reason_code': 'highest_risk'}
            clients.update(team([call('delegate_scanner'), call('delegate_analysis'), plan_call([fix]),
                                 # The remediation phase: the Remediation Agent stops without a decision.
                                 call('delegate_remediation'),
                                 call('submit_review', next_step='remediation_review', reason_code='remediation_incomplete'),
                                 # The second round.
                                 call('delegate_scanner'), call('delegate_analysis'), plan_call([])],
                                scanner_ok() + scanner_ok(), RankingAware()))
            clients[REMEDIATION] = Scripted([])
            for client in clients.values():
                if isinstance(client, Scripted):
                    for item in client.script:
                        item['tool_calls'][0]['function']['arguments']['target_id'] = session.target_id
            clients['explanation'] = Scripted([{'role': 'assistant',
                                                'content': 'ASLR makes memory addresses hard to guess.'}])
            RankingAware.target = session.target_id
            return UbuntuBackend(self.root / 'ubuntu' / 'imports.sqlite3', session=session, ledger=ledger,
                                 families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                                 model_probe=lambda: True)

        self.service = ConnectionService(ledger, ssh_factory=lambda *a: self.channel, backend_factory=backend_factory)
        app = AppTest.from_function(existing_page, default_timeout=60)
        app.session_state['fixture_database'] = str(self.root / 'windows' / 'imports.sqlite3')
        app.session_state[SERVICE_KEY] = self.service
        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
        return app

    def ok(self, app):
        self.assertFalse(list(app.error), [e.value for e in app.error])
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        return app

    @staticmethod
    def tab(app, label):
        return next(t for t in app.tabs if t.label == label)

    @staticmethod
    def keys(app):
        return {b.key for b in app.button if b.key}

    def test_risk_ranking_shows_the_finding_details_and_explains_one_finding(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            app = self.page()
            self.ok(app.button(key='agentic_run').click().run())
            risk, fixes = self.tab(app, 'Risk ranking'), self.tab(app, 'Fixes')
            # As on Windows: a selector of the ranked findings, then the chosen one's factors and the button.
            self.assertTrue([s for s in risk.selectbox if s.label == 'Finding details'])
            factors = [row['Factor'] for frame in risk.dataframe for row in frame.value.to_dict('records')
                       if 'Factor' in row]
            self.assertEqual(factors, ['I Security impact', 'E Exposure', 'P Privilege impact', 'L Likelihood',
                                       'D Drift'])
            self.assertEqual([b.label for b in fixes.button if b.label == EXPLAIN], [])  # not in the fix cards
            [explain] = [b for b in risk.button if b.label == EXPLAIN]
            self.ok(explain.click().run())
            self.assertIn('Model-written explanation (unverified; does not affect the score):', self.text(app))
            self.assertIn('ASLR makes memory addresses hard to guess.', ' '.join(t.value for t in app.text))
        self.assertEqual(self.clients['explanation'].tools_seen, [[]])  # no tools: the explanation changes nothing

    def test_execute_remaining_without_ai_appears_only_after_the_agents_stopped_early(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            app = self.page()
            self.ok(app.button(key='agentic_run').click().run())
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.ok(self.approve_buttons(app)[0].click().run())
            with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
                app.run()
                self.assertNotIn('ubuntu_execute_fallback', self.keys(app))  # the agents have not run yet
                self.ok(app.button(key='ubuntu_execute_review').click().run())
                self.assertNotIn('ubuntu_execute_fallback', self.keys(app))  # nor on the confirmation
                self.ok(app.button(key='ubuntu_execute').click().run())
                self.ok(app.run())
                self.assertEqual(self.writes(), [])  # the Remediation Agent stopped without a decision
                self.assertIn('Orchestrator review:', self.text(app) + ' '.join(i.value for i in app.info))
                fallback = app.button(key='ubuntu_execute_fallback')
                self.assertEqual(fallback.label, 'Execute remaining without AI')
                self.ok(fallback.click().run())
                self.ok(app.run())
                self.assertEqual(self.writes(), ['alpha'])  # executed once, in plan order, without AI
                self.assertNotIn('ubuntu_execute_fallback', self.keys(app))  # nothing approved is left
                # As on Windows, the outcome now says it ran without AI; the stopped phase's review is superseded.
                shown = self.text(app) + ' '.join(i.value for i in app.info)
                self.assertIn('Executed without AI', shown)
                self.assertNotIn('1.5.1 was not attempted', shown)
        executes = [c for c in self.channel.runner_calls if c.startswith(b'{"op":"execute"}')]
        self.assertEqual(len(executes), 1)

    def test_round_picker_report_and_the_changes_found_by_the_verification_scan(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        from system.bootstrap import CONNECTION_KEY, WORKFLOW_KEY
        from system.ui.round_report import ubuntu_round_report
        with open_gate():
            app = self.page()
            self.ok(app.button(key='agentic_run').click().run())
            self.assertEqual([s for s in app.selectbox if s.key == 'ubuntu_round_view'], [])  # one round: no picker
            self.assertTrue([d for d in app.get('download_button') if d.proto.label == 'Round report'])
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.ok(self.approve_buttons(app)[0].click().run())
            with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
                app.run()
                self.ok(app.button(key='ubuntu_execute_review').click().run())
                self.ok(app.button(key='ubuntu_execute').click().run())
                self.ok(app.run())
                self.ok(app.button(key='ubuntu_execute_fallback').click().run())
                self.ok(app.run())
                self.assertEqual(self.writes(), ['alpha'])
                # Results: the configuration changes the verification scan found, as on Windows.
                results = self.tab(app, 'Results')
                self.assertIn('Configuration changes found by the verification rescan', self.text(results))
                changes = [row for frame in results.dataframe for row in frame.value.to_dict('records')
                           if 'Change' in row and 'Before' in row]
                [aslr] = [row for row in changes if row['Control'] == '1.5.1']
                self.assertEqual((aslr['Before'], aslr['After'], aslr['Change']),
                                 ('Non-Compliant', 'Compliant', 'Improvement'))
                # The HTML report of the round, built from the stored records only.
                backend = self.service.backend_for(app.session_state[CONNECTION_KEY])
                connection, workflow = app.session_state[CONNECTION_KEY], app.session_state[WORKFLOW_KEY]
                snapshot = backend.snapshot(connection, workflow)
                html = ubuntu_round_report(snapshot, backend.assessment_rounds(connection, workflow),
                                           backend.remediation_review(connection, workflow),
                                           backend.verification_changes(connection, workflow,
                                                                        snapshot.current_round_reference))
                for section in ('1. Round outcome', '2. Risk ranking', '3. Proposed fixes and administrator decisions',
                                '4. Remediation and verification', '5. Agent activity', '6. All assessed controls',
                                'Configuration changes found by the verification rescan', 'fixture-operator',
                                'Improvement', 'CIS Ubuntu'):
                    self.assertIn(section, html)
                self.assertNotIn('ASLR makes memory addresses', html)  # model explanations are left out
                # A second round, then the earlier one through the picker: read-only.
                self.ok(app.button(key='agentic_run').click().run())
                picker = app.selectbox(key='ubuntu_round_view')
                self.assertEqual(len(picker.options), 2)
                self.assertTrue(picker.options[0].endswith('(latest)'))
                self.ok(picker.select_index(1).run())
                self.assertIn('An earlier round, read-only', self.text(app))
                self.assertNotIn('agentic_run', self.keys(app))
                self.assertEqual([k for k in self.keys(app) if k.startswith(('ubuntu_prepare_', 'ubuntu_approve'))], [])
                earlier = self.tab(app, 'Results')
                self.assertIn('Configuration changes found by the verification rescan', self.text(earlier))
                self.ok(app.selectbox(key='ubuntu_round_view').select_index(0).run())
                self.assertIn('agentic_run', self.keys(app))
        for database in self.root.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())


for _name in [n for n in dir(base.FixUiTests) if n.startswith('test')]:
    setattr(RoundViewTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    import unittest
    unittest.main()
