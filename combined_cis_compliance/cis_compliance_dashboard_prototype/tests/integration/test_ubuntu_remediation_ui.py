"""The Ubuntu page's agentic execution (2026-11-09): after approval, "Confirm and execute" runs the remediation phase.
The Remediation Agent prechecks and executes the approved fix once, the Scanner Agent verifies it, and the
Orchestrator's code-written review is shown. TEST-ONLY file-value family and scripted models; no VM."""
from unittest import mock

from tests.integration import test_ubuntu_fix_ui as base  # module import: base tests are not collected twice
from tests.integration.pairing_fixture import paired_connect


class RemediationUiTests(base.FixUiTests):
    def test_confirm_runs_the_remediation_agent_then_the_review(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import existing_page
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware, Scripted
        from tests.integration.test_ubuntu_live_path import open_gate, TARGET as LIVE
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from backends.ubuntu.remediation_agents import REMEDIATION
        from system.bootstrap import SERVICE_KEY
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        self.addCleanup(setattr, RankingAware, 'target', 'ubuntu:fixture')
        channel = self.make_channel()
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY fixture value',
                          recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']})
        ledger = CoordinationLedger(self.root / 'integration.sqlite3')
        clients = {}

        def backend_factory(session):
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': spec.action_id, 'reason_code': 'highest_risk'}
            # The fixture keeps ASLR at 0, so the verification scan reads 1.5.1 Non-Compliant: verification_failed.
            clients.update(team([call('delegate_scanner'), call('delegate_analysis'), plan_call([fix]),
                                 call('delegate_remediation'), call('delegate_verification'),
                                 call('submit_review', next_step='remediation_review', reason_code='verification_failed')],
                                scanner_ok() + [call('scan_target'), call('read_coverage'),
                                                call('handoff_verification', reason='verified')], RankingAware()))
            clients[REMEDIATION] = Scripted([call('precheck'), call('execute_fixes', control_ids=['1.5.1']),
                                             call('report_results')])
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
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=LIVE[1], identity=LIVE[0]).state, 'connected')
            app.button(key='agentic_run').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            app.text_input(key='agentic_operator').input('fixture-operator').run()
            self.approve_buttons(app)[0].click().run()
            with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
                app.run()
                app.button(key='ubuntu_execute_review').click().run()
                # As on Windows: the path without AI is offered only once the agents stopped early
                # (test_ubuntu_round_views), never beside Confirm.
                self.assertEqual([b.label for b in app.button if b.key == 'ubuntu_execute_fallback'], [])
                self.assertIn('The Remediation Agent re-checks each fix', self.text(app))
                app.button(key='ubuntu_execute').click().run()
                self.assertFalse(list(app.error), [e.value for e in app.error])
                app.run()
                self.assertEqual(self.writes(), ['alpha'])  # executed once, by the Remediation Agent
                text = self.text(app) + ' '.join(e.value for e in app.info)
                self.assertIn('Orchestrator review:', text)
                self.assertIn('1.5.1 did not verify Compliant', text)
                self.assertIn(':red-badge[Failed]', self.text(app))  # the Scanner Agent's verification scan
        executes = [c for c in channel.runner_calls if c.startswith(b'{"op":"execute"}')]
        self.assertEqual(len(executes), 1)
        self.assertEqual(clients[REMEDIATION].script, [])  # the Remediation Agent made every scripted call


for _name in [n for n in dir(base.FixUiTests) if n.startswith('test')]:
    setattr(RemediationUiTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    import unittest
    unittest.main()
