from contextlib import closing
from datetime import datetime, timedelta
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from hardening.import_storage import ImportedEvidenceStore
from hardening.vm_bridge import BridgeStore
from hardening.framework import AssessmentOrchestrator
from hardening.lifecycle import RemediationLifecycle
from test_evidence_import import export_fixture, MACHINE_UUID
from test_expanded_controls import expanded_fixture, observation
from test_local_security_controls import local_security_fixture
from test_agent_team import scripted_clients
from hardening.agent_team import ORCHESTRATOR, SCANNER, ANALYSIS, REMEDIATION
from hardening.scan_exchange import ScanExchange
from test_scan_exchange import response_fixture
from test_worker_readiness import worker_fixture

APP = Path(__file__).resolve().parents[1] / 'legacy_app.py'

class Upload(io.BytesIO):
    @property
    def size(self):
        return len(self.getvalue())

class ImportViewTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.database = Path(folder.name) / 'preview.sqlite3'
        self.imports = self.database.with_name('preview_imports.sqlite3')
        env = patch.dict(os.environ, {'CIS_DASHBOARD_DB': str(self.database),
                                    'CIS_SCAN_EXCHANGE': str(Path(folder.name) / 'queue')})
        env.start(); self.addCleanup(env.stop)
        self.uploads = {'evidence': None, 'receipt': None}
        def upload(*args, **kwargs):
            kind = 'receipt' if kwargs.get('key', '').startswith('vm_receipt_') else 'evidence'
            raw = self.uploads[kind]
            return Upload(raw) if raw is not None else None
        mocked = patch('streamlit.file_uploader', side_effect=upload)
        mocked.start(); self.addCleanup(mocked.stop)

    def open_page(self):
        return AppTest.from_file(str(APP), default_timeout=30).run()

    def analyze(self, app, raw, compatibility='compatible'):
        self.uploads['evidence'] = raw
        app.run()
        app.text_input(key='vm_expected_host').set_value('FIXTURE-SERVER').run()
        app.text_input(key='vm_expected_uuid').set_value(MACHINE_UUID).run()
        app.button(key='analyze_vm_evidence').click().run()
        if compatibility is not None and not app.error and any(b.key == 'vm_context_save' for b in app.button):
            app.selectbox(key='vm_context_status').set_value(compatibility).run()
            app.text_input(key='vm_context_operator').set_value('fixture-operator').run()
            app.text_area(key='vm_context_note').set_value('Fixture provisioning supports 14 characters.').run()
            app.button(key='vm_context_save').click().run()
        return app

    def bridge(self):
        return BridgeStore(self.imports.with_name('preview_imports_bridge.sqlite3'), ImportedEvidenceStore(self.imports))

    def baseline(self, value=0):
        doc = export_fixture()
        doc['observations'][0]['value'] = value
        return json.dumps(doc).encode()

    def approve(self, app):
        app.button(key='vm_propose').click().run()
        identifier = app.session_state['vm_cycle_proposal']
        self.assertTrue(app.button(key='approve_' + identifier).disabled)
        app.text_input(key='operator_' + identifier).set_value('fixture-admin').run()
        app.checkbox(key='confirm_' + identifier).check().run()
        app.button(key='approve_' + identifier).click().run()
        return identifier

    def receipt(self, identifier):
        raw = self.bridge().get(identifier)['request']
        approved = datetime.fromisoformat(json.loads(raw)['approved_at'])
        evidence = []
        for offset, value in ((1, 0), (3, 14)):
            doc = export_fixture()
            doc['started_at'] = (approved + timedelta(seconds=offset)).isoformat()
            doc['completed_at'] = (approved + timedelta(seconds=offset + 1)).isoformat()
            for row in doc['observations']:
                row['collected_at'] = doc['started_at']
            doc['observations'][0]['value'] = value
            evidence.append(json.dumps(doc).encode())
        return json.dumps(dict(schema_version=1, request_id=identifier,
            request_sha256=hashlib.sha256(raw).hexdigest(), status='applied',
            before_evidence=base64.b64encode(evidence[0]).decode(),
            after_evidence=base64.b64encode(evidence[1]).decode())).encode()

    def test_blank_start_despite_populated_database_and_legacy_session_keys(self):
        saved, _ = ImportedEvidenceStore(self.imports).save(self.baseline(14),
            expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        app = self.open_page()
        app.session_state['saved_vm_import'] = saved.assessment.source_sha256
        app.run()
        self.assertFalse(app.metric)
        self.assertFalse(app.dataframe)
        self.assertFalse(app.selectbox)
        self.assertFalse(app.sidebar.radio)
        self.assertFalse(self.database.exists())
        self.assertTrue(any('No previous assessment' in i.value for i in app.info))
        self.assertFalse(any(b.key == 'vm_propose' for b in app.button))

    def test_current_upload_only_and_restart_does_not_reload_results(self):
        app = self.analyze(self.open_page(), self.baseline(0))
        self.assertFalse(app.exception)
        self.assertEqual(app.dataframe[0].value.iloc[0]['Observed'], '0')
        self.assertTrue(any('single executable remediation' in i.value for i in app.info))
        run_id = app.session_state['vm_cycle_framework_run']
        run = AssessmentOrchestrator(ImportedEvidenceStore(self.imports)).get(run_id)
        self.assertEqual(run.state, 'ready_for_review')
        self.assertEqual(len(run.tasks), 3)
        self.assertEqual(list(app.table[0].value['Role']), ['Scanner Agent', 'Analysis Agent', 'Remediation Agent'])
        self.uploads['evidence'] = None
        restarted = self.open_page()
        self.assertFalse(restarted.metric)
        self.assertFalse(restarted.selectbox)
        self.assertEqual(len(ImportedEvidenceStore(self.imports).recent()), 1)

    def test_expanded_upload_displays_all_checks_and_coverage(self):
        data = expanded_fixture()
        observation(data, '1.1.4')['value'] = 0
        observation(data, '1.1.2')['value'] = -1
        observation(data, '1.2.4').update(state='missing', value=None)
        app = self.analyze(self.open_page(), json.dumps(data).encode())
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        self.assertEqual(app.metric[0].value, '11 / 12')
        self.assertEqual(len(app.dataframe[0].value), 12)
        self.assertEqual(set(app.dataframe[0].value['Control']), {r['control_id'] for r in data['observations']})
        self.assertTrue(any('never expire' in caption.value for caption in app.caption))
        self.assertTrue(any(b.key == 'vm_propose' for b in app.button))

    def test_sixteen_control_filters_do_not_change_coverage_or_stored_evidence(self):
        data = local_security_fixture()
        observation(data, '2.3.1.2')['value'] = 0
        observation(data, '2.3.10.1').update(state='missing', value=None)
        raw = json.dumps(data).encode()
        app = self.analyze(self.open_page(), raw)
        self.assertFalse(app.exception)
        self.assertEqual(app.metric[0].value, '15 / 16')
        self.assertEqual(len(app.dataframe[0].value), 16)
        digest = app.session_state['vm_cycle_digest']
        key = 'assessment_filter_' + digest
        app.selectbox(key=key + '_status').set_value('Non-Compliant').run()
        app.selectbox(key=key + '_area').set_value('Local Security Options').run()
        self.assertEqual(list(app.dataframe[0].value['Control']), ['2.3.1.2'])
        self.assertEqual(app.metric[0].value, '15 / 16')
        app.selectbox(key=key + '_area').set_value('Remote Desktop Services').run()
        self.assertTrue(any('No checks match' in item.value for item in app.info))
        self.assertEqual(len(app.dataframe[0].value), 0)
        app.selectbox(key=key + '_area').set_value('All areas').run()
        app.selectbox(key=key + '_status').set_value('All statuses').run()
        self.assertEqual(len(app.dataframe[0].value), 16)
        self.assertEqual(ImportedEvidenceStore(self.imports).get(digest).raw, raw)

    def test_team_button_shows_four_roles_and_leaves_proposal_unapproved(self):
        app = self.analyze(self.open_page(), self.baseline(0))
        clients = scripted_clients('windows:' + MACHINE_UUID)
        with patch('hardening.agent_team.OllamaClient', side_effect=[clients[r] for r in (ORCHESTRATOR, SCANNER, ANALYSIS, REMEDIATION)]):
            app.button(key='vm_agent_team').click().run()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        team_table = next(frame.value for frame in app.dataframe if 'Agent' in frame.value.columns)
        self.assertEqual(set(team_table['Agent']), {ORCHESTRATOR, SCANNER, ANALYSIS, REMEDIATION})
        identifier = app.session_state['vm_cycle_proposal']
        self.assertIsNone(self.bridge().get(identifier)['decision'])
        self.assertTrue(app.button(key='vm_agent_team').disabled)

    def test_request_scan_from_blank_page_then_import_response_without_upload(self):
        app = self.open_page()
        app.text_input(key='vm_expected_host').set_value('FIXTURE-SERVER').run()
        app.text_input(key='vm_expected_uuid').set_value(MACHINE_UUID).run()
        app.button(key='vm_request_scan').click().run()
        self.assertFalse(app.exception)
        identifier = app.session_state['vm_cycle_scan_id']
        app.button(key='vm_check_scan').click().run()
        self.assertFalse(app.metric)
        self.assertTrue(any('Awaiting VM worker' in x.value for x in app.info))
        exchange = ScanExchange(AssessmentOrchestrator(ImportedEvidenceStore(self.imports)), os.environ['CIS_SCAN_EXCHANGE'])
        exchange._file(identifier, 'response').write_text(json.dumps(response_fixture(exchange.get(identifier))), encoding='utf-8')
        app.button(key='vm_check_scan').click().run()
        self.assertFalse(app.exception)
        self.assertFalse(app.error)
        self.assertEqual(app.metric[0].value, '32 / 32')
        self.assertEqual(len(app.dataframe[0].value), 32)
        self.assertFalse(self.uploads['evidence'])

    def test_scanner_team_queue_does_not_replace_later_selected_request(self):
        data = local_security_fixture()
        observation(data, '1.1.4').update(state='missing', value=None)
        app = self.analyze(self.open_page(), json.dumps(data).encode(), compatibility=None)
        clients = scripted_clients('windows:' + MACHINE_UUID, branch='missing')
        with patch('hardening.agent_team.OllamaClient', side_effect=[clients[r] for r in (ORCHESTRATOR, SCANNER)]):
            app.button(key='vm_agent_team').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(app.session_state['vm_cycle_scan_id'])
        app.session_state['vm_cycle_scan_id'] = 'a' * 32
        app.run()
        self.assertEqual(app.session_state['vm_cycle_scan_id'], 'a' * 32)

    def test_worker_setup_command_and_report_do_not_create_assessment(self):
        from datetime import timezone
        app=self.open_page()
        app.text_input(key='vm_expected_host').set_value('FIXTURE-SERVER').run()
        app.text_input(key='vm_expected_uuid').set_value(MACHINE_UUID).run()
        self.assertTrue(any('Worker report: not_seen' in item.value for item in app.info))
        self.assertTrue(any('Watch-ScanRequests.ps1' in item.value and MACHINE_UUID in item.value for item in app.code))
        queue=Path(os.environ['CIS_SCAN_EXCHANGE']); queue.mkdir(parents=True,exist_ok=True)
        (queue/('worker-'+MACHINE_UUID+'.json')).write_text(json.dumps(worker_fixture(now=datetime.now(timezone.utc))),encoding='utf-8')
        app.button(key='vm_worker_refresh').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any('Worker report: ready' in item.value for item in app.info))
        self.assertFalse(app.metric)
        self.assertFalse(self.imports.exists())

    def test_rejected_upload_and_unsupported_storage_never_show_old_data(self):
        app = self.open_page()
        bad = export_fixture(); bad['target']['hostname'] = 'OTHER'
        self.analyze(app, json.dumps(bad).encode())
        self.assertTrue(any('selected target' in e.value for e in app.error))
        self.assertFalse(app.metric)
        self.uploads['evidence'] = b'x' * 65537
        app.run()
        self.assertTrue(any('maximum size' in e.value for e in app.error))
        with closing(sqlite3.connect(self.imports)) as db, db:
            db.execute('PRAGMA user_version = 99')
        self.analyze(app, self.baseline())
        self.assertTrue(app.error)
        self.assertFalse(app.metric)

    def test_reject_then_approve_same_test_and_dynamic_directory(self):
        app = self.analyze(self.open_page(), self.baseline())
        target = 'windows:' + MACHINE_UUID
        app.text_input(key='workspace_' + target).set_value(r"D:\Lab\Mikey's VM").run()
        app.button(key='save_workspace').click().run()
        app.button(key='vm_propose').click().run()
        rejected = app.session_state['vm_cycle_proposal']
        app.text_input(key='operator_' + rejected).set_value('fixture-admin').run()
        app.button(key='reject_' + rejected).click().run()
        self.assertIsNone(self.bridge().get(rejected)['request'])
        approved = self.approve(app)
        self.assertNotEqual(approved, rejected)
        remediation_commands = [c.value for c in app.code if 'Invoke-ApprovedVmAction.ps1' in c.value]
        self.assertEqual(len(remediation_commands), 1)
        self.assertIn("D:\\Lab\\Mikey''s VM", remediation_commands[0])
        self.assertNotIn('C:\\FYP', remediation_commands[0])
        app.run()
        self.assertEqual(app.session_state['vm_cycle_proposal'], approved)
        self.assertFalse(app.exception)

    def test_unrelated_framework_run_blocks_solution_review(self):
        app = self.analyze(self.open_page(), self.baseline(0))
        runtime = AssessmentOrchestrator(ImportedEvidenceStore(self.imports))
        other = runtime.start(self.baseline(14), expected_hostname='FIXTURE-SERVER',
                              expected_machine_uuid=MACHINE_UUID)
        runtime.complete_assessment(other.run_id)
        app.session_state['vm_cycle_framework_run'] = other.run_id
        app.run()
        self.assertFalse(app.exception)
        self.assertTrue(any('does not belong to this test' in e.value for e in app.error))
        self.assertFalse(any(b.key == 'vm_propose' for b in app.button))

    def test_repeated_tests_new_approval_old_receipt_cannot_complete_new_cycle(self):
        raw = self.baseline()
        app = self.analyze(self.open_page(), raw)
        first = self.approve(app)
        receipt = self.receipt(first)
        self.uploads['receipt'] = receipt
        app.run()
        app.button(key='save_vm_receipt').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any('This test completed' in s.value for s in app.success))
        self.assertEqual(app.dataframe[0].value.iloc[0]['Observed'], '14')
        self.assertEqual(self.bridge().get(first)['verdict'], 'Verified compliant')
        self.uploads.update(evidence=None, receipt=None)
        app.button(key='new_vm_test').click().run()
        self.assertFalse(app.metric)
        self.assertFalse(app.success)
        self.assertNotIn('vm_cycle_framework_run', app.session_state)
        # Same bytes are deliberately reused here to test isolation even when digest matches.
        self.analyze(app, raw)
        self.assertEqual(app.dataframe[0].value.iloc[0]['Observed'], '0')
        self.assertFalse(any(b.key == 'approve_' + first for b in app.button))
        second = self.approve(app)
        self.assertNotEqual(first, second)
        self.uploads['receipt'] = receipt
        app.run(); app.button(key='save_vm_receipt').click().run()
        self.assertTrue(any('different test request' in e.value for e in app.error))
        self.assertIsNone(self.bridge().get(second)['verdict'])
        self.uploads['receipt'] = self.receipt(second)
        app.run(); app.button(key='save_vm_receipt').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any('This test completed' in s.value for s in app.success))

    def test_current_run_recovers_approval_and_verification_without_cached_result_keys(self):
        app = self.analyze(self.open_page(), self.baseline())
        identifier = self.approve(app)
        run_id = app.session_state['vm_cycle_framework_run']
        del app.session_state['vm_cycle_proposal']
        # Obsolete client keys must not manufacture a verified result.
        app.session_state['vm_cycle_verification'] = app.session_state['vm_cycle_digest']
        app.session_state['vm_cycle_verdict'] = 'Verified compliant'
        app.run()
        self.assertFalse(app.success)
        self.assertEqual(app.session_state['vm_cycle_proposal'], identifier)
        self.assertFalse(any(b.key == 'vm_propose' for b in app.button))
        service = RemediationLifecycle(AssessmentOrchestrator(ImportedEvidenceStore(self.imports)), self.bridge())
        service.accept_receipt(run_id, identifier, self.receipt(identifier))
        del app.session_state['vm_cycle_verification']
        del app.session_state['vm_cycle_verdict']
        app.run()
        self.assertFalse(app.exception)
        self.assertTrue(any('This test completed' in s.value for s in app.success))
        self.assertEqual(app.dataframe[0].value.iloc[0]['Observed'], '14')

    def test_missing_postcheck_is_unresolved_and_labels_pre_action_readings(self):
        app = self.analyze(self.open_page(), self.baseline())
        identifier = self.approve(app)
        payload = json.loads(self.receipt(identifier))
        payload.update(status='verification_unavailable', after_evidence=None)
        self.uploads['receipt'] = json.dumps(payload).encode()
        app.run(); app.button(key='save_vm_receipt').click().run()
        self.assertFalse(app.exception)
        self.assertFalse(app.success)
        self.assertTrue(any('No post-action evidence' in w.value for w in app.warning))
        self.assertEqual(app.dataframe[0].value.iloc[0]['Observed'], '0')
        self.assertFalse(any(b.key == 'vm_propose' for b in app.button))

    def test_interrupted_receipt_import_can_finish_in_ui_without_rerunning_vm(self):
        app = self.analyze(self.open_page(), self.baseline())
        identifier = self.approve(app)
        self.uploads['receipt'] = self.receipt(identifier)
        app.run()
        with patch.object(ImportedEvidenceStore, 'save', side_effect=OSError('fixture interrupted save')):
            app.button(key='save_vm_receipt').click().run()
        self.assertTrue(any('fixture interrupted save' in e.value for e in app.error))
        app.run()
        self.assertFalse(app.success)
        self.assertTrue(any('Upload the same receipt' in w.value for w in app.warning))
        app.button(key='save_vm_receipt').click().run()
        self.assertFalse(app.exception)
        self.assertTrue(any('This test completed' in s.value for s in app.success))

    def test_unknown_context_blocks_proposal_and_new_test_clears_context_inputs(self):
        app = self.analyze(self.open_page(), self.baseline(), compatibility=None)
        self.assertTrue(app.button(key='vm_propose').disabled)
        self.assertFalse(app.button(key='vm_ai').disabled)
        app.selectbox(key='vm_context_status').set_value('compatible').run()
        app.text_input(key='vm_context_operator').set_value('fixture').run()
        app.text_area(key='vm_context_note').set_value('Fixture compatibility checked.').run()
        app.button(key='vm_context_save').click().run()
        self.assertFalse(app.button(key='vm_propose').disabled)
        self.uploads['evidence'] = None
        app.button(key='new_vm_test').click().run()
        self.assertNotIn('vm_context_operator', app.session_state)
        self.analyze(app, self.baseline(), compatibility=None)
        self.assertTrue(app.button(key='vm_propose').disabled)

    def test_incompatible_context_disables_deterministic_proposal(self):
        app = self.analyze(self.open_page(), self.baseline(), compatibility='incompatible')
        self.assertFalse(app.exception)
        self.assertTrue(app.button(key='vm_propose').disabled)
        self.assertFalse(app.button(key='vm_ai').disabled)

if __name__ == '__main__':
    unittest.main()
