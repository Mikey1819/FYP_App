"""Live Scanner channel contracts with a fake remoting session. No VM is contacted."""
from pathlib import Path
import json
import tempfile
import unittest

from hardening.domain import EvidenceMode
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.scan_exchange import COLLECTOR
from hardening.vm_bridge import encode
from hardening.winrm_channel import IDENTITY_SCRIPT, ChannelError, LiveScanner, WinRmTarget
from test_evidence_import import MACHINE_UUID
from test_full_controls import full_fixture

IDENTITY = dict(hostname='FIXTURE-SERVER', machine_uuid=MACHINE_UUID, os_caption='Microsoft Windows Server 2022 Standard',
                build_number='20348', part_of_domain=False, domain_role=2, is_admin=True)


class FakeSession:
    """Records every script/parameter set; answers identity and collector calls."""

    def __init__(self, *, identity=IDENTITY, evidence=None, collector_error=None, fail=None):
        self.identity, self.evidence = identity, evidence or encode(full_fixture()).decode()
        self.collector_error, self.fail, self.calls = collector_error, fail, []

    def __call__(self, target):
        self.target = target
        return self

    def run(self, script, parameters=None):
        self.calls.append((script, parameters))
        if self.fail is not None:
            raise self.fail
        if script == IDENTITY_SCRIPT:
            return [json.dumps(self.identity)], False, []
        if self.collector_error:
            return [], True, [self.collector_error]
        return [self.evidence], False, []


def target(**overrides):
    values = dict(hostname='FIXTURE-SERVER', machine_uuid=MACHINE_UUID, username='Administrator', password='secret')
    values.update(overrides)
    return WinRmTarget(**values)


class LiveScannerTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.runtime = AssessmentOrchestrator(ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3'))

    def scanner(self, session):
        return LiveScanner(self.runtime, target(), session_factory=session)

    def test_scan_sends_only_the_registered_collector_with_typed_parameters(self):
        session = FakeSession()
        result = self.scanner(session).request('FIXTURE-SERVER', MACHINE_UUID)
        self.assertEqual(result['state'], 'assessment_ready')
        self.assertEqual(result['channel'], 'winrm')
        script, parameters = session.calls[-1]
        self.assertEqual(script, COLLECTOR.read_text(encoding='utf-8-sig'))
        self.assertEqual(parameters, {'ExpectedComputerName': 'FIXTURE-SERVER', 'EmitJson': True})
        run = self.runtime.get(result['framework_run_id'])
        self.assertEqual(run.evidence_sha256, result['evidence_sha256'])
        self.assertTrue(run.tasks, 'Scan must produce an assessed framework run')

    def test_channel_evidence_is_stored_as_live_and_a_file_as_imported(self):
        result = self.scanner(FakeSession()).request('FIXTURE-SERVER', MACHINE_UUID)
        run = self.runtime.get(result['framework_run_id'])
        record = self.runtime.imports.get(run.evidence_sha256)
        self.assertEqual({r.evidence.mode for r in record.assessment.results}, {EvidenceMode.LIVE})
        self.assertEqual(run.tasks[0]['output']['collection'], 'Collected live over WinRM by the Scanner Agent')
        precheck = self.scanner(FakeSession()).observe()
        self.assertEqual({r.evidence.mode for r in precheck.results}, {EvidenceMode.LIVE})
        upload = full_fixture()
        upload['target']['hostname'] = 'fixture-server'  # Other bytes: identical bytes are the same evidence.
        uploaded = self.runtime.start(encode(upload), expected_hostname='FIXTURE-SERVER',
                                      expected_machine_uuid=MACHINE_UUID)
        self.assertEqual(self.runtime.imports.get(uploaded.evidence_sha256).assessment.results[0].evidence.mode,
                         EvidenceMode.IMPORTED)
        with self.assertRaisesRegex(ValueError, 'Imported or Live'):
            self.runtime.imports.save(encode(full_fixture()), expected_hostname='FIXTURE-SERVER',
                                      expected_machine_uuid=MACHINE_UUID, mode=EvidenceMode.SYNTHETIC)

    def test_each_scan_is_a_separate_run(self):
        scanner = self.scanner(FakeSession())
        first = scanner.request('FIXTURE-SERVER', MACHINE_UUID)
        second = scanner.request('FIXTURE-SERVER', MACHINE_UUID)
        self.assertNotEqual(first['framework_run_id'], second['framework_run_id'])

    def test_wrong_vm_on_the_port_is_refused_before_collection(self):
        session = FakeSession(identity={**IDENTITY, 'machine_uuid': '11111111-2222-3333-4444-555555555555'})
        with self.assertRaises(ChannelError) as caught:
            self.scanner(session).request('FIXTURE-SERVER', MACHINE_UUID)
        self.assertEqual(caught.exception.state, 'wrong_target')
        self.assertEqual(len(session.calls), 1, 'Collector must not run on an unverified target')

    def test_request_for_other_registration_is_refused_without_contacting_vm(self):
        session = FakeSession()
        with self.assertRaises(ChannelError) as caught:
            self.scanner(session).request('OTHER', MACHINE_UUID)
        self.assertEqual(caught.exception.state, 'wrong_target')
        self.assertEqual(session.calls, [])

    def test_filtered_admin_token_is_reported(self):
        session = FakeSession(identity={**IDENTITY, 'is_admin': False})
        status = self.scanner(session).worker_status('FIXTURE-SERVER', MACHINE_UUID)
        self.assertEqual(status['state'], 'not_admin')

    def test_collector_failure_creates_no_assessment(self):
        session = FakeSession(collector_error='Unsupported target: only a standalone Windows Server 2022 x64 lab is permitted.')
        with self.assertRaises(ChannelError) as caught:
            self.scanner(session).request('FIXTURE-SERVER', MACHINE_UUID)
        self.assertEqual(caught.exception.state, 'collection_failed')
        self.assertIn('Unsupported target', caught.exception.detail)

    def test_invalid_evidence_is_rejected_by_the_strict_importer(self):
        doc = full_fixture(); doc['target']['machine_uuid'] = '11111111-2222-3333-4444-555555555555'
        with self.assertRaises(ValueError):
            self.scanner(FakeSession(evidence=encode(doc).decode())).request('FIXTURE-SERVER', MACHINE_UUID)

    def test_network_and_auth_failures_are_classified_without_leaking_password(self):
        class AuthenticationError(Exception):
            pass
        for error, state in ((ConnectionError('Connection refused'), 'unreachable'),
                             (AuthenticationError('bad'), 'auth_failed'), (RuntimeError('x'), 'channel_error')):
            status = self.scanner(FakeSession(fail=error)).worker_status('FIXTURE-SERVER', MACHINE_UUID)
            self.assertEqual(status['state'], state)
            self.assertNotIn('secret', json.dumps(status))
        self.assertNotIn('secret', repr(target()))

    def test_target_requires_credentials(self):
        with self.assertRaises(ValueError):
            target(password='')


if __name__ == '__main__':
    unittest.main()
