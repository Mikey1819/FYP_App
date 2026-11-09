"""Live Scanner channel contracts with a fake remoting session. No VM is contacted."""
from pathlib import Path
import json
import tempfile
import unittest

from hardening.domain import EvidenceMode
from hardening.evidence_import import encode
from hardening.framework import AssessmentRuns
from hardening.import_storage import ImportedEvidenceStore
from hardening.winrm_channel import COLLECTOR, IDENTITY_SCRIPT, ChannelError, LiveScanner, WinRmTarget
from evidence_fixture import MACHINE_UUID, evidence_fixture

IDENTITY = dict(hostname='FIXTURE-SERVER', machine_uuid=MACHINE_UUID, os_caption='Microsoft Windows Server 2022 Standard',
                build_number='20348', part_of_domain=False, domain_role=2, is_admin=True)


class FakeSession:
    """Records every script/parameter set; answers identity and collector calls."""

    def __init__(self, *, identity=IDENTITY, evidence=None, collector_error=None, fail=None):
        self.identity, self.evidence = identity, evidence or encode(evidence_fixture()).decode()
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
    values = dict(hostname='FIXTURE-SERVER', machine_uuid=MACHINE_UUID, username='Administrator', password='secret',
                  host='127.0.0.1', port=55985)
    values.update(overrides)
    return WinRmTarget(**values)


class LiveScannerTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.runtime = AssessmentRuns(ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3'))

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

    def test_channel_evidence_is_stored_as_live_and_a_file_as_imported(self):
        result = self.scanner(FakeSession()).request('FIXTURE-SERVER', MACHINE_UUID)
        run = self.runtime.get(result['framework_run_id'])
        record = self.runtime.imports.get(run.evidence_sha256)
        self.assertEqual({r.evidence.mode for r in record.assessment.results}, {EvidenceMode.LIVE})
        precheck = self.scanner(FakeSession()).observe()
        self.assertEqual({r.evidence.mode for r in precheck.results}, {EvidenceMode.LIVE})
        upload = evidence_fixture()
        upload['target']['hostname'] = 'fixture-server'  # Other bytes: identical bytes are the same evidence.
        uploaded = self.runtime.start(encode(upload), expected_hostname='FIXTURE-SERVER',
                                      expected_machine_uuid=MACHINE_UUID)
        self.assertEqual(self.runtime.imports.get(uploaded.evidence_sha256).assessment.results[0].evidence.mode,
                         EvidenceMode.IMPORTED)
        with self.assertRaisesRegex(ValueError, 'Imported or Live'):
            self.runtime.imports.save(encode(evidence_fixture()), expected_hostname='FIXTURE-SERVER',
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
        doc = evidence_fixture(); doc['target']['machine_uuid'] = '11111111-2222-3333-4444-555555555555'
        # A scan the checks refuse is a failed collection (ChannelError), so the Scanner Agent can report it.
        with self.assertRaisesRegex(ChannelError, 'evidence_refused: The scan failed validation: Evidence does not match'):
            self.scanner(FakeSession(evidence=encode(doc).decode())).request('FIXTURE-SERVER', MACHINE_UUID)

    def test_the_server_clock_is_read_and_set_after_the_identity_check(self):
        from datetime import timedelta
        from hardening.winrm_channel import CLOCK_SCRIPT, SET_CLOCK_SCRIPT
        from test_agentic import FakeVm
        vm = FakeVm()
        vm.clock_ahead = timedelta(minutes=7)
        scanner = LiveScanner(None, target(), session_factory=vm)
        reading = scanner.clock_offset()
        self.assertAlmostEqual(reading['offset'], 420, delta=2)
        self.assertEqual(vm.scripts, [IDENTITY_SCRIPT, CLOCK_SCRIPT])
        result = scanner.set_clock()
        self.assertEqual(vm.scripts[2:], [IDENTITY_SCRIPT, SET_CLOCK_SCRIPT])
        self.assertAlmostEqual((result['before'] - result['after']).total_seconds(), 420, delta=2)
        self.assertAlmostEqual(scanner.clock_offset()['offset'], 0, delta=2)

    def test_an_odd_clock_answer_is_refused(self):
        class OddClock:
            def __init__(self, _):
                pass

            def run(self, script, parameters=None):
                return ([json.dumps(IDENTITY)] if script == IDENTITY_SCRIPT else ['tomorrow']), False, []
        with self.assertRaisesRegex(ChannelError, 'unexpected form'):
            LiveScanner(None, target(), session_factory=OddClock).clock_offset()

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


class CountingSession(FakeSession):
    """FakeSession that also counts connections: every factory call is one, open() and close() mark a shared one."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.connections = self.opened = self.closed = 0

    def __call__(self, target):
        self.connections += 1
        return super().__call__(target)

    def open(self):
        self.opened += 1

    def close(self):
        self.closed += 1


class BatchTests(unittest.TestCase):
    """A batch of fixes shares one connection; every call keeps its own checks; a failure drops the connection."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.runtime = AssessmentRuns(ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3'))

    def test_without_a_batch_every_call_opens_its_own_connection(self):
        session = CountingSession()
        scanner = LiveScanner(self.runtime, target(), session_factory=session)
        scanner.identity(); scanner.identity()
        self.assertEqual((session.connections, session.opened), (2, 0))

    def test_a_batch_shares_one_connection_and_closes_it_once_even_when_nested(self):
        session = CountingSession()
        scanner = LiveScanner(self.runtime, target(), session_factory=session)
        with scanner.batch():
            scanner.identity()
            with scanner.batch():
                scanner.observe()  # Its own identity check and collection, on the same connection.
            scanner.identity()
            self.assertEqual(session.closed, 0)
        self.assertEqual((session.connections, session.opened, session.closed), (1, 1, 1))
        self.assertEqual([s for s, _ in session.calls].count(IDENTITY_SCRIPT), 3)  # No check is skipped.
        scanner.identity()
        self.assertEqual(session.connections, 2)  # After the batch, back to one connection per call.

    def test_a_scan_checks_identity_and_collects_over_one_connection(self):
        session = CountingSession()
        LiveScanner(self.runtime, target(), session_factory=session).request('FIXTURE-SERVER', MACHINE_UUID)
        self.assertEqual((session.connections, len(session.calls)), (1, 2))

    def test_a_failed_call_drops_the_connection_and_the_next_call_opens_a_fresh_one(self):
        broken = CountingSession(fail=ConnectionError('reset'))
        healthy = CountingSession()
        sessions = iter([broken, healthy])
        scanner = LiveScanner(self.runtime, target(), session_factory=lambda t: next(sessions)(t))
        with scanner.batch():
            with self.assertRaises(ChannelError) as raised:
                scanner.identity()
            self.assertEqual(raised.exception.state, 'unreachable')
            self.assertEqual(broken.closed, 1)
            self.assertEqual(scanner.identity()['hostname'], 'FIXTURE-SERVER')
        self.assertEqual((healthy.opened, healthy.closed), (1, 1))


class FakePsrp:
    """Stands in for pypsrp's WSMan, RunspacePool and PowerShell, counting connections and scopes."""

    def __init__(self):
        self.connections, self.pools, self.exits, self.scopes = 0, 0, [], []
        fake = self

        class WSMan:
            def __init__(self, *args, **kwargs):
                fake.connections += 1

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                fake.exits.append('wsman')

        class RunspacePool:
            def __init__(self, wsman):
                fake.pools += 1

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                fake.exits.append('pool')

        class PowerShell:
            had_errors = False

            def __init__(self, pool):
                self.streams = type('Streams', (), {'error': []})()

            def add_script(self, script, use_local_scope=None):
                fake.scopes.append(use_local_scope)

            def add_parameter(self, name, value):
                pass

            def invoke(self):
                return ['done']

        self.modules = {'pypsrp.wsman': type('M', (), {'WSMan': WSMan}),
                        'pypsrp.powershell': type('M', (), {'RunspacePool': RunspacePool, 'PowerShell': PowerShell})}


class PsrpSessionTests(unittest.TestCase):
    def fake(self):
        from unittest.mock import patch
        fake = FakePsrp()
        patcher = patch.dict('sys.modules', fake.modules)
        patcher.start(); self.addCleanup(patcher.stop)
        return fake

    def test_each_call_opens_and_closes_its_own_runspace_without_open(self):
        from hardening.winrm_channel import PsrpSession
        fake = self.fake()
        session = PsrpSession(target())
        self.assertEqual(session.run('1'), (['done'], False, []))
        session.run('2')
        self.assertEqual((fake.connections, fake.pools, fake.exits.count('pool')), (2, 2, 2))

    def test_an_open_session_shares_one_runspace_and_runs_each_script_in_its_own_scope(self):
        from hardening.winrm_channel import PsrpSession
        fake = self.fake()
        session = PsrpSession(target())
        session.open()
        for script in ('1', '2', '3'):
            session.run(script)
        self.assertEqual((fake.connections, fake.pools, fake.exits), (1, 1, []))
        self.assertEqual(fake.scopes, [True, True, True])  # No variable or function carries over between scripts.
        session.close(); session.close()  # Closing twice is harmless.
        self.assertEqual(fake.exits, ['pool', 'wsman'])
        session.run('4')  # Closed: back to one runspace per call.
        self.assertEqual(fake.connections, 2)


if __name__ == '__main__':
    unittest.main()
