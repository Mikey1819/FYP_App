"""Host -> fixed SSH helper command -> target CLI -> envelope -> store, all in-process with fakes.

No VM, network or sudo is used. Evidence produced here exists only in temporary test stores.
"""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from tests.integration.test_collection import FakeIO
from vm.ubuntu.spec import SCAP_RULES
from system.connection import VerifiedSession
from system.identity import VerifiedIdentity
from system.ledger import CoordinationLedger
from tests.integration.pairing_fixture import paired_connect

APP = Path(__file__).resolve().parents[2]
TARGET = ('a'*32, 'UBUNTU-FIXTURE')


def fake_io_factory(scap='pass'):
    def factory():
        target = FakeIO()
        target._verified = False
        target.scap_results = lambda request_id, engine: {r: scap for rules in SCAP_RULES.values() for r in rules}
        return target
    return factory


def fake_preflight(target, request):
    if (request['machine_id'], request['hostname'].casefold()) != (TARGET[0], TARGET[1].casefold()):
        raise ValueError('identity mismatch')
    target._identity = (request['machine_id'], request['hostname'].casefold())
    target._verified = True


def run_cli(stdin_bytes, **kwargs):
    from vm.ubuntu.cli import main
    out, err = io.BytesIO(), io.BytesIO()
    code = main(stdin=io.BytesIO(stdin_bytes), stdout=out, stderr=err,
                io_factory=kwargs.pop('io_factory', fake_io_factory()), preflight=kwargs.pop('preflight', fake_preflight))
    return code, out.getvalue(), err.getvalue()


def payload(**request_changes):
    request = dict(target_id='ubuntu:fixture', registration_epoch='epoch', hostname=TARGET[1], machine_id=TARGET[0],
                   request_id='b'*32, benchmark_sha256='c'*64, source_lock_sha256='d'*64, evidence_mode='Live (SSH)')
    request.update(request_changes)
    return dict(request=request, scap_engine_version='1.3.7', registered_firewall_manager=None)


class TargetCliTests(unittest.TestCase):
    def test_valid_request_writes_only_envelope_bytes(self):
        code, out, err = run_cli(json.dumps(payload()).encode())
        self.assertEqual((code, err), (0, b''))
        doc = json.loads(out)
        self.assertEqual(doc['evidence_mode'], 'Live (SSH)')
        self.assertTrue(all('scap_rules' in doc['observations'][cid] for cid in SCAP_RULES))
        self.assertNotIn(b'SECRET-SENTINEL', out)

    def test_malformed_requests_and_failures_write_no_evidence_and_echo_nothing(self):
        sentinel = 'SECRET-SENTINEL'
        good = payload()
        bad_inputs = [b'', b'not json', b'{"request":1,"request":2}', b' ' * (64*1024 + 1),
                      json.dumps(dict(good, extra=sentinel)).encode(),
                      json.dumps(dict(good, scap_engine_version=sentinel)).encode(),
                      json.dumps(dict(good, registered_firewall_manager=sentinel)).encode(),
                      json.dumps(payload(hostname='other-host')).encode()]
        for raw in bad_inputs:
            with self.subTest(raw=raw[:30]):
                code, out, err = run_cli(raw)
                self.assertNotEqual(code, 0)
                self.assertEqual(out, b'')
                self.assertNotIn(sentinel.encode(), err)
                self.assertLessEqual(len(err), 80)
        def broken():
            raise OSError('/etc/' + sentinel)
        code, out, err = run_cli(json.dumps(good).encode(), io_factory=broken)
        self.assertNotEqual(code, 0); self.assertEqual(out, b''); self.assertNotIn(sentinel.encode(), err)

    def test_launcher_is_fixed_isolated_and_digest_pinned(self):
        from vm.ubuntu.provenance import HELPER_FILES
        launcher = (APP/'vm'/'ubuntu'/'collect').read_bytes()
        self.assertTrue(launcher.startswith(b'#!/usr/bin/python3 -IB\n'))
        self.assertIn(b"sys.path.insert(0, '/usr/local/libexec/fyp-hardening')", launcher)
        self.assertIn(b'from fyp_ubuntu.cli import main', launcher)
        self.assertNotIn(b'\r', launcher)
        for name in ('collect', 'cli.py'):
            self.assertIn(name, HELPER_FILES)


class FakeChannel:
    """Paramiko-like session channel recording exactly what the host sends."""
    def __init__(self, stdout=b'', status=0, stderr=b''):
        self.stdout, self.status, self.stderr = stdout, status, stderr
        self.command, self.sent, self.write_closed, self.closed = None, b'', False, False
    def settimeout(self, value):pass
    def exec_command(self, command):self.command = command
    def sendall(self, data):self.sent += data
    def shutdown_write(self):self.write_closed = True
    def recv_ready(self):return bool(self.stdout)
    def recv(self, n):chunk, self.stdout = self.stdout[:n], self.stdout[n:];return chunk
    def recv_stderr_ready(self):return bool(self.stderr)
    def recv_stderr(self, n):chunk, self.stderr = self.stderr[:n], self.stderr[n:];return chunk
    def exit_status_ready(self):return True
    def recv_exit_status(self):return self.status
    def close(self):self.closed = True


class FakeTransport:
    def __init__(self, channel):self.channel = channel
    def open_session(self, timeout):return self.channel


class ChannelInvocationTests(unittest.TestCase):
    def channel(self, fake):
        from backends.ubuntu.ssh_channel import SshChannel
        return SshChannel(FakeTransport(fake), 'SHA256:fixture')

    def test_fixed_command_request_on_stdin_and_bounded_output(self):
        from backends.ubuntu.ssh_channel import HELPER_COMMAND
        fake = FakeChannel(stdout=b'{"ok":1}')
        self.assertEqual(self.channel(fake).invoke_helper(b'{"request":{}}'), b'{"ok":1}')
        self.assertEqual(fake.command, HELPER_COMMAND)
        self.assertEqual(HELPER_COMMAND, 'sudo -n /usr/local/libexec/fyp-hardening/collect')
        self.assertEqual(fake.sent, b'{"request":{}}')
        self.assertTrue(fake.write_closed and fake.closed)
        with self.assertRaises(ValueError):self.channel(FakeChannel(stdout=b'x' * 100)).invoke_helper(b'{}', max_bytes=10)

    def test_failure_exit_is_generic_and_never_echoes_remote_stderr(self):
        with self.assertRaises(ValueError) as caught:
            self.channel(FakeChannel(status=1, stderr=b'sudo: a password is required SECRET-SENTINEL')).invoke_helper(b'{}')
        self.assertNotIn('SECRET-SENTINEL', str(caught.exception))
        with self.assertRaises(ValueError):self.channel(FakeChannel()).invoke_helper('not bytes')


class CliChannel:
    """Stands in for SshChannel by running the real target CLI in-process against FakeIO."""
    def __init__(self, scap='pass', identity=TARGET):
        self.calls, self.scap, self.identity = 0, scap, identity
    def invoke_helper(self, stdin_bytes, **kwargs):
        self.calls += 1
        def preflight(target, request):
            if (request['machine_id'], request['hostname']) != self.identity:
                raise ValueError('identity mismatch')
            fake_preflight(target, request)
        code, out, _ = run_cli(stdin_bytes, io_factory=fake_io_factory(self.scap), preflight=preflight)
        if code != 0:
            raise ValueError('Ubuntu collection helper refused the request')
        return out


class _NoModel:
    def chat(self, messages, tools, *, timeout):
        raise AssertionError('Tests must never reach a real or fake model here')


# Hermetic: never probe or call the developer's local Ollama from these tests.
STOPPED_MODEL = dict(model_probe=lambda: False, model_client_factory=lambda role: _NoModel())


def open_gate():
    # Test-only: the real gate is closed (activation false, OpenSCAP version unrecorded).
    gate = mock.patch('backends.ubuntu.adapter.assessment_gate', return_value=())
    engine = mock.patch('backends.ubuntu.adapter.accepted_engine_version', return_value='1.3.7')
    class Both:
        def __enter__(self):gate.start();engine.start()
        def __exit__(self, *exc):engine.stop();gate.stop()
    return Both()


class BackendLiveAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(); self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)/'ubuntu.sqlite3'
        self.ledger = CoordinationLedger(Path(self.folder.name)/'ledger.sqlite3')

    def backend(self, channel):
        from backends.ubuntu.adapter import UbuntuBackend
        session = VerifiedSession('c', VerifiedIdentity('ubuntu', TARGET[1], TARGET[0], '22.04', 'ssh'),
                                  'ubuntu:fixture', 'epoch', 'user', 'vm', 22, channel)
        return UbuntuBackend(self.path, session=session, ledger=self.ledger, **STOPPED_MODEL)

    def test_closed_gate_lists_reasons_and_scans_nothing(self):
        from backends.ubuntu.adapter import assessment_gate
        self.assertEqual(assessment_gate(), ())  # real sources activated from recorded evidence (2026-11-06)
        with mock.patch('backends.ubuntu.adapter.assessment_gate', return_value=('Ubuntu assessment is not enabled (test-closed gate: catalogue activation false).',)):
            self._closed_gate_checks()

    def _closed_gate_checks(self):
        backend = self.backend(CliChannel())
        capabilities = backend.capabilities('c')
        self.assertFalse(capabilities.can_assess)
        self.assertTrue(any('activation' in r.lower() or 'review' in r.lower() for r in capabilities.blocked_reasons))
        with self.assertRaises(ValueError):backend.start_round('c', None, None, 'deterministic', 'op-1')
        self.assertEqual(backend.session.channel.calls, 0)
        self.assertFalse(self.path.exists())

    def test_open_gate_runs_one_collection_stores_and_replays_without_second_scan(self):
        channel = CliChannel()
        with open_gate():
            backend = self.backend(channel)
            self.assertTrue(backend.capabilities('c').can_assess)
            handle = backend.start_round('c', None, None, 'deterministic', 'op-1')
            self.assertEqual(handle.state, 'completed')
            again = backend.start_round('c', handle.binding.workflow_session_id, None, 'deterministic', 'op-1')
            self.assertEqual(again.round_reference, handle.round_reference)
            self.assertEqual(channel.calls, 1)
            snap = backend.snapshot('c', handle.binding.workflow_session_id)
            self.assertEqual(len(snap.controls), 30)
            self.assertEqual(snap.current_round_reference, handle.round_reference)
            self.assertEqual(len(backend.history('ubuntu:fixture')), 1)
        self.assertEqual(self.ledger.operation_state('op-1').state, 'completed')

    def test_agentic_mode_is_refused_while_the_local_model_is_unavailable(self):
        # Superseded the 'refused until Ubuntu agents exist' check: agents now exist, so the model is the gate.
        with open_gate():
            backend = self.backend(CliChannel())
            self.assertFalse(backend.capabilities('c').can_use_model)
            with self.assertRaises(ValueError):backend.start_round('c', None, 'goal', 'agentic', 'op-a')
        self.assertEqual(backend.session.channel.calls, 0)
        self.assertEqual(self.ledger.operation_state('op-a').code, 'unknown_operation')  # nothing was claimed

    def test_failed_or_mismatched_collection_stores_nothing_and_does_not_block_retry(self):
        with open_gate():
            wrong = self.backend(CliChannel(identity=('e'*32, 'OTHER')))
            with self.assertRaises(ValueError):wrong.start_round('c', None, None, 'deterministic', 'op-1')
            self.assertEqual(self.ledger.operation_state('op-1').state, 'refused')
            retry = self.backend(CliChannel())
            handle = retry.start_round('c', None, None, 'deterministic', 'op-2')
            self.assertEqual(handle.state, 'completed')
            self.assertEqual(len(retry.history('ubuntu:fixture')), 1)


class PageLiveAssessmentTests(unittest.TestCase):
    def test_same_page_button_runs_gated_read_only_assessment(self):
        from streamlit.testing.v1 import AppTest
        from tests.integration.test_system_acceptance import FixtureSsh, existing_page
        from system.bootstrap import SERVICE_KEY, WORKFLOW_KEY
        from system.connection import ConnectionService
        from backends.ubuntu.adapter import UbuntuBackend

        class HelperSsh(FixtureSsh, CliChannel):
            def __init__(self):CliChannel.__init__(self)

        channel = HelperSsh()
        with tempfile.TemporaryDirectory() as folder, open_gate():
            path = Path(folder); ledger = CoordinationLedger(path/'integration.sqlite3')
            service = ConnectionService(ledger, ssh_factory=lambda *a: channel,
                backend_factory=lambda session: UbuntuBackend(path/'ubuntu'/'imports.sqlite3', session=session, ledger=ledger,
                                                              **STOPPED_MODEL))
            app = AppTest.from_function(existing_page, default_timeout=60)
            app.session_state['fixture_database'] = str(path/'windows'/'imports.sqlite3')
            app.session_state[SERVICE_KEY] = service
            app.run()
            self.assertEqual(paired_connect(app, platform='ubuntu', hostname=TARGET[1], identity=TARGET[0]).state, 'connected')
            self.assertEqual(channel.calls, 0, 'Connecting must not scan')
            # The page has no Assess without AI button (removed by the administrator); the backend's read-only
            # deterministic scan still works, and the page shows its result.
            self.assertEqual([b for b in app.button if b.key == 'agentic_assess_without_ai'], [])
            from system.bootstrap import CONNECTION_KEY
            backend = service.backend_for(app.session_state[CONNECTION_KEY])
            handle = backend.start_round(app.session_state[CONNECTION_KEY], None, None, 'deterministic', 'op-scan')
            app.session_state[WORKFLOW_KEY] = handle.binding.workflow_session_id
            app.run()
            self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
            self.assertFalse(list(app.error), [e.value for e in app.error])
            self.assertEqual(channel.calls, 1)
            self.assertIn(WORKFLOW_KEY, app.session_state)
            self.assertTrue(any('30 selected controls' in c.value for c in app.caption))
            for database in path.rglob('*.sqlite3'):
                self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes())
