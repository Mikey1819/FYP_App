"""Target-side envelope assembly through host validation and storage. Synthetic fixture only, no VM."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from tests.integration.test_collection import FakeIO

START = datetime(2026, 11, 6, 0, 0, 0, tzinfo=timezone.utc)


def request(**changes):
    value = dict(target_id='ubuntu:fixture', registration_epoch='epoch', hostname='UBUNTU-FIXTURE',
                 machine_id='a'*32, request_id='b'*32, benchmark_sha256='c'*64, source_lock_sha256='d'*64,
                 evidence_mode='Synthetic fixture')
    value.update(changes)
    return value


def clock():
    times = iter((START, START + timedelta(seconds=3)))
    return lambda: next(times)


def verified_io():
    io = FakeIO()
    io._identity = ('a'*32, 'ubuntu-fixture')
    return io


class ProvenanceTests(unittest.TestCase):
    def expected(self, req):
        from backends.ubuntu.envelope import ExpectedEvidence
        from vm.ubuntu.provenance import collector_digest
        return ExpectedEvidence(req['target_id'], req['registration_epoch'], req['hostname'], req['machine_id'],
                                req['request_id'], req['benchmark_sha256'], req['source_lock_sha256'],
                                collector_digest(), req['evidence_mode'])

    def test_collected_envelope_is_accepted_by_host_parser_and_store(self):
        from vm.ubuntu.provenance import run_collection
        from backends.ubuntu.envelope import parse_bundle
        from backends.ubuntu.storage import UbuntuStore
        from system.contracts import WorkflowBinding
        req = request()
        raw = run_collection(verified_io(), req, clock=clock(), registered_firewall_manager='ufw')
        self.assertNotIn(b'SECRET-SENTINEL', raw)
        now = START + timedelta(seconds=4)
        bundle = parse_bundle(raw, self.expected(req), now=now)
        self.assertEqual(len(bundle.assessments), 30)
        doc = json.loads(raw)
        self.assertEqual(doc['probes']['1.5.1']['exit_state'], 'ok')
        # The Manual updates control now has read-only update facts; this fixture target lacks some of them,
        # so the probe is explicitly incomplete and the control is never a pass (manual review remains).
        self.assertIn(doc['probes']['1.2.2.1']['exit_state'], ('partial', 'missing', 'error'))
        self.assertNotEqual(next(a for a in bundle.assessments if a.control_id == '1.2.2.1').status.value, 'Compliant')
        with tempfile.TemporaryDirectory() as folder:
            store = UbuntuStore(Path(folder)/'ubuntu.sqlite3')
            binding = WorkflowBinding('workflow', 'ubuntu', 'ubuntu:fixture', 'epoch', 'backend', '2026-11-06T00:00:00+00:00')
            run = store.start_run(raw, self.expected(req), binding, now=now)
            self.assertEqual(store.get_evidence(run.digest, 'ubuntu:fixture', 'epoch').raw, raw)

    def test_collector_digest_binds_helper_bytes(self):
        from vm.ubuntu.provenance import collector_digest, HELPER_FILES
        with tempfile.TemporaryDirectory() as folder:
            source = Path(__file__).resolve().parents[2]/'vm'/'ubuntu'
            for name in HELPER_FILES:
                (Path(folder)/name).write_bytes((source/name).read_bytes())
            self.assertEqual(collector_digest(folder), collector_digest())
            (Path(folder)/'probes.py').write_bytes((source/'probes.py').read_bytes() + b'\n')
            self.assertNotEqual(collector_digest(folder), collector_digest())
            (Path(folder)/'probes.py').unlink()
            with self.assertRaises(ValueError):collector_digest(folder)

    def test_malformed_request_and_unverified_or_other_identity_are_refused(self):
        from vm.ubuntu.provenance import run_collection
        for bad in (request(extra='x'), request(machine_id='A'*32), request(request_id='../x'),
                    request(benchmark_sha256='c'*63), request(evidence_mode='Compliant'), request(hostname=1)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                run_collection(verified_io(), bad, clock=clock())
        unverified = FakeIO(); unverified._verified = False
        with self.assertRaises(ValueError):run_collection(unverified, request(), clock=clock())
        with self.assertRaises(ValueError):run_collection(verified_io(), request(machine_id='e'*32), clock=clock())
        with self.assertRaises(ValueError):run_collection(verified_io(), request(hostname='other'), clock=clock())

    def test_envelope_refuses_incomplete_or_invalid_observations_and_bad_times(self):
        from vm.ubuntu.provenance import build_envelope, collector_digest
        from vm.ubuntu.collection import collect_observations
        facts = collect_observations(verified_io(), registered_firewall_manager='ufw')
        kwargs = dict(started_at=START, completed_at=START + timedelta(seconds=1), collector_sha256=collector_digest())
        missing = dict(facts); missing.pop('1.5.1')
        empty = dict(facts); empty['1.5.1'] = {}
        forged = json.loads(json.dumps(facts)); forged['1.5.1']['status'] = {'state': 'ok', 'value': 'Compliant'}
        for bad in (missing, empty, forged):
            with self.subTest(), self.assertRaises(ValueError):build_envelope(request(), bad, **kwargs)
        with self.assertRaises(ValueError):
            build_envelope(request(), facts, started_at=START, completed_at=START - timedelta(seconds=1),
                           collector_sha256=collector_digest())
        with self.assertRaises(ValueError):
            build_envelope(request(), facts, started_at=START.replace(tzinfo=None), completed_at=START,
                           collector_sha256=collector_digest())

    def test_mixed_probe_states_are_partial_not_ok(self):
        from vm.ubuntu.provenance import build_envelope, collector_digest
        from vm.ubuntu.collection import collect_observations
        io = verified_io(); original = io.command
        io.command = lambda key: (_ for _ in ()).throw(OSError('fixture')) if key == 'sysctl.kernel.randomize_va_space' else original(key)
        facts = collect_observations(io, registered_firewall_manager='ufw')
        doc = json.loads(build_envelope(request(), facts, started_at=START, completed_at=START + timedelta(seconds=1),
                                        collector_sha256=collector_digest()))
        self.assertEqual(doc['probes']['1.5.1']['exit_state'], 'partial')
