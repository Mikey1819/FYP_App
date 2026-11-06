"""Approval bytes, target runner and host executor with a TEST-ONLY file-value family. No VM, no system files."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.integration.runner_fixture import FileValueFamily, sha
from system.contracts import WorkflowBinding
from system.ledger import CoordinationLedger

APP = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 11, 6, 1, 0, 0, tzinfo=timezone.utc)
IDENTITY = ('a' * 32, 'ubuntu-fixture')


class Fixture(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.state, self.work = self.root / 'state', self.root / 'work'
        self.state.mkdir(); self.work.mkdir()
        (self.work / 'alpha').write_bytes(b'old')
        self.family = FileValueFamily(self.work)

    def plan(self, value='new', *, collected=None, **changes):
        from backends.ubuntu.actions import ActionSpec, plan_action
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60)
        params = {'name': 'alpha', 'value': value}
        fields = dict(target_id='ubuntu:fixture', registration_epoch='epoch', hostname='UBUNTU-FIXTURE', machine_id='a' * 32,
                      workflow_session_id='1' * 32, round_id='2' * 32, evidence_sha256='e' * 64, control_id='1.5.1',
                      predicate_id='ubuntu.1.5.1.predicate.v1', parameters=params,
                      before_state_sha256=sha(self.family.read_state(params)), expected_after_sha256=sha(value.encode()),
                      before_state_collected_at=(collected or NOW - timedelta(minutes=1)).isoformat(),
                      recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']}, job_deadline_seconds=60)
        fields.update(changes)
        return plan_action(spec, families={spec.action_id: spec}, **fields)

    def approved(self, **kwargs):
        from backends.ubuntu.approvals import approve
        return approve(self.plan(**kwargs), 'fixture-operator', NOW)

    def runner(self, family=None, *, identity=IDENTITY, clock=None):
        from vm.ubuntu.runner import Runner
        family = family or self.family
        return Runner(self.state, {family.action_id: family}, lambda: identity, clock=clock or (lambda: NOW + timedelta(minutes=1)),
                      require_root_owned=False)

    def writes(self):
        log = self.work / 'writes.log'
        return log.read_text().splitlines() if log.exists() else []


class ApprovalTests(Fixture):
    def test_canonical_bytes_hash_and_strict_reparse(self):
        from vm.ubuntu.remediation_schema import parse_request
        a = self.approved()
        self.assertEqual(a.sha256, sha(a.raw))
        self.assertEqual(parse_request(a.raw), a.request)
        self.assertEqual(a.request['namespace'], 'ubuntu-remediation')
        self.assertEqual(a.request['expires_at'], (NOW + timedelta(hours=1)).isoformat())
        doc = json.loads(a.raw)
        for bad in (json.dumps(doc, indent=1).encode(),                      # same content, other bytes
                    a.raw.replace(b'"approver":', b'"approver":"x","approver":'),  # duplicate key
                    json.dumps(dict(doc, extra=1), sort_keys=True, separators=(',', ':')).encode(),
                    a.raw.replace(b'"job_deadline_seconds":60', b'"job_deadline_seconds":NaN')):
            with self.subTest(), self.assertRaises(ValueError):parse_request(bad)

    def test_stale_before_state_bad_operator_and_unregistered_action_refused(self):
        from backends.ubuntu.approvals import approve
        from backends.ubuntu.actions import plan_action, ActionSpec
        with self.assertRaises(ValueError):approve(self.plan(collected=NOW - timedelta(minutes=6)), 'op', NOW)
        with self.assertRaises(ValueError):approve(self.plan(), '', NOW)
        with self.assertRaises(ValueError):self.plan(control_id='9.9.9')
        with self.assertRaises(ValueError):self.plan(job_deadline_seconds=61)
        spec = ActionSpec('ubuntu.1.5.1.v1', 1, 'a' * 64, ('1.5.1',), lambda p: None, 60)
        with self.assertRaisesRegex(ValueError, 'registered'):plan_action(spec, families={}, parameters={})

    def test_production_registry_holds_exactly_the_implemented_families(self):
        # Superseded "no family yet": the sysctl family (4 controls) is implemented; 26 reserved IDs remain absent.
        from backends.ubuntu.actions import FAMILIES
        from backends.ubuntu.catalogue import EXPECTED_IDS
        from vm.ubuntu.families import build
        from tests.integration.test_ubuntu_sysctl_family import FakeSystem
        implemented = {'ubuntu.1.5.1.v1', 'ubuntu.1.5.3.v1', 'ubuntu.3.3.1.v1', 'ubuntu.3.3.2.v1', 'ubuntu.3.3.8.v1'}
        self.assertEqual(set(FAMILIES), implemented)
        self.assertEqual(set(build(FakeSystem())), implemented)
        self.assertEqual(len({'ubuntu.' + c + '.v1' for c in EXPECTED_IDS} - implemented), 25)
        self.assertNotIn(self.family.action_id, FAMILIES)  # test-only fixture is never registered


class RunnerTests(Fixture):
    def outcome(self, receipt):
        doc = json.loads(receipt)
        return doc['outcome'], doc['code']

    def test_applied_once_receipt_persisted_and_fence_released(self):
        a = self.approved()
        receipt = self.runner().execute(a.raw)
        self.assertEqual(self.outcome(receipt), ('applied', 'expected_after_state'))
        self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
        self.assertEqual(json.loads(receipt)['request_sha256'], a.sha256)
        self.assertFalse((self.state / 'active').exists())
        self.assertEqual(self.outcome(self.runner().execute(a.raw)), ('refused', 'already_claimed'))
        self.assertEqual(self.writes(), ['alpha'])

    def test_change_between_approval_and_dispatch_writes_nothing(self):
        a = self.approved()
        (self.work / 'alpha').write_bytes(b'changed elsewhere')
        self.assertEqual(self.outcome(self.runner().execute(a.raw)), ('refused', 'stale_read_set'))
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.state / 'active').exists())

    def test_change_after_claim_before_write_writes_nothing(self):
        a = self.approved()
        family = FileValueFamily(self.work)
        reads = {'n': 0}
        original = family.read_state
        def racing(params):
            reads['n'] += 1
            if reads['n'] == 2:
                (self.work / 'alpha').write_bytes(b'raced')
            return original(params)
        family.read_state = racing
        self.assertEqual(self.outcome(self.runner(family).execute(a.raw)), ('refused', 'changed_after_claim'))
        self.assertEqual(self.writes(), [])

    def test_identity_expiry_family_hash_and_tampering_refused_without_writes(self):
        a = self.approved()
        late = NOW + timedelta(hours=1, seconds=1)
        other = FileValueFamily(self.work); other.implementation_sha256 = 'b' * 64
        cases = [(self.runner(identity=('b' * 32, 'ubuntu-fixture')), a.raw, 'identity_mismatch'),
                 (self.runner(clock=lambda: late), a.raw, 'expired'),
                 (self.runner(other), a.raw, 'implementation_mismatch'),
                 # Still canonical after the change: valid shape, but inconsistent with the approved after-state.
                 (self.runner(), a.raw.replace(b'"new"', b'"evil"'), 'inconsistent_request'),
                 (self.runner(), a.raw.replace(b'","', b'", "', 1), 'invalid_request')]
        from vm.ubuntu.runner import Runner
        cases.append((Runner(self.state, {}, lambda: IDENTITY, clock=lambda: NOW, require_root_owned=False), a.raw, 'unknown_action'))
        for runner, raw, code in cases:
            with self.subTest(code=code):
                self.assertEqual(self.outcome(runner.execute(raw)), ('refused', code))
        self.assertEqual(self.writes(), [])
        self.assertFalse((self.state / 'active').exists())

    def test_apply_exception_is_unresolved_and_keeps_fence_against_other_requests(self):
        a = self.approved()
        family = FileValueFamily(self.work)
        def broken(params):
            (self.work / 'alpha').write_bytes(b'half')
            raise OSError('disk')
        family.apply = broken
        self.assertEqual(self.outcome(self.runner(family).execute(a.raw)), ('unresolved', 'apply_failed'))
        self.assertTrue((self.state / 'active').exists())
        (self.work / 'beta').write_bytes(b'x')
        b = self.approved(value='other')
        self.assertEqual(self.outcome(self.runner().execute(b.raw)), ('refused', 'target_fenced'))
        # Neither before nor expected state: reconciliation cannot decide, so the fence stays.
        self.assertEqual(self.outcome(self.runner().reconcile(a.request['request_id'])), ('unresolved', 'state_unknown'))
        self.assertTrue((self.state / 'active').exists())

    def test_process_death_after_write_reconciles_to_applied_and_releases_fence(self):
        a = self.approved()
        request = self.root / 'request.json'; request.write_bytes(a.raw)
        result = subprocess.run([sys.executable, '-B', str(APP / 'tests' / 'integration' / 'runner_fixture.py'),
                                 str(self.state), str(self.work), str(request), (NOW + timedelta(minutes=1)).isoformat(), 'crash'], capture_output=True, text=True,
                                cwd=str(APP), timeout=60)
        self.assertEqual(result.returncode, 9)
        self.assertTrue((self.state / 'active').exists())
        self.assertFalse((self.state / 'requests' / a.request['request_id'] / 'receipt.json').exists())
        receipt = self.runner().reconcile(a.request['request_id'])
        self.assertEqual(self.outcome(receipt), ('reconciled_applied', 'expected_after_state'))
        self.assertFalse((self.state / 'active').exists())
        self.assertEqual(self.outcome(self.runner().execute(a.raw)), ('refused', 'already_claimed'))
        self.assertEqual(self.writes(), ['alpha'])

    def test_crash_after_claim_before_write_reconciles_to_not_applied(self):
        a = self.approved()
        family = FileValueFamily(self.work)
        class Crash(BaseException):pass
        def crash(params):raise Crash()
        family.apply = crash
        with self.assertRaises(Crash):self.runner(family).execute(a.raw)
        self.assertTrue((self.state / 'active').exists())
        self.assertEqual(self.outcome(self.runner().reconcile(a.request['request_id'])), ('reconciled_not_applied', 'before_state'))
        self.assertFalse((self.state / 'active').exists())
        self.assertEqual(self.outcome(self.runner().execute(a.raw)), ('refused', 'already_claimed'))  # never replayed

    def test_two_processes_race_and_exactly_one_applies(self):
        a = self.approved()
        request = self.root / 'request.json'; request.write_bytes(a.raw)
        command = [sys.executable, '-B', str(APP / 'tests' / 'integration' / 'runner_fixture.py'),
                   str(self.state), str(self.work), str(request), (NOW + timedelta(minutes=1)).isoformat()]
        children = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(APP))
                    for _ in range(2)]
        outputs = sorted(child.communicate(timeout=60)[0] for child in children)
        self.assertEqual(sum(o.startswith('applied') for o in outputs), 1, outputs)
        self.assertTrue(all(o.startswith(('applied', 'refused already_claimed', 'refused target_fenced')) for o in outputs), outputs)
        self.assertEqual(self.writes(), ['alpha'])


class ExecutorTests(Fixture):
    def setUp(self):
        super().setUp()
        self.ledger = CoordinationLedger(self.root / 'ledger.sqlite3')
        self.binding = self.ledger.add_binding(WorkflowBinding('1' * 32, 'ubuntu', 'ubuntu:fixture', 'epoch', 'b',
                                                               '2026-11-06T00:00:00+00:00'))

    def test_applied_completes_once_and_a_second_operation_cannot_redispatch(self):
        from backends.ubuntu.executor import execute
        a, calls = self.approved(), []
        def dispatch(raw):
            calls.append(raw); return self.runner().execute(raw)
        first = execute(a, ledger=self.ledger, binding=self.binding, operation_id='op-1', dispatch=dispatch, now=NOW)
        self.assertEqual((first.state, first.receipt['outcome']), ('completed', 'applied'))
        second = execute(a, ledger=self.ledger, binding=self.binding, operation_id='op-2', dispatch=dispatch, now=NOW)
        self.assertEqual(second.state, 'completed')
        self.assertEqual(len(calls), 1)
        self.assertIn('verification', self.ledger.operation_state('op-1').detail.lower())

    def test_lost_receipt_is_unresolved_then_reconciled_without_replay(self):
        from backends.ubuntu.executor import execute, reconcile
        a, calls = self.approved(), []
        def lossy(raw):
            calls.append(raw); self.runner().execute(raw); raise TimeoutError('connection lost')
        result = execute(a, ledger=self.ledger, binding=self.binding, operation_id='op-1', dispatch=lossy, now=NOW)
        self.assertEqual(result.state, 'unresolved')
        with self.assertRaises(ValueError):  # target owner fence on the host side too
            self.ledger.claim(self.binding, 'op-other', 'execution', {'x': 1}, mutation=True)
        settled = reconcile(a, ledger=self.ledger, operation_id='op-1', status=lambda rid: self.runner().reconcile(rid))
        self.assertEqual((settled.state, settled.receipt['outcome']), ('completed', 'applied'))
        self.assertEqual(len(calls), 1)
        self.ledger.claim(self.binding, 'op-other', 'execution', {'x': 1}, mutation=True)  # fence released

    def test_expired_or_tampered_approval_is_refused_before_any_dispatch(self):
        from backends.ubuntu.approvals import ApprovedRequest
        from backends.ubuntu.executor import execute
        a, calls = self.approved(), []
        dispatch = lambda raw: calls.append(raw)
        with self.assertRaises(ValueError):
            execute(a, ledger=self.ledger, binding=self.binding, operation_id='op-1', dispatch=dispatch, now=NOW + timedelta(hours=2))
        forged = ApprovedRequest(a.raw.replace(b'"new"', b'"evil"'), a.sha256, a.request)
        with self.assertRaises(ValueError):
            execute(forged, ledger=self.ledger, binding=self.binding, operation_id='op-2', dispatch=dispatch, now=NOW)
        other = WorkflowBinding('x' * 32, 'ubuntu', 'ubuntu:other', 'epoch', 'b', '2026-11-06T00:00:00+00:00')
        with self.assertRaises(ValueError):
            execute(a, ledger=self.ledger, binding=other, operation_id='op-3', dispatch=dispatch, now=NOW)
        self.assertEqual(calls, [])

    def test_receipt_for_another_request_is_not_trusted(self):
        from backends.ubuntu.executor import execute
        a, b = self.approved(), self.approved(value='other')
        result = execute(a, ledger=self.ledger, binding=self.binding, operation_id='op-1',
                         dispatch=lambda raw: self.runner().execute(b.raw), now=NOW)
        self.assertEqual(result.state, 'unresolved')
        self.assertIsNone(result.receipt)
