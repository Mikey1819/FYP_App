"""Proposal/decision/receipt persistence and target preview, with the TEST-ONLY file-value family."""
from contextlib import closing
from datetime import timedelta
import io
import json
import sqlite3
import unittest
from tests.integration.runner_fixture import FileValueFamily, sha
from tests.integration.test_ubuntu_runner import Fixture, NOW, IDENTITY
from system.contracts import WorkflowBinding


class StoreFixture(Fixture):
    def setUp(self):
        super().setUp()
        from backends.ubuntu.storage import UbuntuStore
        from tests.integration.test_ubuntu_evidence import envelope
        from backends.ubuntu.envelope import ExpectedEvidence
        from datetime import datetime, timezone
        self.store = UbuntuStore(self.root / 'ubuntu.sqlite3')
        self.binding = WorkflowBinding('1' * 32, 'ubuntu', 'ubuntu:fixture', 'epoch', 'b', '2026-11-06T00:00:00+00:00')
        doc = envelope()
        expected = ExpectedEvidence(*[doc[f] for f in ExpectedEvidence.__dataclass_fields__])
        run = self.store.start_run(json.dumps(doc).encode(), expected, self.binding,
                                   now=datetime(2026, 11, 6, 0, 0, 2, tzinfo=timezone.utc))
        self.round_id = self.store.record_round(self.binding, run.run_id, mode='deterministic')

    def stored_plan(self, **changes):
        plan = self.plan(round_id=self.round_id, **changes)
        self.store.add_proposal(self.binding, plan, title='Fixture value', preview={'name': 'alpha', 'proposed': 'new'})
        return plan


class ProposalStoreTests(StoreFixture):
    def test_proposal_approval_receipt_lifecycle_is_append_only_and_exact(self):
        from backends.ubuntu.approvals import approve
        plan = self.stored_plan()
        self.assertEqual(self.store.add_proposal(self.binding, plan, title='Fixture value',
                                                 preview={'name': 'alpha', 'proposed': 'new'}), plan.proposal_id)
        approved = approve(plan, 'fixture-operator', NOW)
        self.store.record_decision(self.binding, plan.proposal_id, approved=approved)
        self.assertTrue(self.store.record_decision(self.binding, plan.proposal_id, approved=approved))  # identical replay
        with self.assertRaises(ValueError):self.store.record_decision(self.binding, plan.proposal_id, rejected=('op', NOW))
        receipt = self.runner().execute(approved.raw)
        self.store.record_receipt(self.binding, plan.proposal_id, receipt)
        [row] = self.store.proposals(self.binding, self.round_id)
        self.assertEqual((row.decision, row.approved_raw, row.receipts[-1]['outcome']), ('approved', approved.raw, 'applied'))
        with closing(sqlite3.connect(self.store.paths[2])) as db:
            with self.assertRaises(sqlite3.IntegrityError):db.execute('DELETE FROM rem_decisions')
            with self.assertRaises(sqlite3.IntegrityError):db.execute("UPDATE rem_receipts SET verdict='x'")
        self.assertEqual(self.store.consistency_errors(), ())

    def test_approval_must_match_the_stored_plan_and_binding(self):
        from backends.ubuntu.approvals import approve
        plan = self.stored_plan()
        other = self.plan(round_id=self.round_id, value='other')  # same proposal shape, different plan, not stored
        object.__setattr__(other, 'proposal_id', plan.proposal_id)
        with self.assertRaises(ValueError):self.store.record_decision(self.binding, plan.proposal_id, approved=approve(other, 'op', NOW))
        stranger = WorkflowBinding('3' * 32, 'ubuntu', 'ubuntu:fixture', 'epoch', 'c', '2026-11-06T00:00:00+00:00')
        with self.assertRaises(ValueError):self.store.record_decision(stranger, plan.proposal_id, approved=approve(plan, 'op', NOW))
        with self.assertRaises(ValueError):self.store.add_proposal(self.binding, self.plan(round_id='4' * 32), title='x', preview={})

    def test_rejection_writes_nothing_and_receipts_need_an_approval(self):
        from backends.ubuntu.approvals import approve
        plan = self.stored_plan()
        self.store.record_decision(self.binding, plan.proposal_id, rejected=('fixture-operator', NOW))
        receipt = self.runner().execute(approve(plan, 'op', NOW).raw)
        with self.assertRaises(ValueError):self.store.record_receipt(self.binding, plan.proposal_id, receipt)
        [row] = self.store.proposals(self.binding, self.round_id)
        self.assertEqual((row.decision, row.approved_raw, row.receipts), ('rejected', None, ()))

    def test_receipt_for_another_request_is_refused(self):
        from backends.ubuntu.approvals import approve
        plan = self.stored_plan()
        approved = approve(plan, 'op', NOW)
        self.store.record_decision(self.binding, plan.proposal_id, approved=approved)
        foreign = self.runner().execute(approve(self.plan(value='zzz'), 'op', NOW).raw)
        with self.assertRaises(ValueError):self.store.record_receipt(self.binding, plan.proposal_id, foreign)


class PreviewTests(Fixture):
    def test_preview_is_read_only_and_matches_what_the_runner_checks(self):
        from backends.ubuntu.approvals import approve
        from datetime import datetime
        preview = self.runner(clock=lambda: NOW - timedelta(minutes=1)).preview(self.family.action_id, {'name': 'alpha', 'value': 'new'})
        self.assertEqual(preview['before_state_sha256'], sha(b'old'))
        self.assertEqual(preview['expected_after_sha256'], sha(b'new'))
        self.assertEqual(preview['summary'], {'name': 'alpha', 'current_length': 3, 'proposed_length': 3})
        self.assertEqual(self.writes(), [])
        plan = self.plan(before_state_sha256=preview['before_state_sha256'], expected_after_sha256=preview['expected_after_sha256'],
                         collected=datetime.fromisoformat(preview['collected_at']))
        self.assertEqual(json.loads(self.runner(clock=lambda: NOW).execute(approve(plan, 'op', NOW).raw))['outcome'], 'applied')
        with self.assertRaises(ValueError):self.runner().preview('ubuntu.1.5.1.v1', {})
        with self.assertRaises(ValueError):self.runner().preview(self.family.action_id, {'name': '../etc', 'value': 'x'})

    def test_runner_cli_operations_and_fixed_failure_output(self):
        from vm.ubuntu.runner_cli import main
        def run(header, payload=b''):
            out, err = io.BytesIO(), io.BytesIO()
            code = main(stdin=io.BytesIO(json.dumps(header).encode() + b'\n' + payload), stdout=out, stderr=err,
                        runner_factory=lambda: self.runner(clock=lambda: NOW))
            return code, out.getvalue(), err.getvalue()
        code, out, _ = run({'op': 'preview', 'action_id': self.family.action_id, 'parameters': {'name': 'alpha', 'value': 'new'}})
        self.assertEqual((code, json.loads(out)['before_state_sha256']), (0, sha(b'old')))
        from backends.ubuntu.approvals import approve
        approved = approve(self.plan(), 'op', NOW)
        code, out, _ = run({'op': 'execute'}, approved.raw)
        self.assertEqual((code, json.loads(out)['outcome']), (0, 'applied'))
        code, out, _ = run({'op': 'reconcile', 'request_id': approved.request['request_id']})
        self.assertEqual(json.loads(out)['outcome'], 'applied')
        for header in ({'op': 'shell', 'command': 'id'}, {'op': 'preview', 'action_id': 'x', 'parameters': {}, 'extra': 1}, 'nope'):
            code, out, err = run(header)
            self.assertEqual((code, out), (2, b''))
            self.assertLessEqual(len(err), 80)

    def test_channel_runner_command_is_fixed(self):
        from backends.ubuntu.ssh_channel import RUNNER_COMMAND, SshChannel
        from tests.integration.test_ubuntu_live_path import FakeChannel, FakeTransport
        fake = FakeChannel(stdout=b'{}')
        self.assertEqual(SshChannel(FakeTransport(fake), 'SHA256:x').invoke_runner(b'{"op":"preview"}\n'), b'{}')
        self.assertEqual(fake.command, RUNNER_COMMAND)
        self.assertEqual(RUNNER_COMMAND, 'sudo -n /usr/local/libexec/fyp-hardening/runner')


class EligibleFixTests(unittest.TestCase):
    def test_fix_only_for_eligible_control_with_its_exact_action(self):
        from tests.integration.test_ubuntu_agents import AgentRoundTests, call, plan_call, team, scanner_ok, analysis_ok
        case = AgentRoundTests('test_complete_round_delegates_in_order_and_defers_every_finding'); case.setUp()
        try:
            from backends.ubuntu.agents import run_agentic_round
            from backends.ubuntu.adapter import _controls
            def round_with(decisions):
                rest = [{'control_id': '5.1.20', 'decision': 'defer', 'reason_code': 'no_registered_action'}]
                clients = team([call('delegate_scanner'), call('delegate_analysis'), plan_call(decisions + rest)],
                               scanner_ok(), analysis_ok())
                return run_agentic_round(client_factory=clients.__getitem__, collect=case.collect_with(), log_store=case.log,
                                         target_id='ubuntu:fixture', titles={c: x.title for c, x in _controls().items()},
                                         rank=lambda r, e: None, eligible={'1.5.1': 'fixture.file_value.v1'})
            fix = {'control_id': '1.5.1', 'decision': 'fix', 'action_id': 'fixture.file_value.v1', 'reason_code': 'highest_risk'}
            self.assertEqual(round_with([fix])['plan']['fixes'], [fix])
            for bad in (dict(fix, action_id='ubuntu.1.5.1.v1'), dict(fix, control_id='5.1.20'),
                        dict(fix, reason_code='no_registered_action')):
                self.assertIsNone(round_with([bad])['plan'])
        finally:
            case.doCleanups()


class BackendRemediationTests(StoreFixture):
    FIX = [{'control_id': '1.5.1', 'decision': 'fix', 'action_id': 'fixture.file_value.v1', 'reason_code': 'highest_risk'}]

    def backend(self, orchestrator_decisions):
        from backends.ubuntu.actions import ActionSpec
        from backends.ubuntu.adapter import UbuntuBackend
        from system.connection import VerifiedSession
        from system.identity import VerifiedIdentity
        from system.ledger import CoordinationLedger
        from tests.integration.test_ubuntu_agents import call, plan_call, team, scanner_ok, RankingAware
        from tests.integration.test_ubuntu_live_path import CliChannel, TARGET as LIVE
        test = self

        class Channel(CliChannel):
            def __init__(self):
                super().__init__(); self.runner_calls = []
            def invoke_helper(self, stdin_bytes, **kwargs):
                # Fake target with exactly one confirmed failure: runtime ASLR 0 (control 1.5.1).
                from types import SimpleNamespace
                from tests.integration.test_ubuntu_live_path import run_cli, fake_io_factory, fake_preflight
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
                code = main(stdin=io.BytesIO(data), stdout=out, stderr=err,
                            runner_factory=lambda: test.runner(clock=test.clock))
                if code:
                    raise ValueError('runner refused')
                return out.getvalue()
        self.channel = Channel()
        spec = ActionSpec(self.family.action_id, 1, self.family.implementation_sha256, ('1.5.1',), self.family.validate, 60,
                          propose=lambda cid, evidence: {'name': 'alpha', 'value': 'new'}, title='TEST-ONLY fixture value',
                          recovery={'kind': 'restore_backup', 'scope': ['fixture:alpha']})
        self.ledger = CoordinationLedger(self.root / 'ledger.sqlite3')
        session = VerifiedSession('c', VerifiedIdentity('ubuntu', LIVE[1], LIVE[0], '22.04', 'ssh'), 'ubuntu:fixture',
                                  'epoch', 'user', 'vm', 22, self.channel)
        clients = team([call('delegate_scanner'), call('delegate_analysis'),
                        plan_call(orchestrator_decisions)], scanner_ok(), RankingAware())
        return UbuntuBackend(self.root / 'backend.sqlite3', session=session, ledger=self.ledger,
                             families={spec.action_id: spec}, model_client_factory=clients.__getitem__,
                             model_probe=lambda: True)

    def clock(self):
        from datetime import datetime, timezone
        return datetime.now(timezone.utc)

    def round(self, backend):
        from tests.integration.test_ubuntu_live_path import open_gate
        with open_gate():
            handle = backend.start_round('c', None, None, 'agentic', 'op-round')
        return handle, backend.snapshot('c', handle.binding.workflow_session_id)

    def executes(self):
        return [c for c in self.channel.runner_calls if c.startswith(b'{"op":"execute"}')]

    def test_agentic_fix_creates_previewed_proposal_then_approve_and_gated_execute_apply_once(self):
        from unittest import mock
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        [proposal] = snap.proposals
        self.assertEqual((proposal.control_id, proposal.action_id, proposal.decision),
                         ('1.5.1', 'fixture.file_value.v1', None))
        self.assertEqual(proposal.eligible_commands, ('approve', 'reject'))
        self.assertIn('Current length: 3', proposal.exact_preview)  # readable lines, not raw JSON
        self.assertEqual(self.writes(), [])
        workflow = handle.binding.workflow_session_id
        decision = backend.decide('c', workflow, proposal.reference, True, 'fixture-operator', 'Looks right', 'op-decide')
        self.assertEqual(decision.state, 'approved')
        snap = backend.snapshot('c', workflow)
        stored = backend._store().proposals(handle.binding, snap.current_round_reference.record_id)[0]
        request_id = json.loads(stored.approved_raw)['request_id']
        with self.assertRaisesRegex(ValueError, 'not enabled'):  # the real execution gate is closed
            backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True, 'op-x')
        from tests.integration.test_ubuntu_live_path import open_gate
        # Test-only: verification is a Live collection, so it needs the assessment gate's accepted engine too.
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            with self.assertRaises(ValueError):
                backend.execute_approved('c', workflow, snap.current_round_reference, ('9' * 32,), True, 'op-wrong')
            result = backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True, 'op-exec')
            self.assertEqual(result.state, 'completed')
            again = backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True, 'op-exec-2')
            self.assertEqual(again.state, 'completed')
        self.assertEqual(len(self.executes()), 1)
        self.assertEqual(self.writes(), ['alpha'])
        snap = backend.snapshot('c', workflow)
        [row] = snap.results
        # The TEST-ONLY family wrote a temp file, not the target's ASLR: fresh verification honestly still fails,
        # and nothing is retried automatically.
        self.assertEqual((row.execution_state, row.verification_status.value), ('applied', 'Non-Compliant'))
        self.assertIsNotNone(row.verification_assessment_reference)
        self.assertIn('verification', row.detail.lower())
        self.assertEqual(snap.proposals[0].eligible_commands, ())
        self.assertEqual(snap.step_states[4:], ('done', 'done'))
        self.assertEqual(snap.current_round_reference, handle.round_reference)  # still the assessment round
        self.assertEqual(len(backend.history('ubuntu:fixture')), 2)  # assessment + verification
        self.assertEqual(len(self.executes()), 1)

    def test_failed_verification_scan_reports_pending_and_never_retries(self):
        from unittest import mock
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow = handle.binding.workflow_session_id
        backend.decide('c', workflow, snap.proposals[0].reference, True, 'fixture-operator', '', 'op-d')
        stored = backend._store().proposals(handle.binding, snap.current_round_reference.record_id)[0]
        request_id = json.loads(stored.approved_raw)['request_id']
        # Execution gate open but no accepted OpenSCAP engine: the fresh Live collection is refused by the target.
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), \
                mock.patch('backends.ubuntu.adapter.accepted_engine_version', return_value=None):
            result = backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True, 'op-e')
        self.assertEqual(result.state, 'verification_pending')
        self.assertEqual(self.writes(), ['alpha'])
        self.assertEqual(len(self.executes()), 1)
        snap = backend.snapshot('c', workflow)
        self.assertEqual((snap.results[0].verification_status, snap.step_states[5]), (None, 'pending'))

    def test_applied_fix_can_be_restored_through_a_separately_approved_recovery_proposal(self):
        from unittest import mock
        from system.contracts import AuxiliaryKind, RecoveryInput
        from tests.integration.test_ubuntu_live_path import open_gate
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow, fix = handle.binding.workflow_session_id, snap.proposals[0]
        backend.decide('c', workflow, fix.reference, True, 'fixture-operator', '', 'op-d')
        request_id = backend.snapshot('c', workflow).proposals[0].approved_request_id
        before = backend.snapshot('c', workflow).proposals[0].before_state_sha256
        inputs = RecoveryInput(request_id, before, 'restore_before_state')
        with self.assertRaises(ValueError):  # nothing applied yet: nothing to restore
            backend.request_auxiliary('c', workflow, AuxiliaryKind.RECOVERY, fix.reference, inputs, 'op-early')
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), open_gate():
            backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True, 'op-exec')
            self.assertEqual((self.work / 'alpha').read_bytes(), b'new')
            with self.assertRaises(ValueError):  # wrong backup digest
                backend.request_auxiliary('c', workflow, AuxiliaryKind.RECOVERY, fix.reference,
                                          RecoveryInput(request_id, 'f' * 64, 'restore_before_state'), 'op-bad')
            ref = backend.request_auxiliary('c', workflow, AuxiliaryKind.RECOVERY, fix.reference, inputs, 'op-aux')
            rows = {p.reference: p for p in backend.snapshot('c', workflow).proposals}
            self.assertEqual((rows[ref].kind, rows[ref].action_id, rows[ref].eligible_commands),
                             ('recovery', 'recovery.restore.v1', ('approve', 'reject')))
            with self.assertRaises(ValueError):  # not approved yet
                backend.dispatch_auxiliary('c', workflow, ref, 'op-dispatch-early')
            backend.decide('c', workflow, ref, True, 'fixture-operator', 'Undo for the demo', 'op-d2')
            # The recovery proposal never joins the CIS fix set.
            self.assertEqual(backend.execute_approved('c', workflow, snap.current_round_reference, (request_id,), True,
                                                      'op-exec-again').state, 'completed')
            result = backend.dispatch_auxiliary('c', workflow, ref, 'op-dispatch')
            self.assertEqual(result.state, 'completed')
            again = backend.dispatch_auxiliary('c', workflow, ref, 'op-dispatch-2')
            self.assertEqual(again.state, 'completed')
        self.assertEqual((self.work / 'alpha').read_bytes(), b'old')
        self.assertEqual(len([c for c in self.channel.runner_calls if c.startswith(b'{"op":"execute"}')]), 2)
        results = {r.proposal_reference: r for r in backend.snapshot('c', workflow).results}
        self.assertEqual(results[ref].execution_state, 'applied')
        with self.assertRaises(ValueError):  # a restore is not itself restorable
            backend.request_auxiliary('c', workflow, AuxiliaryKind.RECOVERY, ref,
                                      RecoveryInput(request_id, before, 'restore_before_state'), 'op-loop')

    def test_a_reboot_naming_no_applied_change_is_refused(self):
        # Superseded "reboot unsupported": maintenance.reboot.v1 exists, but only to complete applied changes.
        from system.contracts import AuxiliaryKind, RebootInput
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        with self.assertRaises(ValueError):
            backend.request_auxiliary('c', handle.binding.workflow_session_id, AuxiliaryKind.REBOOT, None,
                                      RebootInput((), 'now'), 'op-reboot')

    def test_rejection_writes_nothing_and_cannot_be_executed(self):
        from unittest import mock
        backend = self.backend(self.FIX)
        handle, snap = self.round(backend)
        workflow = handle.binding.workflow_session_id
        state = backend.decide('c', workflow, snap.proposals[0].reference, False, 'fixture-operator', '', 'op-r').state
        self.assertEqual(state, 'rejected')
        with mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            with self.assertRaises(ValueError):
                backend.execute_approved('c', workflow, snap.current_round_reference, (), True, 'op-exec')
        self.assertEqual(self.executes(), [])
        self.assertEqual(self.writes(), [])

    def test_no_registered_family_means_no_fix_and_no_proposal(self):
        backend = self.backend([])
        backend.families = {}
        _, snap = self.round(backend)
        self.assertEqual(snap.proposals, ())
        self.assertEqual(self.channel.runner_calls, [])
