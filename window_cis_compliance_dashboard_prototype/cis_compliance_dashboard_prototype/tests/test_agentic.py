"""Agentic round contracts with scripted models and a simulated VM. No real VM or model."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest

from hardening.action_library import LIBRARY
from hardening.agentic import ANALYSIS, ORCHESTRATOR, SCANNER, AgenticHardening
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.remediation import RUNNER, RemediationAgent, RemediationStore
from hardening.risk import analyse
from hardening.winrm_channel import IDENTITY_SCRIPT, LiveScanner
from test_investigation import MockClient
from test_full_controls import full_fixture
from test_winrm_channel import IDENTITY, target

# The registered lab VM as observed on 26 October 2026 (live WinRM scan), used as fixture state.
LAB_STATE = {'1.2.2': 0, '1.2.1': None, '1.2.4': None, '1.1.1': 0, '1.1.3': 0, '1.1.2': 42,
             '2.3.10.3': 0, '9.3.1': None, '18.10.57.3.9.4': None}


class FakeVm:
    """Answers only the three registered scripts and simulates the runner's guards."""

    def __init__(self, state=LAB_STATE, *, fail_action=False, firewall=True, error_controls=()):
        self.values = {o['control_id']: o['value'] for o in full_fixture()['observations']}
        self.values.update(state)
        self.fail_action, self.firewall, self.error_controls = fail_action, firewall, set(error_controls)
        self.ledger, self.writes, self.scripts = set(), [], []

    def __call__(self, target):
        return self

    def evidence(self):
        doc = full_fixture()
        stamp = datetime.now(timezone.utc).isoformat()
        doc['started_at'] = doc['completed_at'] = stamp
        for row in doc['observations']:
            value = self.values[row['control_id']]
            failed = row['control_id'] in self.error_controls
            row.update(collected_at=stamp, value=None if failed else value,
                       state='error' if failed else ('ok' if value is not None else 'missing'),
                       error='collection_failed' if failed else None)
        for row in doc['effective_context']:
            row['collected_at'] = stamp
            if row['control_id'] == 'firewall_public_enabled':
                row['value'] = self.firewall
        return json.dumps(doc)

    def run(self, script, parameters=None):
        self.scripts.append(script)
        if script == IDENTITY_SCRIPT:
            return [json.dumps(IDENTITY)], False, []
        if script == LiveScanner.collector_text():
            return [self.evidence()], False, []
        if script == RUNNER.read_text(encoding='utf-8-sig'):
            return self.remediate(parameters)
        raise AssertionError('An unregistered script was sent to the VM')

    def remediate(self, p):
        raw = p['RequestJson'].encode()
        if hashlib.sha256(raw).hexdigest() != p['ExpectedRequestSha256']:
            return [], True, ['Request hash does not match the approved request.']
        request = json.loads(raw)
        action = LIBRARY.get(request['action_id'])
        if action is None or request['value'] != action.target_value or request['control_id'] != action.control_id:
            return [], True, ['Request is outside the approved library contract.']
        if request['request_id'] in self.ledger:
            return [], True, ['Request already attempted. Review its outcome; do not replay.']
        before = self.evidence()
        current = self.values[request['control_id']]
        if type(current) is not type(request['expected_before']) or current != request['expected_before']:
            return [], True, ['Configuration changed since assessment. Rescan and obtain a new approval.']
        self.ledger.add(request['request_id'])
        status = 'execution_failed' if self.fail_action else 'applied'
        if not self.fail_action:
            # auditpol /set only enables flags, so audit values gain bits; other actions set the value.
            self.values[request['control_id']] = (current | action.target_value if request['control_id'].startswith('17.')
                                                  else action.target_value)
            self.writes.append(request['control_id'])
            if request['control_id'] == '1.2.2':  # Windows enables default lockout timers.
                for dependent in ('1.2.1', '1.2.4'):
                    if self.values[dependent] is None:
                        self.values[dependent] = 30
        receipt = dict(schema_version=2, request_id=request['request_id'], request_sha256=p['ExpectedRequestSha256'],
                       status=status, before_evidence=base64.b64encode(before.encode()).decode(),
                       after_evidence=base64.b64encode(self.evidence().encode()).decode())
        return [json.dumps(receipt)], False, []


def call(name, target_id, **arguments):
    return {'tool_calls': [{'function': {'name': name, 'arguments': {'target_id': target_id, **arguments}}}]}


def clients(target_id, orchestrator, scanner=None):
    scanner = scanner or [call('scan_target', target_id), call('read_coverage', target_id),
                          call('handoff_analysis', target_id, reason='Coverage read; four gaps are policy Unknowns.')]
    return {ORCHESTRATOR: MockClient(orchestrator), SCANNER: MockClient(scanner)}.__getitem__


class AgenticTestCase(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        imports = ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3')
        self.runtime = AssessmentOrchestrator(imports)
        self.store = RemediationStore(Path(folder.name) / 'agentic.sqlite3', imports)

    def hardening(self, vm, orchestrator, scanner=None):
        scanner_channel = LiveScanner(self.runtime, target(), session_factory=vm)
        self.target_id = 'windows:' + target().machine_uuid
        return AgenticHardening(self.runtime, self.store, scanner_channel,
                                client_factory=clients(self.target_id, orchestrator, scanner))

    def standard_round(self, vm):
        t = 'windows:' + target().machine_uuid
        return self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t), plan(t,
            fixes=[('1.2.2', 'REM-1.2.2', 'high_risk'), ('1.1.1', 'REM-1.1.1', 'low_impact')],
            skipped=[('2.3.10.3', 'needs_review'), ('1.1.3', 'lower_priority')])])

    def rejected(self, hardening, round_id):
        trace = next(t for t in hardening.traces(round_id) if t['agent_role'] == ORCHESTRATOR)
        return [e['data']['error'] for e in trace['events'] if e['kind'] == 'tool_rejected']


def plan(t, fixes=(), skipped=()):
    return call('submit_plan', t, fixes=[dict(control_id=c, action_id=a, reason_code=r) for c, a, r in fixes],
                skipped=[dict(control_id=c, reason_code=r) for c, r in skipped])


DEFER_ALL = [(c, 'lower_priority') for c in ('1.2.2', '2.3.10.3', '1.1.1', '1.1.3')]


class AgenticRoundTests(AgenticTestCase):
    def test_full_loop_scan_analyse_propose_approve_execute_verify(self):
        vm = FakeVm()
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        self.assertEqual(vm.writes, [], 'Proposing must never write to the VM')
        roles = {t['agent_role'] for t in hardening.traces(result['round_id'])}
        self.assertEqual(roles, {ORCHESTRATOR, SCANNER, ANALYSIS})
        proposals = self.store.for_run(result['framework_run_id'])
        self.assertEqual([p['proposal']['control_id'] for p in proposals], ['1.2.2', '1.1.1'])
        self.assertTrue(all(p['decision'] is None for p in proposals))

        self.store.decide(proposals[0]['proposal']['request_id'], approve=True, operator='admin01')
        self.store.decide(proposals[1]['proposal']['request_id'], approve=False, operator='admin01', comment='Later')
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual([v['verdict'] for v in executed['verdicts']], ['Verified compliant'])
        self.assertEqual(vm.writes, ['1.2.2'], 'Rejected proposal must cause no write')
        changes = {c['control_id']: c['change'] for c in
                   hardening.changes(result['framework_run_id'], executed['verification_run_id'])}
        self.assertEqual(changes['1.2.2'], 'Improvement')
        self.assertEqual(changes['1.2.1'], 'Unknown -> Compliant')
        self.assertEqual(changes['1.1.1'], 'Unchanged')
        with self.assertRaises(ValueError):
            hardening.execute_approved(result['session_id'])  # Nothing approved and unexecuted remains.

    def test_orchestrator_cannot_skip_scanner_or_analysis(self):
        vm, t = FakeVm(), 'windows:' + target().machine_uuid
        hardening = self.hardening(vm, [plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')]),
                                        call('delegate_analysis', t)])
        result = hardening.run_round()
        errors = self.rejected(hardening, result['round_id'])
        self.assertEqual(errors, ['Delegate the Scanner before submitting a plan',
                                  'A Scanner handoff is required before analysis'])
        self.assertEqual(result['outcome']['outcome'], 'incomplete')  # Two invalid calls stop the run.
        self.assertEqual(vm.scripts, [], 'Nothing reaches the VM without a Scanner delegation')

    def test_plan_cannot_fix_gaps_or_use_foreign_actions_and_stores_nothing(self):
        vm, t = FakeVm(), 'windows:' + target().machine_uuid
        hardening = self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.1', 'REM-1.2.1', 'high_risk')], skipped=DEFER_ALL),
            plan(t, fixes=[('1.2.2', 'REM-1.1.4', 'high_risk')], skipped=DEFER_ALL[1:])])
        result = hardening.run_round()
        errors = self.rejected(hardening, result['round_id'])
        self.assertTrue(errors[0].startswith('1.2.1 is not in must_decide'))
        self.assertEqual(errors[1], 'REM-1.1.4 cannot fix 1.2.2 now; use one of REM-1.2.2')
        self.assertEqual(self.store.for_run(result['framework_run_id']), [])
        self.assertEqual(vm.writes, [])

    def test_blocked_prerequisite_and_duplicate_decisions_are_refused(self):
        state = dict(LAB_STATE, **{'1.2.1': 5})  # Duration non-compliant while threshold is still 0.
        t = 'windows:' + target().machine_uuid
        others = [('2.3.10.3', 'lower_priority'), ('1.1.1', 'lower_priority'), ('1.1.3', 'lower_priority')]
        hardening = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.1', 'REM-1.2.1', 'high_risk'), ('1.2.2', 'REM-1.2.2', 'unblocks_other')], skipped=others),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')], skipped=[('1.2.2', 'lower_priority')] + others)])
        result = hardening.run_round()
        errors = self.rejected(hardening, result['round_id'])
        self.assertEqual(errors[0], 'REM-1.2.1 cannot fix 1.2.1 now; it waits for 1.2.2 to be compliant')
        self.assertEqual(errors[1], '1.2.2 appears more than once; decide each finding exactly once')
        self.assertEqual(self.store.for_run(result['framework_run_id']), [])

    def test_blocked_finding_is_deferred_and_its_prerequisite_proposed(self):
        state = dict(LAB_STATE, **{'1.2.1': 5})
        t = 'windows:' + target().machine_uuid
        result = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')],
                 skipped=[('1.2.1', 'waits_for_prerequisite'), ('2.3.10.3', 'lower_priority'),
                          ('1.1.1', 'lower_priority'), ('1.1.3', 'lower_priority')])]).run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        proposals = self.store.for_run(result['framework_run_id'])
        self.assertEqual([p['proposal']['control_id'] for p in proposals], ['1.2.2'])
        self.assertEqual(proposals[0]['proposal']['reason'], 'Prerequisite that unblocks 1.2.1 (unblocks_other)')
        self.assertEqual(result['outcome']['skipped'][0], dict(control_id='1.2.1', reason_code='waits_for_prerequisite',
                                                               reason='Waits until 1.2.2 is compliant'))

    def test_model_unavailable_leaves_no_proposals_or_writes(self):
        vm = FakeVm()
        hardening = self.hardening(vm, [ConnectionError('Ollama down')])
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'incomplete')
        self.assertEqual(vm.writes, [])
        self.assertEqual(self.store.rounds(result['session_id'])[0]['outcome']['outcome'], 'incomplete')

    def test_scanner_reports_collection_failure_and_round_stops(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), plan(t)],
            scanner=[call('scan_target', t), call('report_failure', t, reason='VM unreachable.')])
        hardening.scanner.session_factory = lambda _: (_ for _ in ()).throw(ConnectionError('Connection refused'))
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'collection_failed')

    def test_scanner_rescan_only_for_error_results(self):
        t = 'windows:' + target().machine_uuid
        scanner = [call('scan_target', t), call('read_coverage', t), call('rescan', t, reason='retry'),
                   call('handoff_analysis', t, reason='ok')]
        for errors, allowed in (((), False), (('1.1.5',), True)):
            hardening = self.hardening(FakeVm(error_controls=errors), [call('delegate_scanner', t),
                call('delegate_analysis', t), plan(t, skipped=DEFER_ALL)], scanner=list(scanner))
            result = hardening.run_round()
            trace = next(x for x in hardening.traces(result['round_id']) if x['agent_role'] == SCANNER)
            rescans = [e for e in trace['events'] if e['data'].get('name') == 'rescan']
            self.assertEqual(rescans[0]['kind'], 'tool' if allowed else 'tool_rejected')

    def test_models_receive_compact_views(self):
        result = self.standard_round(FakeVm()).run_round()
        hardening = self.standard_round(FakeVm())
        trace = next(t for t in AgenticHardening.traces(hardening, result['round_id']) if t['agent_role'] == ORCHESTRATOR)
        analysis = next(e['data']['result'] for e in trace['events'] if e['data'].get('name') == 'delegate_analysis')
        self.assertEqual(set(analysis), {'agent', 'must_decide', 'no_action', 'gaps'})
        self.assertEqual(analysis['must_decide'][0], dict(control_id='1.2.2', level='High', score=62, actions=['REM-1.2.2'],
            fix_codes=['high_risk', 'low_impact'], skip_codes=['needs_review', 'lower_priority']))
        moderate = next(d for d in analysis['must_decide'] if d['control_id'] == '1.1.1')
        self.assertEqual(moderate['fix_codes'], ['low_impact'])  # Only codes that are true for this finding.


class OrchestratorAccountabilityTests(AgenticTestCase):
    def test_summary_is_written_from_records_and_lists_every_decision(self):
        result = self.standard_round(FakeVm()).run_round()
        outcome = result['outcome']
        self.assertNotIn('model_commentary', outcome)
        self.assertEqual(outcome['reason'], 'Proposed for your approval, in order: 1.2.2 (High 62), 1.1.1 (Moderate 56). '
                         'Deferred by the Orchestrator: 2.3.10.3, 1.1.3. 4 Unknown/Error gap(s) not scored. '
                         'Nothing has been approved or executed.')
        self.assertEqual([s['control_id'] for s in outcome['skipped']], ['2.3.10.3', '1.1.3'])
        reasons = [p['proposal']['reason'] for p in self.store.for_run(result['framework_run_id'])]
        self.assertEqual(reasons, ['High-priority finding (high_risk)', 'Low operational impact (low_impact)'])

    def test_unknown_reason_code_is_rejected_with_the_allowed_list(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'because_i_said_so')], skipped=DEFER_ALL[1:]),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=DEFER_ALL[1:])])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']), [
            'because_i_said_so is not a fixes reason_code; use one of high_risk, improves_detection, low_impact, unblocks_other'])
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')

    def test_unaccounted_finding_and_reasons_that_contradict_facts_are_rejected(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.1.1', 'REM-1.1.1', 'high_risk')], skipped=DEFER_ALL[:2] + DEFER_ALL[3:]),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=[('1.1.1', 'lower_priority')])])
        result = hardening.run_round()
        errors = self.rejected(hardening, result['round_id'])
        self.assertEqual(errors[0], 'reason_code high_risk does not fit 1.1.1 (Moderate 56)')
        self.assertEqual(errors[1], 'Every must_decide finding needs a fix or a skip reason; missing: 2.3.10.3, 1.1.3')
        self.assertEqual(result['outcome']['outcome'], 'incomplete')  # Two invalid calls end the run unfinished.
        self.assertEqual(self.store.for_run(result['framework_run_id']), [])

    def test_argument_errors_name_what_was_wrong(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            call('submit_plan', t, fixes=[], reason='done'), plan(t, skipped=DEFER_ALL)])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']),
                         ['submit_plan needs exactly: fixes, skipped, target_id; received: fixes, reason, target_id'])
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')  # One correction, then success.


class ExpandedControlRoundTests(AgenticTestCase):
    def test_default_audit_policy_is_ranked_proposed_and_verified_by_include_rule(self):
        # Windows Server default audit: Success only for these subcategories.
        state = dict(LAB_STATE, **{'17.1.1': 1, '17.5.1': 1, '9.2.6': None, '18.10.57.3.9.3': None})
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('17.5.1', 'REM-17.5.1', 'improves_detection')],
                 skipped=[(c, 'lower_priority') for c in ('1.2.2', '2.3.10.3', '1.1.1', '1.1.3', '17.1.1')])])
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        record = self.runtime.imports.get(self.runtime.get(result['framework_run_id']).evidence_sha256)
        self.assertEqual(len(record.assessment.results), 32)
        ranked = {f.control_id: f for f in analyse(record)}
        self.assertEqual((ranked['17.5.1'].factors['E'], ranked['17.5.1'].rule), (2, 'audit includes Failure'))
        proposal = self.store.for_run(result['framework_run_id'])[0]['proposal']['request_id']
        self.store.decide(proposal, approve=True, operator='admin01')
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual(executed['verdicts'][0]['verdict'], 'Verified compliant')
        after = self.runtime.imports.get(self.runtime.get(executed['verification_run_id']).evidence_sha256)
        self.assertEqual(next(r.evidence.value for r in after.assessment.results if r.control.control_id == '17.5.1'), 3)


class RemediationAgentTests(AgenticTestCase):
    def proposed(self, vm):
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        return hardening, result, self.store.for_run(result['framework_run_id'])[0]['proposal']['request_id']

    def test_unapproved_or_rejected_proposals_cannot_execute(self):
        vm = FakeVm()
        hardening, _, proposal = self.proposed(vm)
        agent = RemediationAgent(self.store, hardening.scanner)
        with self.assertRaises(ValueError):
            agent.execute(proposal)
        self.store.decide(proposal, approve=False, operator='admin01')
        with self.assertRaises(ValueError):
            agent.execute(proposal)
        with self.assertRaises(ValueError):
            self.store.decide(proposal, approve=True, operator='admin01')  # One decision per proposal.
        self.assertEqual(vm.writes, [])

    def test_changed_precondition_is_refused_without_write_and_never_replayed(self):
        vm = FakeVm()
        hardening, _, proposal = self.proposed(vm)
        self.store.decide(proposal, approve=True, operator='admin01')
        vm.values['1.2.2'] = 3  # Someone changed the VM after the scan.
        verdict = RemediationAgent(self.store, hardening.scanner).execute(proposal)
        self.assertTrue(verdict.startswith('Refused before execution: Configuration changed'))
        self.assertEqual(vm.writes, [])
        with self.assertRaises(ValueError):
            RemediationAgent(self.store, hardening.scanner).execute(proposal)

    def test_execution_failure_is_unresolved_and_expired_approval_refused(self):
        vm = FakeVm(fail_action=True)
        hardening, _, proposal = self.proposed(vm)
        self.store.decide(proposal, approve=True, operator='admin01')
        self.assertEqual(RemediationAgent(self.store, hardening.scanner).execute(proposal), 'Unresolved: execution_failed')
        second = self.store.for_run(self.store.get(proposal)['proposal']['framework_run_id'])[1]['proposal']['request_id']
        self.store.decide(second, approve=True, operator='admin01',
                          now=datetime.now(timezone.utc) - timedelta(hours=2))
        with self.assertRaises(ValueError):
            RemediationAgent(self.store, hardening.scanner).execute(second)

    def test_channel_loss_during_execution_is_uncertain_not_retried(self):
        vm = FakeVm()
        hardening, _, proposal = self.proposed(vm)
        self.store.decide(proposal, approve=True, operator='admin01')
        original = vm.run

        def drop(script, parameters=None):
            if script == RUNNER.read_text(encoding='utf-8-sig'):
                raise ConnectionError('Connection reset')
            return original(script, parameters)
        vm.run = drop
        verdict = RemediationAgent(self.store, hardening.scanner).execute(proposal)
        self.assertIn('outcome uncertain', verdict)
        with self.assertRaises(ValueError):
            RemediationAgent(self.store, hardening.scanner).execute(proposal)


class RiskEngineTests(AgenticTestCase):
    def record(self, vm):
        scanner = LiveScanner(self.runtime, target(), session_factory=vm)
        run = scanner.request(target().hostname, target().machine_uuid)
        return self.runtime.imports.get(run['evidence_sha256'])

    def test_scores_rank_and_skip_unknowns(self):
        ranked = {f.control_id: f for f in analyse(self.record(FakeVm()))}
        self.assertEqual(set(ranked), {'1.2.2', '1.1.1', '1.1.3', '2.3.10.3'})
        self.assertEqual((ranked['1.2.2'].score, ranked['1.2.2'].level), (62, 'High'))  # Report example I4 E3 P3 L3 D1.
        self.assertEqual([f.control_id for f in analyse(self.record(FakeVm()))], ['1.2.2', '2.3.10.3', '1.1.1', '1.1.3'])

    def test_regression_drift_and_disabled_firewall_raise_scores(self):
        compliant = self.record(FakeVm(dict(LAB_STATE, **{'1.2.2': 5, '1.2.1': 15, '1.2.4': 15})))
        regressed = self.record(FakeVm())
        finding = next(f for f in analyse(regressed, [compliant]) if f.control_id == '1.2.2')
        self.assertEqual((finding.factors['D'], finding.score), (5, 70))  # Report's confirmed-regression example.
        exposed = next(f for f in analyse(self.record(FakeVm(firewall=False))) if f.control_id == '1.2.2')
        self.assertEqual((exposed.factors['E'], exposed.score), (4, 67))


@unittest.skipUnless(shutil.which('powershell.exe'), 'Windows PowerShell required')
class LibraryParityTests(unittest.TestCase):
    def test_powershell_runner_table_matches_python_library(self):
        output = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(RUNNER),
                                 '-ListActions'], capture_output=True, text=True, timeout=60, check=True).stdout
        table = json.loads(output)
        self.assertEqual(set(table), set(LIBRARY))
        for action_id, entry in table.items():
            self.assertEqual(entry['control_id'], LIBRARY[action_id].control_id)
            self.assertEqual(entry['value'], LIBRARY[action_id].target_value)
            self.assertIs(type(entry['value']), type(LIBRARY[action_id].target_value))


if __name__ == '__main__':
    unittest.main()
