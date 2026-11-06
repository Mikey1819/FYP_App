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
from hardening.agentic import (ANALYSIS, ATTENTION, ORCHESTRATOR, PROMPTS, REMEDIATION, REVIEW_PROMPT, SCANNER,
                               AgenticHardening)
from hardening.framework import AssessmentRuns
from hardening.import_storage import ImportedEvidenceStore
from hardening.remediation import RUNNER, ApprovedActionExecutor, RemediationStore
from hardening.domain import Status
from hardening.risk import analyse
from hardening.server2022_catalogue import SOURCES
from hardening.winrm_channel import IDENTITY_SCRIPT, LiveScanner
from test_investigation import MockClient
from evidence_fixture import evidence_fixture
from test_winrm_channel import IDENTITY, target

# The registered lab VM as observed by a live WinRM scan, used as fixture state.
LAB_STATE = {'1.2.2': 0, '1.2.1': None, '1.2.4': None, '1.1.1': 0, '1.1.3': 0, '1.1.2': 42,
             '2.3.10.3': 0, '9.3.1': None, '18.10.57.3.9.4': None}


class FakeVm:
    """Answers only the three registered scripts and simulates the runner's guards."""

    def __init__(self, state=LAB_STATE, *, fail_action=False, firewall=True, error_controls=(), revert_controls=()):
        # fail_action: every write fails (True, or the failure message the runner reports).
        # revert_controls: the write succeeds but something sets the old value straight back.
        self.values = {o['control_id']: o['value'] for o in evidence_fixture()['observations']}
        self.values.update(state)
        self.fail_action, self.firewall, self.error_controls = fail_action, firewall, set(error_controls)
        self.revert_controls = set(revert_controls)
        self.ledger, self.writes, self.scripts, self.attempts = set(), [], [], []

    def __call__(self, target):
        return self

    def evidence(self):
        doc = evidence_fixture()
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
        self.attempts.append(request['control_id'])
        status = 'execution_failed' if self.fail_action else 'applied'
        if not self.fail_action and request['control_id'] in self.revert_controls:
            self.writes.append(request['control_id'])  # Written, then reverted before verification.
        elif not self.fail_action:
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
        if type(self.fail_action) is str:
            receipt['error'] = self.fail_action
        return [json.dumps(receipt)], False, []


def call(name, target_id, **arguments):
    return {'tool_calls': [{'function': {'name': name, 'arguments': {'target_id': target_id, **arguments}}}]}


class Responsive:
    """Test double that picks its next call from the tool results it has seen. Not a model."""
    model, provenance = 'mock-model', 'Mock model (test only)'

    def __init__(self, policy):
        self.policy = policy

    def chat(self, messages, tools, *, timeout):
        seen = [(m['tool_name'], json.loads(m['content'])) for m in messages if m['role'] == 'tool']
        name, arguments = self.policy(seen, [t['function']['name'] for t in tools])
        return call(name, tools[0]['function']['parameters']['properties']['target_id']['enum'][0], **arguments)


def scanner_policy(seen, names):
    done = [n for n, _ in seen]
    if 'scan_target' not in done:
        return 'scan_target', {}
    if 'read_coverage' not in done:
        return 'read_coverage', {}
    return names[4], dict(reason='Coverage read.')  # handoff_analysis, or handoff_verification when verifying.


def analysis_policy(seen, names):
    if not seen:
        return 'score_findings', {}
    return 'submit_analysis', dict(gap_triage=[
        dict(control_id=g['control_id'], triage_code='manual_review') for g in seen[0][1]['gaps']])


def remediation_policy(seen, names):
    done = [n for n, _ in seen]
    if 'list_approved' not in done:
        return 'list_approved', {}
    if 'precheck' not in done:
        return 'precheck', {}
    rows = next(r for n, r in seen if n == 'precheck').get('requests', [])
    skipped = {r.get('control_id') for n, r in seen if n == 'skip_fix'}
    waiting = [row for row in rows if not row['ready'] and row['control_id'] not in skipped]
    if waiting:
        return 'skip_fix', dict(control_id=waiting[0]['control_id'], reason_code=waiting[0]['skip_codes'][0])
    ready = [row['control_id'] for row in rows if row['ready']]
    executed = any(n == 'execute_fixes' and 'results' in r for n, r in seen)  # A refused list executed nothing.
    if ready and not executed and not any(r.get('must_stop') for _, r in seen):
        return 'execute_fixes', dict(control_ids=ready)
    return 'report_results', {}


def review_policy(seen, names):
    done = [n for n, _ in seen]
    if 'delegate_remediation' not in done:
        return 'delegate_remediation', {}
    if 'next_step_codes' not in seen[-1][1] and 'delegate_verification' not in done:
        return 'delegate_verification', {}
    codes = next(r['next_step_codes'] for _, r in reversed(seen) if 'next_step_codes' in r)
    step = next(s for s in ('remediation_review', 'next_round', 'finish') if codes[s])
    return 'submit_review', dict(next_step=step, reason_code=codes[step][0])


class PhasedOrchestrator:
    """Scripted plan for the assessment phase; scripted or responsive decisions for the remediation phase."""
    model, provenance = 'mock-model', 'Mock model (test only)'

    def __init__(self, plan, review=None):
        self.plan = MockClient(plan)
        self.review = MockClient(review) if review is not None else Responsive(review_policy)

    def chat(self, messages, tools, *, timeout):
        client = self.review if messages[0]['content'] == REVIEW_PROMPT else self.plan
        return client.chat(messages, tools, timeout=timeout)


def clients(target_id, orchestrator, scanner=None, analysis=None, remediation=None, review=None):
    """One client per role: a given client, a scripted list where a test pins the behaviour, otherwise responsive."""
    def role(given, policy):
        return given if hasattr(given, 'chat') else MockClient(given) if given else Responsive(policy)
    team = {ORCHESTRATOR: PhasedOrchestrator(orchestrator, review), SCANNER: role(scanner, scanner_policy),
            ANALYSIS: role(analysis, analysis_policy), REMEDIATION: role(remediation, remediation_policy)}
    return team.__getitem__


class TeamDouble:
    """Routes plain client calls to role doubles by system prompt (the page builds clients without a role)."""

    def __init__(self, factory):
        self.factory = factory
        self.roles = {prompt: role for role, prompt in PROMPTS.items()} | {REVIEW_PROMPT: ORCHESTRATOR}

    def chat(self, messages, tools, *, timeout):
        return self.factory(self.roles[messages[0]['content']]).chat(messages, tools, timeout=timeout)


class AgenticTestCase(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        imports = ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3')
        self.runtime = AssessmentRuns(imports)
        self.store = RemediationStore(Path(folder.name) / 'agentic.sqlite3', imports)

    def hardening(self, vm, orchestrator, scanner=None, **agents):
        scanner_channel = LiveScanner(self.runtime, target(), session_factory=vm)
        self.target_id = 'windows:' + target().machine_uuid
        return AgenticHardening(self.runtime, self.store, scanner_channel,
                                client_factory=clients(self.target_id, orchestrator, scanner, **agents))

    def trace(self, hardening, round_id, role):
        return [t for t in hardening.traces(round_id) if t['agent_role'] == role]

    def calls(self, trace):
        return [(e['kind'], e['data']['name']) for e in trace['events'] if e['kind'] in ('tool', 'tool_rejected')]

    def standard_round(self, vm, **agents):
        t = 'windows:' + target().machine_uuid
        return self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t), plan(t,
            fixes=[('1.2.2', 'REM-1.2.2', 'high_risk'), ('1.1.1', 'REM-1.1.1', 'low_impact')],
            skipped=[('2.3.10.3', 'needs_review'), ('1.1.3', 'lower_priority'), ('18.10.57.3.9.4', 'needs_review')])],
            **agents)

    def approve_all(self, framework_run_id):
        for record in self.store.for_run(framework_run_id):
            self.store.decide(record['proposal']['request_id'], approve=True, operator='admin01')

    def rejected(self, hardening, round_id, role=ORCHESTRATOR):
        trace = next(t for t in hardening.traces(round_id) if t['agent_role'] == role)
        return [e['data']['error'] for e in trace['events'] if e['kind'] == 'tool_rejected']


def decisions(fixes=(), skipped=()):
    """submit_plan's single list: fixes in execution order, then deferrals."""
    return ([dict(control_id=c, decision='fix', action_id=a, reason_code=r) for c, a, r in fixes]
            + [dict(control_id=c, decision='defer', reason_code=r) for c, r in skipped])


def plan(t, fixes=(), skipped=()):
    return call('submit_plan', t, decisions=decisions(fixes, skipped))


# The lab VM's fixable findings; NLA policy is Not configured there (Non-Compliant under decision D5).
DEFER_ALL = [(c, 'lower_priority') for c in ('1.2.2', '2.3.10.3', '1.1.1', '1.1.3', '18.10.57.3.9.4')]


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
        # Scans and the runner's before/after evidence all arrived over WinRM: none is stored as an imported file.
        modes = {r.evidence.mode.value for row in self.store.imports.recent()
                 for r in self.store.imports.get(row['digest']).assessment.results}
        self.assertEqual(modes, {'Live'})
        changes = {c['control_id']: c['change'] for c in
                   hardening.changes(result['framework_run_id'], executed['verification_run_id'])}
        self.assertEqual(changes['1.2.2'], 'Improvement')
        self.assertEqual(changes['1.2.1'], 'Unknown -> Compliant')
        self.assertEqual(changes['1.1.1'], 'Unchanged')
        # Remediation phase: the Orchestrator delegated the Remediation Agent and a verification scan, then decided.
        phase = {t['agent_role']: t for t in hardening.traces(executed['round_id'])}
        self.assertEqual(set(phase), {ORCHESTRATOR, REMEDIATION, SCANNER})
        self.assertEqual(self.calls(phase[REMEDIATION]), [('tool', 'list_approved'), ('tool', 'precheck'),
                                                          ('tool', 'execute_fixes'), ('tool', 'report_results')])
        self.assertEqual(self.calls(phase[ORCHESTRATOR]), [('tool', 'delegate_remediation'),
                                                           ('tool', 'delegate_verification'), ('tool', 'submit_review')])
        self.assertEqual(executed['outcome']['outcome'], 'next_round')
        self.assertEqual(executed['outcome']['reason'], 'Executed: 1.2.2 (Verified compliant). Verification rescan by '
                         'the Scanner Agent: no regressions. Next step (next round): fixable findings remain (1.1.1, '
                         '1.1.3, 18.10.57.3.9.4, 2.3.10.3); run a new round to review them.')
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
        others = [('2.3.10.3', 'lower_priority'), ('1.1.1', 'lower_priority'), ('1.1.3', 'lower_priority'),
                  ('18.10.57.3.9.4', 'needs_review')]
        hardening = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.1', 'REM-1.2.1', 'high_risk'), ('1.2.2', 'REM-1.2.2', 'unblocks_other')], skipped=others),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')], skipped=[('1.2.2', 'lower_priority')] + others)])
        result = hardening.run_round()
        errors = self.rejected(hardening, result['round_id'])
        self.assertEqual(errors[0], 'REM-1.2.1 cannot fix 1.2.1 now; it waits for 1.2.2 to be compliant')
        self.assertEqual(errors[1], '1.2.2 has more than one decision: give each finding exactly one, fix or defer')
        self.assertEqual(self.store.for_run(result['framework_run_id']), [])

    def test_blocked_finding_is_deferred_and_its_prerequisite_proposed(self):
        state = dict(LAB_STATE, **{'1.2.1': 5})
        t = 'windows:' + target().machine_uuid
        result = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')],
                 skipped=[('1.2.1', 'waits_for_prerequisite'), ('2.3.10.3', 'lower_priority'),
                          ('1.1.1', 'lower_priority'), ('1.1.3', 'lower_priority'),
                          ('18.10.57.3.9.4', 'needs_review')])]).run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        proposals = self.store.for_run(result['framework_run_id'])
        self.assertEqual([p['proposal']['control_id'] for p in proposals], ['1.2.2'])
        # 1.2.1 is a finding blocked by 1.2.2; 1.2.4 is still a gap expected to resolve with it.
        self.assertEqual(proposals[0]['proposal']['reason'], 'Prerequisite that unblocks 1.2.1, 1.2.4 (unblocks_other)')
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

    def test_scanner_may_read_coverage_again_after_a_rescan(self):
        t = 'windows:' + target().machine_uuid
        scanner = [call('scan_target', t), call('read_coverage', t), call('rescan', t, reason='Error on 1.1.5'),
                   call('read_coverage', t), call('handoff_analysis', t, reason='Error persists after one rescan.')]
        result = self.hardening(FakeVm(error_controls=('1.1.5',)), [call('delegate_scanner', t),
            call('delegate_analysis', t), plan(t, skipped=DEFER_ALL)], scanner=scanner).run_round()
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')

    def test_a_rescan_in_the_same_round_is_not_history_for_the_drift_factor(self):
        # The round's own first scan, replaced by the Scanner's rescan, must not count as an earlier assessment
        # (otherwise every finding gets D=3 and 1.2.2 scores 73, not 69).
        t = 'windows:' + target().machine_uuid
        scanner = [call('scan_target', t), call('read_coverage', t), call('rescan', t, reason='Error on 1.1.5'),
                   call('read_coverage', t), call('handoff_analysis', t, reason='ok')]
        hardening = self.hardening(FakeVm(error_controls=('1.1.5',)), [call('delegate_scanner', t),
            call('delegate_analysis', t), plan(t, skipped=DEFER_ALL)], scanner=scanner)
        result = hardening.run_round()
        stored = self.store.rounds(result['session_id'])[0]
        self.assertEqual(len(stored['scanned_runs']), 2)
        self.assertEqual({f['factors']['D'] for f in stored['analysis']['ranked']}, {1})
        self.assertEqual(next(f['score'] for f in stored['analysis']['ranked'] if f['control_id'] == '1.2.2'), 69)
        # Later readers (Overview, the next round) skip the replaced scan as well.
        self.assertEqual(hardening.history.previous_records(result['framework_run_id']), [])
        follow_up = self.standard_round(FakeVm()).run_round()  # A real earlier round still counts: D=3.
        ranked = self.store.rounds(follow_up['session_id'])[0]['analysis']['ranked']
        self.assertEqual(next(f['factors']['D'] for f in ranked if f['control_id'] == '1.2.2'), 3)

    def test_a_scanner_that_stops_without_handoff_is_reported_truthfully_and_can_be_redelegated(self):
        t = 'windows:' + target().machine_uuid
        silent = {'content': '', 'tool_calls': []}
        stalled = [call('scan_target', t), call('read_coverage', t), silent, silent]
        result = self.hardening(FakeVm(), [call('delegate_scanner', t), plan(t)], scanner=stalled).run_round()
        self.assertEqual(result['outcome']['outcome'], 'scan_not_handed_off')  # Not "could not collect evidence".
        self.assertTrue(result['outcome']['reason'].startswith('The Scanner Agent stopped without handing off'))
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_scanner', t),
                                              call('delegate_analysis', t), plan(t, skipped=DEFER_ALL)],
                                   scanner=stalled + [call('scan_target', t), call('read_coverage', t),
                                                      call('handoff_analysis', t, reason='ok')])
        result = hardening.run_round()
        self.assertEqual(len(self.trace(hardening, result['round_id'], SCANNER)), 2)
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')
        delegations = [e['data']['result'] for e in self.trace(hardening, result['round_id'], ORCHESTRATOR)[0]['events']
                       if e['kind'] == 'tool' and e['data']['name'] == 'delegate_scanner']
        # The Orchestrator is told it may retry a stalled Scanner, and only then.
        self.assertEqual([d.get('retry_allowed') for d in delegations], [True, None])

    def test_a_fix_that_resolves_gaps_may_be_given_unblocks_other(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')], skipped=DEFER_ALL[1:])])
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        self.assertEqual(self.store.for_run(result['framework_run_id'])[0]['proposal']['reason'],
                         'Prerequisite that unblocks 1.2.1, 1.2.4 (unblocks_other)')

    def test_models_receive_compact_views(self):
        result = self.standard_round(FakeVm()).run_round()
        hardening = self.standard_round(FakeVm())
        trace = next(t for t in AgenticHardening.traces(hardening, result['round_id']) if t['agent_role'] == ORCHESTRATOR)
        analysis = next(e['data']['result'] for e in trace['events'] if e['data'].get('name') == 'delegate_analysis')
        self.assertEqual(set(analysis), {'agent', 'status', 'must_decide', 'no_action', 'gaps', 'attention',
                                         'rescan_requested'})
        self.assertEqual(analysis['must_decide'][0], dict(control_id='1.2.2', level='High', score=69, actions=['REM-1.2.2'],
            fix_codes=['high_risk', 'unblocks_other', 'low_impact'], defer_codes=['needs_review', 'lower_priority']))
        moderate = next(d for d in analysis['must_decide'] if d['control_id'] == '1.1.3')
        self.assertEqual(moderate['fix_codes'], ['low_impact'])  # Only codes that are true for this finding.


class OrchestratorAccountabilityTests(AgenticTestCase):
    def test_fixes_are_ranked_by_risk_score_whatever_order_the_orchestrator_lists_them(self):
        # The Orchestrator decides which findings to fix; code ranks them, highest risk first.
        t = 'windows:' + target().machine_uuid
        result = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t), plan(t,
            fixes=[('1.1.3', 'REM-1.1.3', 'low_impact'), ('1.1.1', 'REM-1.1.1', 'low_impact'),
                   ('1.2.2', 'REM-1.2.2', 'high_risk')],
            skipped=[('2.3.10.3', 'needs_review'), ('18.10.57.3.9.4', 'needs_review')])]).run_round()
        proposals = [p['proposal'] for p in self.store.for_run(result['framework_run_id'])]
        self.assertEqual([(p['rank'], p['control_id'], p['risk_score']) for p in proposals],
                         [(1, '1.2.2', 69), (2, '1.1.1', 63), (3, '1.1.3', 57)])
        self.assertIn('Proposed for your approval, in order: 1.2.2 (High 69), 1.1.1 (High 63), 1.1.3 (Moderate 57).',
                      result['outcome']['reason'])

    def test_summary_is_written_from_records_and_lists_every_decision(self):
        result = self.standard_round(FakeVm()).run_round()
        outcome = result['outcome']
        self.assertNotIn('model_commentary', outcome)
        self.assertEqual(outcome['reason'], 'Proposed for your approval, in order: 1.2.2 (High 69), 1.1.1 (High 63). '
                         'Deferred by the Orchestrator: 2.3.10.3, 1.1.3, 18.10.57.3.9.4. '
                         'No library action (manual review): 9.3.1. 2 Unknown/Error gap(s) not scored. '
                         'Nothing has been approved or executed.')
        self.assertEqual([s['control_id'] for s in outcome['skipped']], ['2.3.10.3', '1.1.3', '18.10.57.3.9.4'])
        reasons = [p['proposal']['reason'] for p in self.store.for_run(result['framework_run_id'])]
        self.assertEqual(reasons, ['High-priority finding (high_risk)', 'Low operational impact (low_impact)'])

    def test_a_decision_comment_is_kept_apart_from_the_approved_request(self):
        import sqlite3
        from hardening.round_report import round_report
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        first, second = self.store.for_run(result['framework_run_id'])
        request = self.store.decide(first['proposal']['request_id'], approve=True, operator='admin01',
                                    comment='Saturday window')
        self.store.decide(second['proposal']['request_id'], approve=False, operator='admin01', comment='Breaks payroll')
        first, second = self.store.for_run(result['framework_run_id'])
        self.assertEqual((first['comment'], second['comment']), ('Saturday window', 'Breaks payroll'))
        self.assertNotIn(b'Saturday', request)  # The request the VM runner checks by hash is unchanged.
        for sql in ("UPDATE rem_comments SET payload='{}'", 'DELETE FROM rem_comments'):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError), self.store._connection() as db:
                db.execute(sql)
        rounds = self.store.rounds(result['session_id'])
        self.assertIn('Breaks payroll', round_report(hardening, rounds, rounds[0]))

    def test_unknown_reason_code_is_rejected_with_the_allowed_list(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'because_i_said_so')], skipped=DEFER_ALL[1:]),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=DEFER_ALL[1:])])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']), [
            'because_i_said_so is not a fix reason_code; use one of high_risk, improves_detection, low_impact, unblocks_other'])
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')

    def test_a_fix_with_a_false_reason_is_refused_but_a_left_out_finding_is_deferred_by_code(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.1.3', 'REM-1.1.3', 'high_risk')], skipped=DEFER_ALL[:3] + DEFER_ALL[4:]),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=[('1.1.1', 'lower_priority')])])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']),
                         ['reason_code high_risk does not fit 1.1.3 (Moderate 57)'])  # A fix stays strict.
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        self.assertEqual([p['proposal']['control_id'] for p in self.store.for_run(result['framework_run_id'])], ['1.2.2'])
        codes = {s['control_id']: s['reason_code'] for s in result['outcome']['skipped']}
        self.assertEqual(codes, {'1.1.1': 'lower_priority', '2.3.10.3': 'not_decided', '18.10.57.3.9.4': 'not_decided',
                                 '1.1.3': 'not_decided'})
        self.assertIn('Deferred by the Orchestrator: 1.1.1. Left out of the plan, so deferred by code: 2.3.10.3, '
                      '18.10.57.3.9.4, 1.1.3.', result['outcome']['reason'])
        undecided = next(s for s in result['outcome']['skipped'] if s['control_id'] == '1.1.3')
        self.assertEqual(undecided['reason'], 'Not decided by the Orchestrator this round; deferred by code')

    def test_a_deferral_with_a_code_that_does_not_fit_is_recorded_as_not_decided(self):
        # low_impact is a fix code; given as a defer code it must not fail the whole plan.
        t = 'windows:' + target().machine_uuid
        result = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')],
                 skipped=[('1.1.3', 'low_impact'), ('1.1.1', 'keeps_reverting'), ('2.3.10.3', 'made_up'),
                          ('18.10.57.3.9.4', 'needs_review')])]).run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        codes = {s['control_id']: s['reason_code'] for s in result['outcome']['skipped']}
        self.assertEqual(codes, {'1.1.3': 'not_decided', '1.1.1': 'not_decided', '2.3.10.3': 'not_decided',
                                 '18.10.57.3.9.4': 'needs_review'})
        self.assertIn('Deferred with a reason that did not fit, so recorded as not decided: 1.1.3 (low_impact), '
                      '1.1.1 (keeps_reverting), 2.3.10.3 (unknown code).', result['outcome']['reason'])

    def test_not_decided_is_never_offered_to_the_model(self):
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        trace = self.trace(hardening, result['round_id'], ORCHESTRATOR)[0]
        handoff = next(e['data']['result'] for e in trace['events']
                       if e['kind'] == 'tool' and e['data']['name'] == 'delegate_analysis')
        self.assertFalse(any('not_decided' in d['defer_codes'] for d in handoff['must_decide']))

    def test_argument_errors_name_what_was_wrong(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            call('submit_plan', t, fixes=[], reason='done'), plan(t, skipped=DEFER_ALL)])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']),
                         ['submit_plan needs exactly: decisions, target_id; received: fixes, reason, target_id'])
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')  # One correction, then success.

    def test_skipping_a_gap_is_ignored_and_recorded_but_fixing_one_is_refused(self):
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=DEFER_ALL + [('1.2.1', 'waits_for_prerequisite')])])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']), [])
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')
        self.assertIn('Ignored skip entries for controls with nothing to decide: 1.2.1.', result['outcome']['reason'])
        self.assertNotIn('1.2.1', [s['control_id'] for s in result['outcome']['skipped']])

    def test_an_agent_that_answers_without_a_tool_call_gets_one_reminder(self):
        t = 'windows:' + target().machine_uuid
        silent = {'content': '', 'tool_calls': []}
        analysis = [silent, call('score_findings', t), silent, silent]  # Second silence after the nudge ends it.
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=DEFER_ALL)], analysis=analysis)
        result = hardening.run_round()
        trace = self.trace(hardening, result['round_id'], ANALYSIS)[0]
        self.assertEqual([e['data']['available'] for e in trace['events'] if e['kind'] == 'nudge'], [['score_findings']])
        self.assertEqual(self.calls(trace), [('tool', 'score_findings')])
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')  # Ranking survives the silent agent.


class ExpandedControlRoundTests(AgenticTestCase):
    def test_default_audit_policy_is_ranked_proposed_and_verified_by_include_rule(self):
        # Windows Server default audit: Success only for these subcategories.
        state = dict(LAB_STATE, **{'17.1.1': 1, '17.5.1': 1, '9.2.6': None, '18.10.57.3.9.3': None})
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('17.5.1', 'REM-17.5.1', 'improves_detection')],
                 skipped=[(c, 'lower_priority') for c in ('1.2.2', '2.3.10.3', '1.1.1', '1.1.3', '17.1.1', '18.10.57.3.9.4',
                                                       '18.10.57.3.9.3')])])
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

    def test_unconfigured_firewall_logging_is_proposed_and_verified(self):
        # Not configured (D5) is Non-Compliant and fixable: the logging action only records traffic.
        state = dict(LAB_STATE, **{'9.3.6': None})
        t = 'windows:' + target().machine_uuid
        vm = FakeVm(state)
        hardening = self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('9.3.6', 'REM-9.3.6', 'improves_detection')],
                 skipped=[(c, 'lower_priority') for c in ('1.2.2', '2.3.10.3', '1.1.1', '1.1.3', '18.10.57.3.9.4')])])
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        trace = self.trace(hardening, result['round_id'], ORCHESTRATOR)[0]
        analysis = next(e['data']['result'] for e in trace['events'] if e['data'].get('name') == 'delegate_analysis')
        logging = next(d for d in analysis['must_decide'] if d['control_id'] == '9.3.6')
        self.assertEqual(logging['actions'], ['REM-9.3.6'])
        self.assertIn('improves_detection', logging['fix_codes'])
        self.assertNotIn('9.3.1', [d['control_id'] for d in analysis['must_decide']])  # Firewall on/off: no action.
        proposal = self.store.for_run(result['framework_run_id'])[0]['proposal']
        self.assertEqual((proposal['action_id'], proposal['expected_before']), ('REM-9.3.6', None))
        self.store.decide(proposal['request_id'], approve=True, operator='admin01')
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual(executed['verdicts'][0]['verdict'], 'Verified compliant')
        self.assertEqual(vm.writes, ['9.3.6'])
        after = self.runtime.imports.get(self.runtime.get(executed['verification_run_id']).evidence_sha256)
        self.assertEqual(next(r.status for r in after.assessment.results if r.control.control_id == '9.3.6'),
                         Status.COMPLIANT)


class NotConfiguredPolicyTests(AgenticTestCase):
    """Decision D5: an absent Group Policy value is Non-Compliant and, if in the library, fixable."""

    def test_not_configured_nla_policy_is_fixed_from_absent_to_set_and_verified(self):
        t = 'windows:' + target().machine_uuid
        vm = FakeVm()
        hardening = self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('18.10.57.3.9.4', 'REM-18.10.57.3.9.4', 'low_impact')],
                 skipped=[(c, 'lower_priority') for c in ('1.2.2', '2.3.10.3', '1.1.1', '1.1.3')])])
        result = hardening.run_round()
        proposal = self.store.for_run(result['framework_run_id'])[0]['proposal']
        self.assertIsNone(proposal['expected_before'])  # Approved precondition: still Not configured.
        self.store.decide(proposal['request_id'], approve=True, operator='admin01')
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual(executed['verdicts'][0]['verdict'], 'Verified compliant')
        self.assertEqual(vm.writes, ['18.10.57.3.9.4'])
        change = next(c for c in hardening.changes(result['framework_run_id'], executed['verification_run_id'])
                      if c['control_id'] == '18.10.57.3.9.4')
        self.assertEqual((change['before'], change['after'], change['change']), (None, 1, 'Improvement'))

    def test_firewall_policy_findings_are_scored_but_never_fixable(self):
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        self.assertIn('No library action (manual review): 9.3.1.', result['outcome']['reason'])
        trace = next(x for x in hardening.traces(result['round_id']) if x['agent_role'] == ORCHESTRATOR)
        analysis = next(e['data']['result'] for e in trace['events'] if e['data'].get('name') == 'delegate_analysis')
        self.assertNotIn('9.3.1', [d['control_id'] for d in analysis['must_decide']])

    def test_effective_protection_lowers_exposure_only_when_actually_on(self):
        record = lambda vm: self.runtime.imports.get(LiveScanner(self.runtime, target(), session_factory=vm)
                                                     .request(target().hostname, target().machine_uuid)['evidence_sha256'])
        on = {f.control_id: f for f in analyse(record(FakeVm()))}
        self.assertEqual(on['9.3.1'].factors['E'], 1)
        self.assertIn('effectively enabled', on['9.3.1'].exposure_reason)
        off = {f.control_id: f for f in analyse(record(FakeVm(firewall=False)))}
        self.assertEqual((off['9.3.1'].factors['E'], off['9.3.1'].score, off['9.3.1'].level), (4, 80, 'Critical'))


class PlanDecisionTests(AgenticTestCase):
    """The shape of submit_plan decisions is checked before anything is stored."""

    def test_decision_entries_are_checked(self):
        from hardening.agentic import check_decisions
        for entry, message in ((dict(control_id='1.2.2', decision='fix', reason_code='high_risk'), 'a fix needs action_id'),
                               (dict(control_id='1.2.2', decision='skip', reason_code='lower_priority'), 'decision must be fix or defer'),
                               (dict(control_id='1.2.2', reason_code='lower_priority'), 'needs control_id, decision and reason_code')):
            with self.assertRaisesRegex(ValueError, message):
                check_decisions([entry])
        defer = dict(control_id='1.2.2', decision='defer', reason_code='lower_priority', action_id='REM-1.2.2')
        self.assertEqual(check_decisions([defer]), [defer])  # An action on a deferral is harmless and ignored.


class AnalysisAgentTests(AgenticTestCase):
    """The Analysis Agent chooses what to investigate and what to flag; it can never change a number (D2)."""

    def test_agent_investigates_flags_and_triages_with_checked_codes(self):
        t = 'windows:' + target().machine_uuid
        analysis = [call('score_findings', t), call('inspect_finding', t, control_id='1.2.2'),
                    call('check_history', t, control_id='1.2.2'),
                    call('submit_analysis', t, unblocks_other=['1.2.2'], manual_fix_needed=['9.3.1'],
                         gap_triage=[dict(control_id='1.2.1', triage_code='resolves_with_prerequisite'),
                                     dict(control_id='1.2.4', triage_code='resolves_with_prerequisite')])]
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=DEFER_ALL)], analysis=analysis)
        result = hardening.run_round()
        trace = self.trace(hardening, result['round_id'], ANALYSIS)[0]
        self.assertEqual(self.calls(trace), [('tool', 'score_findings'), ('tool', 'inspect_finding'),
                                             ('tool', 'check_history'), ('tool', 'submit_analysis')])
        self.assertIn('Analysis Agent flags for attention: 1.2.2 (fixing it unblocks 1.2.1, 1.2.4); '
                      '9.3.1 (no library action: needs a manual fix).', result['outcome']['reason'])
        stored = self.store.rounds(result['session_id'])[0]
        self.assertEqual([g['reason'] for g in stored['analysis_outcome']['gap_triage']],
                         ['expected to resolve once 1.2.2 is fixed'] * 2)
        self.assertEqual((stored['analysis']['ranked'][0]['control_id'], stored['analysis']['ranked'][0]['score']),
                         ('1.2.2', 69))

    def test_codes_must_fit_facts_and_the_ranking_survives_a_failed_agent(self):
        from hardening.agentic import AnalysisTools
        self.assertEqual(AnalysisTools.names, ('score_findings', 'inspect_finding', 'check_history', 'submit_analysis'))
        t = 'windows:' + target().machine_uuid
        analysis = [call('score_findings', t),
                    call('submit_analysis', t, high_risk=['1.1.3'],
                         gap_triage=[]),
                    call('submit_analysis', t, gap_triage=[dict(control_id='1.2.1', triage_code='rescan')])]
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=DEFER_ALL[1:])], analysis=analysis)
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id'], ANALYSIS), [
            'Every gap needs a triage_code; missing: 1.2.1, 1.2.4',
            'triage_code rescan does not fit 1.2.1; true codes: resolves_with_prerequisite, manual_review'])
        stored = self.store.rounds(result['session_id'])[0]
        self.assertEqual(stored['analysis_outcome']['outcome'], 'incomplete')
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')  # Deterministic ranking still available.
        self.assertEqual(self.store.for_run(result['framework_run_id'])[0]['proposal']['risk_score'], 69)

    def test_investigation_is_bounded_so_the_agent_must_decide(self):
        t = 'windows:' + target().machine_uuid
        offered = []

        class Recording(MockClient):
            def chat(self, messages, tools, *, timeout):
                offered.append([s['function']['name'] for s in tools])
                return super().chat(messages, tools, timeout=timeout)
        analysis = [call('score_findings', t)] + [call('inspect_finding', t, control_id=c)
                                                  for c in ('1.2.2', '1.1.1', '2.3.10.3')]
        analysis.append(call('submit_analysis', t, gap_triage=[
            dict(control_id='1.2.1', triage_code='manual_review'), dict(control_id='1.2.4', triage_code='manual_review')]))
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=DEFER_ALL)], analysis=Recording(analysis))
        result = hardening.run_round()
        trace = self.trace(hardening, result['round_id'], ANALYSIS)[0]
        inspections = [e['data']['result']['investigations_left'] for e in trace['events']
                       if e['kind'] == 'tool' and e['data']['name'] == 'inspect_finding']
        self.assertEqual(inspections, [1, 0])
        # Only valid tools are offered; a call to a hidden one is still refused by code.
        self.assertEqual(offered, [['score_findings'], ['inspect_finding', 'check_history', 'submit_analysis'],
                                   ['inspect_finding', 'check_history', 'submit_analysis'], ['submit_analysis'],
                                   ['submit_analysis']])
        self.assertEqual(self.rejected(hardening, result['round_id'], ANALYSIS),
                         ['Investigation limit (2) reached; call submit_analysis now'])
        self.assertEqual(self.store.rounds(result['session_id'])[0]['analysis_outcome']['outcome'], 'analysis_complete')

    def test_flags_beyond_three_are_checked_then_dropped_not_fatal(self):
        t = 'windows:' + target().machine_uuid
        analysis = [call('score_findings', t), call('submit_analysis', t, manual_fix_needed=['9.3.1'],
                    high_risk=['1.2.2', '1.1.1', '2.3.10.3'],
                    gap_triage=[dict(control_id=g, triage_code='manual_review') for g in ('1.2.1', '1.2.4')])]
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=DEFER_ALL)], analysis=analysis)
        result = hardening.run_round()
        stored = self.store.rounds(result['session_id'])[0]['analysis_outcome']
        # Kept in code order, most specific first (regression, unblocks_other, manual_fix_needed, high_risk).
        self.assertEqual([a['control_id'] for a in stored['attention']], ['9.3.1', '1.2.2', '1.1.1'])
        self.assertIn('Further flags beyond 3 not shown: 2.3.10.3.', stored['reason'])

    def test_only_findings_with_a_true_attention_code_are_offered_for_flagging(self):
        t = 'windows:' + target().machine_uuid
        offered = []

        class Recording(MockClient):
            def chat(self, messages, tools, *, timeout):
                submit = next((s for s in tools if s['function']['name'] == 'submit_analysis'), None)
                if submit:
                    offered.append(submit['function']['parameters']['properties'])
                return super().chat(messages, tools, timeout=timeout)
        analysis = Recording([call('score_findings', t), call('submit_analysis', t, gap_triage=[
            dict(control_id=g, triage_code='manual_review') for g in ('1.2.1', '1.2.4')])])
        self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                  plan(t, skipped=DEFER_ALL)], analysis=analysis).run_round()
        enums = {code: offered[-1][code]['items']['enum'] for code in ATTENTION if code in offered[-1]}
        self.assertNotIn('regression', enums)  # No history in this test, so no finding regressed.
        self.assertIn('1.2.2', enums['high_risk'])
        self.assertEqual(enums['unblocks_other'], ['1.2.2'])  # 1.2.1 and 1.2.4 wait for it.
        self.assertIn('9.3.1', enums['manual_fix_needed'])  # No library action.
        self.assertNotIn('17.1.1', enums['manual_fix_needed'])  # Audit controls have one: no false pairing offered.
        self.assertFalse(any('1.1.3' in controls for controls in enums.values()))  # No true code at all.

    def test_a_flag_that_does_not_fit_is_discarded_and_recorded_never_shown(self):
        t = 'windows:' + target().machine_uuid
        analysis = [call('score_findings', t), call('submit_analysis', t, regression=['1.2.2'], high_risk=['1.1.3', '1.2.2'],
                    unblocks_other=['1.2.2'], manual_fix_needed=['17.1.1'],
                    gap_triage=[dict(control_id=g, triage_code='manual_review') for g in ('1.2.1', '1.2.4')])]
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=DEFER_ALL)], analysis=analysis)
        result = hardening.run_round()
        stored = self.store.rounds(result['session_id'])[0]['analysis_outcome']
        self.assertEqual(stored['outcome'], 'analysis_complete')
        self.assertEqual([a['control_id'] for a in stored['attention']], ['1.2.2'])  # Only the fitting flag.
        # Including a code that was not offered (nothing regressed); attention never fails the decision.
        self.assertEqual(stored['discarded_flags'], [['1.2.2', 'regression'], ['17.1.1', 'manual_fix_needed'],
                                                     ['1.1.3', 'high_risk']])
        self.assertIn('Analysis Agent flags for attention: 1.2.2 (fixing it unblocks 1.2.1, 1.2.4).',
                      result['outcome']['reason'])

    def test_delegate_analysis_may_name_the_current_scan_only(self):
        t = 'windows:' + target().machine_uuid

        class Naming:
            model, provenance = 'mock-model', 'Mock model (test only)'
            steps = []

            def chat(self, messages, tools, *, timeout):
                self.steps.append(1)
                if len(self.steps) == 1:
                    return call('delegate_scanner', t)
                if len(self.steps) == 2:
                    return call('delegate_analysis', t, framework_run_id='f' * 32)
                if len(self.steps) == 3:
                    handoff = next(json.loads(m['content'])['handoff'] for m in messages
                                   if m['role'] == 'tool' and 'handoff' in m['content'])
                    return call('delegate_analysis', t, framework_run_id=handoff['framework_run_id'])
                return plan(t, skipped=DEFER_ALL)
        hardening = self.hardening(FakeVm(), [])
        base, naming = hardening.client_factory, Naming()
        hardening.client_factory = lambda role: naming if role == ORCHESTRATOR else base(role)
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']),
                         ['framework_run_id must be the current scan ' + result['framework_run_id']])
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')

    def test_rescan_request_sends_the_scanner_back_once(self):
        t = 'windows:' + target().machine_uuid
        def triage(code):
            return [dict(control_id='1.1.5', triage_code=code), dict(control_id='1.2.1', triage_code='manual_review'),
                    dict(control_id='1.2.4', triage_code='manual_review')]
        analysis = [call('score_findings', t), call('submit_analysis', t, gap_triage=triage('rescan')),
                    call('score_findings', t), call('submit_analysis', t, gap_triage=triage('manual_review'))]
        orchestrator = [call('delegate_scanner', t), call('delegate_analysis', t), call('delegate_scanner', t),
                        call('delegate_analysis', t), call('delegate_scanner', t), plan(t, skipped=DEFER_ALL)]
        hardening = self.hardening(FakeVm(error_controls=('1.1.5',)), orchestrator, analysis=analysis)
        result = hardening.run_round()
        self.assertEqual(len(self.trace(hardening, result['round_id'], SCANNER)), 2)
        self.assertEqual(len(self.trace(hardening, result['round_id'], ANALYSIS)), 2)
        self.assertEqual(self.rejected(hardening, result['round_id']), [
            'The Scanner runs once per round, and once more only when the Analysis Agent requests a rescan'])
        self.assertEqual(len(hardening.scanned_runs), 2)
        self.assertEqual(result['framework_run_id'], hardening.scanned_runs[-1])  # The plan uses the fresh scan.
        self.assertEqual(result['outcome']['outcome'], 'no_fix_proposed')


class RemediationPhaseTests(AgenticTestCase):
    """Remediation Agent decisions and the Orchestrator's next-step decision after verification."""

    def test_agent_skips_a_changed_request_and_executes_the_ready_one(self):
        vm = FakeVm()
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        vm.values['1.1.1'] = 5  # Someone changed password history after approval.
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual(vm.writes, ['1.2.2'])
        self.assertEqual([v['control_id'] for v in executed['verdicts']], ['1.2.2'])
        self.assertIn('Skipped by the Remediation Agent: 1.1.1 (value changed since approval; a new scan and approval '
                      'are needed).', executed['outcome']['reason'])
        skipped = self.store.for_run(result['framework_run_id'])[1]
        self.assertTrue(skipped['verdict'].startswith('Refused before execution: skipped by the Remediation Agent'))
        self.assertEqual(executed['outcome']['outcome'], 'next_round')

    def test_agent_cannot_act_before_precheck_or_on_unapproved_requests_then_fallback_runs(self):
        def impatient(seen, names):
            if not seen:
                return 'list_approved', {}
            ids = [r['control_id'] for r in seen[0][1]['requests']]
            return 'execute_fixes', dict(control_ids=[ids[0] if len(seen) == 1 else 'f' * 32])
        vm = FakeVm()
        hardening = self.standard_round(vm, remediation=Responsive(impatient))
        result = hardening.run_round()
        first = self.store.for_run(result['framework_run_id'])[0]['proposal']['request_id']
        self.store.decide(first, approve=True, operator='admin01')
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual(self.rejected(hardening, executed['round_id'], REMEDIATION),
                         ['Call precheck before executing', 'Not an open approved request: ' + 'f' * 32])
        self.assertEqual(vm.writes, [])
        self.assertEqual((executed['outcome']['outcome'], executed['outcome']['reason_code']),
                         ('remediation_review', 'remediation_incomplete'))
        fallback = hardening.execute_approved(result['session_id'], deterministic=True)
        self.assertEqual(([v['verdict'] for v in fallback['verdicts']], fallback['outcome']['outcome']),
                         (['Verified compliant'], 'fallback'))
        self.assertIsNotNone(fallback['verification_run_id'])

    def test_execution_without_ai_applies_the_agents_precheck(self):
        # The fallback once ran every approval in rank order with no precheck; it now closes what the agent would skip.
        vm = FakeVm(dict(LAB_STATE, **{'1.2.2': 3, '1.2.1': 5}))  # Threshold compliant, so 1.2.1 is fixable.
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t), plan(t, fixes=[
            ('1.2.1', 'REM-1.2.1', 'low_impact'), ('1.1.1', 'REM-1.1.1', 'low_impact'), ('1.1.3', 'REM-1.1.3', 'low_impact')])])
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        vm.values.update({'1.2.2': 0, '1.1.1': 5})  # The prerequisite reverted and 1.1.1 changed after approval.
        executed = hardening.execute_approved(result['session_id'], deterministic=True)
        self.assertEqual(vm.writes, ['1.1.3'])
        verdicts = {v['control_id']: v['verdict'] for v in executed['verdicts']}
        self.assertEqual(verdicts['1.1.3'], 'Verified compliant')
        self.assertIn('prerequisite control is not compliant yet (1.2.2)', verdicts['1.2.1'])
        self.assertIn('value changed since approval', verdicts['1.1.1'])
        self.assertTrue(all(r['verdict'] for r in self.store.for_run(result['framework_run_id'])))  # Closed for good.

    def test_execution_without_ai_executes_nothing_when_the_vm_cannot_be_prechecked(self):
        vm = FakeVm()
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        hardening.scanner.session_factory = lambda _: (_ for _ in ()).throw(ConnectionError('Connection refused'))
        executed = hardening.execute_approved(result['session_id'], deterministic=True)
        self.assertEqual(vm.writes, [])
        self.assertTrue(executed['verdicts'][0]['verdict'].startswith('Refused before execution: the VM could not'))
        self.assertTrue(all(r['verdict'] is None for r in self.store.for_run(result['framework_run_id'])))  # Still open.

    def test_uncertain_outcome_stops_the_agent_and_forces_review(self):
        vm = FakeVm()
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        original = vm.run

        def drop(script, parameters=None):
            if script == RUNNER.read_text(encoding='utf-8-sig'):
                raise ConnectionError('Connection reset')
            return original(script, parameters)
        vm.run = drop
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual([v['control_id'] for v in executed['verdicts']], ['1.2.2'])  # 1.1.1 never attempted.
        self.assertEqual((executed['outcome']['outcome'], executed['outcome']['reason_code']),
                         ('remediation_review', 'uncertain_outcome'))
        self.assertIn('Not attempted (uncertain outcome): 1.1.1.', executed['outcome']['reason'])
        self.assertIsNotNone(executed['verification_run_id'])  # The VM state was observed again.
        self.assertEqual(vm.writes, [])
        verification = self.store.rounds(result['session_id'])[-1]
        events = next(t for t in hardening.traces(verification['round_id']) if t['agent_role'] == REMEDIATION)['events']
        stopped = next(e['data']['result'] for e in events if e['kind'] == 'tool' and e['data']['name'] == 'execute_fixes')
        self.assertTrue(stopped['must_stop'])
        self.assertIn('target_id only', stopped['next'])  # The model need not copy the results along.

    def test_next_step_codes_are_checked_and_unblocked_findings_lead_to_a_new_round(self):
        state = dict(LAB_STATE, **{'1.2.1': 5})  # Duration non-compliant and blocked while the threshold is 0.
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(state), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')],
                 skipped=[('1.2.1', 'waits_for_prerequisite'), ('2.3.10.3', 'lower_priority'),
                          ('1.1.1', 'lower_priority'), ('1.1.3', 'lower_priority'), ('18.10.57.3.9.4', 'needs_review')])],
            review=[call('delegate_remediation', t), call('delegate_verification', t),
                    call('submit_review', t, next_step='finish', reason_code='nothing_fixable'),
                    call('submit_review', t, next_step='next_round', reason_code='unblocked_findings')])
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual(self.rejected(hardening, executed['round_id']), [
            'reason_code nothing_fixable does not fit finish for these results; true codes: finish: all_verified; '
            'next_round: unblocked_findings, remaining_findings'])
        self.assertEqual(executed['outcome']['outcome'], 'next_round')
        self.assertTrue(executed['outcome']['reason'].endswith('the fixes unblocked 1.2.1; run a new round to propose them.'))

    def test_orchestrator_unavailable_executes_nothing(self):
        vm = FakeVm()
        hardening = self.standard_round(vm, review=[ConnectionError('Ollama down')])
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        executed = hardening.execute_approved(result['session_id'])
        self.assertEqual((executed['outcome']['outcome'], executed['verdicts'], vm.writes), ('incomplete', [], []))
        self.assertEqual(self.store.rounds(result['session_id'])[-1]['outcome']['outcome'], 'incomplete')

    def test_a_list_with_one_unready_request_executes_nothing(self):
        def hasty(seen, names):
            done = [n for n, _ in seen]
            if 'precheck' not in done:
                return ('list_approved' if not done else 'precheck'), {}
            if 'execute_fixes' not in done:  # Includes 1.1.1, whose value changed: the whole list is refused.
                return 'execute_fixes', dict(control_ids=[r['control_id'] for r in seen[-1][1]['requests']])
            return remediation_policy(seen, names)
        vm = FakeVm()
        hardening = self.standard_round(vm, remediation=Responsive(hasty))
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        vm.values['1.1.1'] = 5
        executed = hardening.execute_approved(result['session_id'])
        rejected = self.rejected(hardening, executed['round_id'], REMEDIATION)
        self.assertEqual(rejected, ['1.1.1 is not ready (precondition_changed); use skip_fix'])
        self.assertEqual(vm.writes, ['1.2.2'])  # After the refusal the agent skipped 1.1.1 and executed 1.2.2.


COMPLIANT_LOCKOUT = {'1.2.2': 5, '1.2.1': 15, '1.2.4': 15}


class JudgementTests(AgenticTestCase):
    """Decisions with no single forced answer (J1 recurring drift, J2 isolated or systemic failure)."""

    def history(self, *states):
        """Earlier scans of the same VM, oldest first."""
        for state in states:
            LiveScanner(self.runtime, target(), session_factory=FakeVm(dict(LAB_STATE, **state))).request(
                target().hostname, target().machine_uuid)

    def test_keeps_reverting_is_learnt_from_history_and_only_then_offered_and_accepted(self):
        self.history(COMPLIANT_LOCKOUT, {}, COMPLIANT_LOCKOUT)  # Fixed, reverted, fixed; now reverted again.
        t = 'windows:' + target().machine_uuid
        offered = []

        class Recording(MockClient):
            def chat(self, messages, tools, *, timeout):
                submit = next((s for s in tools if s['function']['name'] == 'submit_analysis'), None)
                offered.append(sorted(submit['function']['parameters']['properties']) if submit else None)
                return super().chat(messages, tools, timeout=timeout)
        triage = [dict(control_id=g, triage_code='manual_review') for g in ('1.2.1', '1.2.4')]
        analysis = Recording([call('score_findings', t), call('check_history', t, control_id='1.2.2'),
                              call('submit_analysis', t, keeps_reverting=['1.2.2'], gap_triage=triage)])
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=[('1.2.2', 'keeps_reverting')] + DEFER_ALL[1:])],
                                   analysis=analysis)
        result = hardening.run_round()
        self.assertNotIn('keeps_reverting', offered[1])  # Scores alone do not reveal it...
        self.assertIn('keeps_reverting', offered[2])  # ...the agent's own history check does.
        trace = self.trace(hardening, result['round_id'], ANALYSIS)[0]
        checked = next(e['data']['result'] for e in trace['events'] if e['kind'] == 'tool'
                       and e['data']['name'] == 'check_history')
        self.assertEqual(checked['reverted_after_fix'], 2)
        self.assertIn('1.2.2 (reverted 2 times after being fixed; find what changes it back)', result['outcome']['reason'])
        self.assertEqual(result['outcome']['skipped'][0]['reason'],
                         'Reverted 2 times after earlier fixes; find what changes it back before fixing it again')
        self.assertNotIn('1.2.2', [p['proposal']['control_id'] for p in self.store.for_run(result['framework_run_id'])])

    def test_keeps_reverting_needs_the_history_check_and_two_reversions(self):
        self.history(COMPLIANT_LOCKOUT)  # One regression only: the drift scenario.
        t = 'windows:' + target().machine_uuid
        triage = [dict(control_id=g, triage_code='manual_review') for g in ('1.2.1', '1.2.4')]
        analysis = [call('score_findings', t), call('submit_analysis', t, keeps_reverting=['1.2.2'], gap_triage=triage)]
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
                                              plan(t, skipped=[('1.2.2', 'keeps_reverting')] + DEFER_ALL[1:]),
                                              plan(t, skipped=DEFER_ALL)], analysis=analysis)
        result = hardening.run_round()
        stored = self.store.rounds(result['session_id'])[0]['analysis_outcome']
        self.assertEqual(stored['discarded_flags'], [['1.2.2', 'keeps_reverting']])  # Unchecked, and only 1 reversion.
        self.assertEqual(self.rejected(hardening, result['round_id']), [])  # A deferral never fails the plan.
        self.assertEqual(result['outcome']['skipped'][0], dict(control_id='1.2.2', reason_code='not_decided',
            reason='Not decided by the Orchestrator this round; deferred by code'))
        self.assertIn('1.2.2 (keeps_reverting)', result['outcome']['reason'])
        handoff = next(e['data']['result'] for e in self.trace(hardening, result['round_id'], ORCHESTRATOR)[0]['events']
                       if e['kind'] == 'tool' and e['data']['name'] == 'delegate_analysis')
        entry = next(d for d in handoff['must_decide'] if d['control_id'] == '1.2.2')
        self.assertEqual(entry['reverted_after_fix'], 1)
        self.assertNotIn('keeps_reverting', entry['defer_codes'])

    def test_a_finding_both_fixed_and_deferred_is_refused_with_the_choice_named(self):
        self.history(COMPLIANT_LOCKOUT, {}, COMPLIANT_LOCKOUT)
        t = 'windows:' + target().machine_uuid
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'unblocks_other')], skipped=[('1.2.2', 'keeps_reverting')] + DEFER_ALL[1:]),
            plan(t, skipped=[('1.2.2', 'keeps_reverting')] + DEFER_ALL[1:])])
        result = hardening.run_round()
        self.assertEqual(self.rejected(hardening, result['round_id']),
                         ['1.2.2 has more than one decision: give each finding exactly one, fix or defer'])
        rejected = next(e['data'] for e in self.trace(hardening, result['round_id'], ORCHESTRATOR)[0]['events']
                        if e['kind'] == 'tool_rejected')
        self.assertEqual(rejected['arguments']['decisions'][0]['control_id'], '1.2.2')  # Kept for later review.
        self.assertEqual(result['outcome']['skipped'][0]['reason_code'], 'keeps_reverting')

    def test_the_plan_gets_a_third_attempt_and_no_more(self):
        t = 'windows:' + target().machine_uuid
        both = plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=DEFER_ALL)
        missing = plan(t, fixes=[('1.2.1', 'REM-1.2.1', 'high_risk')], skipped=DEFER_ALL)  # 1.2.1 is a gap.
        good = plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk')], skipped=DEFER_ALL[1:])
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t), both, missing, good])
        result = hardening.run_round()
        self.assertEqual(len(self.rejected(hardening, result['round_id'])), 2)
        self.assertEqual(result['outcome']['outcome'], 'awaiting_approval')
        wrong_code = plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'lower_priority')], skipped=DEFER_ALL[1:])
        hardening = self.hardening(FakeVm(), [call('delegate_scanner', t), call('delegate_analysis', t), both, missing,
                                              wrong_code, good])
        result = hardening.run_round()
        self.assertEqual(result['outcome']['outcome'], 'incomplete')
        self.assertIn('after 3 invalid tool calls', result['outcome']['reason'])

    def remediation_round(self, vm, remediation):
        t = 'windows:' + target().machine_uuid
        fixes = [(c, 'REM-' + c, 'low_impact') for c in ('1.2.2', '2.3.10.3', '1.1.1')]
        hardening = self.hardening(vm, [call('delegate_scanner', t), call('delegate_analysis', t),
                                        plan(t, fixes=fixes, skipped=DEFER_ALL[3:])], remediation=Responsive(remediation))
        result = hardening.run_round()
        self.approve_all(result['framework_run_id'])
        return hardening, hardening.execute_approved(result['session_id'])

    @staticmethod
    def after_pause(decision):
        def policy(seen, names):
            paused = [r for n, r in seen if n == 'execute_fixes' and r.get('paused_after_failure')]
            if paused and len([n for n, _ in seen if n == 'execute_fixes']) == 1:
                return decision(paused[0])
            return remediation_policy(seen, names)
        return policy

    def test_execution_pauses_after_a_failure_and_the_agent_may_continue(self):
        vm = FakeVm(revert_controls=('1.1.1',))  # Isolated: something sets this one value back.
        hardening, executed = self.remediation_round(
            vm, self.after_pause(lambda r: ('execute_fixes', dict(control_ids=r['remaining']))))
        self.assertEqual(vm.attempts, ['1.2.2', '1.1.1', '2.3.10.3'])  # Risk order: 69, 63, 60.
        self.assertEqual([v['verdict'] for v in executed['verdicts']],
                         ['Verified compliant', 'Verification failed', 'Verified compliant'])
        events = next(t for t in hardening.traces(executed['round_id']) if t['agent_role'] == REMEDIATION)['events']
        first = next(e['data']['result'] for e in events if e['kind'] == 'tool' and e['data']['name'] == 'execute_fixes')
        self.assertEqual((len(first['results']), first['remaining']), (2, ['2.3.10.3']))
        self.assertEqual((executed['outcome']['outcome'], executed['outcome']['reason_code']),
                         ('remediation_review', 'verification_failed'))

    def test_the_agent_may_stop_after_a_failure_and_the_cause_is_shown(self):
        vm = FakeVm(fail_action='Requested registry access is not allowed.')  # Systemic: every write fails.
        hardening, executed = self.remediation_round(vm, self.after_pause(lambda r: ('stop_execution', {})))
        self.assertEqual(vm.attempts, ['1.2.2'])
        self.assertEqual(executed['verdicts'][0]['verdict'],
                         'Unresolved: execution_failed (Requested registry access is not allowed.)')
        self.assertIn('Skipped by the Remediation Agent: 1.1.1 (stopped after an earlier failed result); '
                      '2.3.10.3 (stopped after an earlier failed result).', executed['outcome']['reason'])
        self.assertEqual((executed['outcome']['outcome'], executed['outcome']['reason_code']),
                         ('remediation_review', 'verification_failed'))

    def test_stop_execution_is_refused_before_any_failure(self):
        vm = FakeVm()
        hardening, executed = self.remediation_round(vm, lambda seen, names: (
            ('precheck', {}) if not seen else ('stop_execution', {}) if len(seen) == 1
            else remediation_policy(seen, names)))
        self.assertEqual(self.rejected(hardening, executed['round_id'], REMEDIATION),
                         ['stop_execution is for after a failed result; nothing has failed'])
        self.assertEqual(vm.attempts, ['1.2.2', '1.1.1', '2.3.10.3'])


class OverviewCountTests(AgenticTestCase):
    def test_fixes_awaiting_you_counts_only_the_latest_round(self):
        from hardening.overview_view import awaiting_you
        first = self.standard_round(FakeVm()).run_round()  # Two proposals, never decided.
        self.assertEqual(awaiting_you(self.store, self.runtime, self.target_id), 2)
        second = self.standard_round(FakeVm()).run_round()  # A new scan replaces the first round.
        self.assertEqual(awaiting_you(self.store, self.runtime, self.target_id), 2, 'not 4: old proposals are not offered')
        self.approve_all(second['framework_run_id'])
        self.assertEqual(awaiting_you(self.store, self.runtime, self.target_id), 0)
        self.assertEqual(sum(p['decision'] is None for p in self.store.for_run(first['framework_run_id'])), 2)
        self.assertEqual(awaiting_you(self.store, self.runtime, 'windows:11111111-2222-3333-4444-555555555555'), 0)

    def test_activity_marks_an_older_undecided_round_as_replaced(self):
        from hardening.overview_view import activity_row, latest_assessment_run
        first = self.standard_round(FakeVm()).run_round()
        self.standard_round(FakeVm()).run_round()
        latest = latest_assessment_run(self.store, self.runtime, self.target_id)
        rows = {r['round_id']: activity_row(r, self.store, latest)['Status'] for r in self.store.recent_rounds(10)}
        self.assertEqual(rows[first['round_id']], 'Replaced by a later round')
        self.assertEqual(sorted(rows.values()), ['2 awaiting approval', 'Replaced by a later round'])


class ApprovedActionExecutorTests(AgenticTestCase):
    def proposed(self, vm):
        hardening = self.standard_round(vm)
        result = hardening.run_round()
        return hardening, result, self.store.for_run(result['framework_run_id'])[0]['proposal']['request_id']

    def test_unapproved_or_rejected_proposals_cannot_execute(self):
        vm = FakeVm()
        hardening, _, proposal = self.proposed(vm)
        agent = ApprovedActionExecutor(self.store, hardening.scanner)
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
        verdict = ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal)
        self.assertTrue(verdict.startswith('Refused before execution: Configuration changed'))
        self.assertEqual(vm.writes, [])
        with self.assertRaises(ValueError):
            ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal)

    def test_execution_failure_is_unresolved_and_expired_approval_refused(self):
        vm = FakeVm(fail_action=True)
        hardening, _, proposal = self.proposed(vm)
        self.store.decide(proposal, approve=True, operator='admin01')
        self.assertEqual(ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal), 'Unresolved: execution_failed')
        second = self.store.for_run(self.store.get(proposal)['proposal']['framework_run_id'])[1]['proposal']['request_id']
        self.store.decide(second, approve=True, operator='admin01',
                          now=datetime.now(timezone.utc) - timedelta(hours=2))
        with self.assertRaises(ValueError):
            ApprovedActionExecutor(self.store, hardening.scanner).execute(second)

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
        verdict = ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal)
        self.assertIn('outcome uncertain', verdict)
        with self.assertRaises(ValueError):
            ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal)

    def test_a_receipt_is_judged_even_when_the_error_stream_is_not_empty(self):
        """A receipt proves a write may have happened; an extra error-stream entry must never turn it into
        "Refused before execution" (which would hide a change on the server)."""
        vm = FakeVm()
        hardening, _, proposal = self.proposed(vm)
        self.store.decide(proposal, approve=True, operator='admin01')
        original = vm.run

        def noisy(script, parameters=None):
            output, had_errors, errors = original(script, parameters)
            if script == RUNNER.read_text(encoding='utf-8-sig') and output:
                return output, True, ['A warning written to the error stream after the write.']
            return output, had_errors, errors
        vm.run = noisy
        verdict = ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal)
        self.assertEqual(verdict, 'Verified compliant')
        self.assertEqual(vm.writes, ['1.2.2'])

    def test_stray_output_with_errors_is_uncertain_not_refused(self):
        vm = FakeVm()
        hardening, _, proposal = self.proposed(vm)
        self.store.decide(proposal, approve=True, operator='admin01')
        original = vm.run

        def garbled(script, parameters=None):
            if script == RUNNER.read_text(encoding='utf-8-sig'):
                original(script, parameters)  # The write happened...
                return ['not a receipt'], True, ['...and something else went wrong.']
            return original(script, parameters)
        vm.run = garbled
        verdict = ApprovedActionExecutor(self.store, hardening.scanner).execute(proposal)
        self.assertTrue(verdict.startswith('Unresolved: receipt failed validation'), verdict)


class RiskEngineTests(AgenticTestCase):
    def record(self, vm):
        scanner = LiveScanner(self.runtime, target(), session_factory=vm)
        run = scanner.request(target().hostname, target().machine_uuid)
        return self.runtime.imports.get(run['evidence_sha256'])

    def test_scores_rank_and_skip_unknowns(self):
        ranked = {f.control_id: f for f in analyse(self.record(FakeVm()))}
        self.assertEqual(set(ranked), {'1.2.2', '1.1.1', '1.1.3', '2.3.10.3', '9.3.1', '18.10.57.3.9.4'})
        # Derived: protection_weakened I4, all_local_accounts P4, Level 1 Automated L4; E3; D1.
        self.assertEqual(ranked['1.2.2'].factors, dict(I=4, E=3, P=4, L=4, D=1))
        self.assertEqual((ranked['1.2.2'].score, ranked['1.2.2'].level), (69, 'High'))
        self.assertEqual([(f.control_id, f.score) for f in analyse(self.record(FakeVm()))],
                         [('1.2.2', 69), ('9.3.1', 65), ('1.1.1', 63), ('2.3.10.3', 60), ('18.10.57.3.9.4', 59), ('1.1.3', 57)])
        self.assertTrue(ranked['1.2.2'].factor_reasons['P'].startswith('all_local_accounts: applies to every local account'))

    def test_regression_drift_and_disabled_firewall_raise_scores(self):
        compliant = self.record(FakeVm(dict(LAB_STATE, **{'1.2.2': 5, '1.2.1': 15, '1.2.4': 15})))
        regressed = self.record(FakeVm())
        finding = next(f for f in analyse(regressed, [compliant]) if f.control_id == '1.2.2')
        self.assertEqual((finding.factors['D'], finding.score), (5, 77))  # Confirmed regression adds 2 x (5-1).
        exposed = next(f for f in analyse(self.record(FakeVm(firewall=False))) if f.control_id == '1.2.2')
        self.assertEqual((exposed.factors['E'], exposed.score), (4, 74))


class RiskDerivationTests(unittest.TestCase):
    def test_every_catalogue_control_has_attributes_and_no_hand_assigned_factor(self):
        from hardening.risk import ATTRIBUTES, CONSEQUENCE, LIKELIHOOD, PRIVILEGE_SCOPE, derive
        from hardening.server2022_catalogue import CATALOGUE
        self.assertEqual({c.control_id for c in CATALOGUE}, set(ATTRIBUTES))
        for control_id, attributes in ATTRIBUTES.items():
            derivation = derive(control_id)
            self.assertEqual(derivation.impact, CONSEQUENCE[attributes.consequence][0])
            self.assertEqual(derivation.privilege, PRIVILEGE_SCOPE[attributes.privilege_scope][0])
            self.assertEqual(derivation.likelihood, LIKELIHOOD[(attributes.level, attributes.automated)])
            self.assertEqual(set(derivation.reasons), {'I', 'P', 'L'})

    def test_likelihood_rule_and_its_documented_limitation(self):
        from hardening.risk import ATTRIBUTES, LIKELIHOOD
        self.assertEqual(LIKELIHOOD, {(1, True): 4, (1, False): 3, (2, True): 3, (2, False): 2})
        # Every selected control is Level 1 and Automated, so L does not separate them (stated limitation).
        self.assertEqual({(a.level, a.automated) for a in ATTRIBUTES.values()}, {(1, True)})

    def test_logging_consequences_score_lower_than_authentication_weaknesses(self):
        from hardening.risk import derive
        self.assertLess(derive('17.1.1').impact, derive('1.2.2').impact)  # Table 4.15: logging visibility lower.
        self.assertGreater(derive('2.3.10.1').privilege, derive('2.3.10.2').privilege)  # Admin identity vs anonymous.


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

    def test_no_action_can_change_which_traffic_the_firewall_allows(self):
        # Channel safety: firewall on/off and inbound-block policy could cut the agents' WinRM channel.
        firewall = sorted(a.control_id for a in LIBRARY.values() if a.control_id.startswith('9.'))
        self.assertEqual(firewall, ['9.2.6', '9.2.7', '9.3.6', '9.3.7'])  # Logging only.
        output = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(RUNNER),
                                 '-ListActions'], capture_output=True, text=True, timeout=60, check=True).stdout
        sources = {'9.2.6': 'PrivateProfile\\Logging:LogDroppedPackets',
                   '9.2.7': 'PrivateProfile\\Logging:LogSuccessfulConnections',
                   '9.3.6': 'PublicProfile\\Logging:LogDroppedPackets',
                   '9.3.7': 'PublicProfile\\Logging:LogSuccessfulConnections'}
        for action_id, entry in json.loads(output).items():
            if entry['control_id'].startswith('9.'):
                # Written exactly where the collector reads it, so the read-back verifies the same value.
                written = 'HKLM\\' + entry['key'] + ':' + entry['name']
                self.assertEqual(written, SOURCES[entry['control_id']])
                self.assertTrue(written.endswith(sources[entry['control_id']]))
                self.assertEqual((entry['kind'], entry['value']), ('reg_dword', 1))


if __name__ == '__main__':
    unittest.main()
