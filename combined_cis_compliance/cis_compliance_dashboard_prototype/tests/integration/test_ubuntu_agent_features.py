"""The six agent features of the Windows engine, on Ubuntu (2026-11-09): the Orchestrator's second Scanner delegation
and fix order, the Scanner's inspect_observation, the Analysis Agent's check_history and fitting attention/triage
codes, the Remediation Agent, the Orchestrator's review after approval, and the finding explanation (FR17).
Scripted models; synthetic evidence and fake server callables; no VM."""
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace as N
from unittest import mock

from system.contracts import ComplianceStatus
from tests.integration import test_ubuntu_agents as base  # module import: base tests are not collected twice
from tests.integration.test_ubuntu_agents import INJECTION, TARGET, Scripted, call, plan_call, scanner_ok, team

COMPLIANT, FAILING = ComplianceStatus.COMPLIANT, ComplianceStatus.NON_COMPLIANT
NOTHING = {'role': 'assistant', 'content': 'Thinking about it.', 'tool_calls': []}


def finding(cid, rank, D=1):
    return N(control_id=cid, rank=rank, D=D, score=60, level='High')


def names(event_list, kind='tool'):
    return [e['data']['name'] for e in event_list if e['kind'] == kind]


class AssessmentFeatureTests(base.AgentRoundTests):
    def round_with(self, clients, *, collect=None, rank=None, history=None):
        from backends.ubuntu.agents import run_agentic_round
        from backends.ubuntu.adapter import _controls
        return run_agentic_round(client_factory=clients.__getitem__, collect=collect or self.collect_with(),
                                 log_store=self.log, target_id=TARGET,
                                 titles={cid: c.title for cid, c in _controls().items()},
                                 rank=rank or (lambda run_id, ev: None), history=history)

    def test_the_scanner_inspects_observations_as_code_written_states_only(self):
        # At most three controls per Scanner run (MAX_OBSERVATIONS); the fourth is refused.
        scanner = [call('scan_target')] + [call('inspect_observation', control_id=c)
                                           for c in ('5.2.3', '1.5.1', '2.4.1.2', '5.1.20')] + [
                   call('read_coverage'), call('handoff_analysis', reason='ok')]
        clients = team([call('delegate_scanner')], scanner)
        result = self.round_with(clients, collect=self.collect_with(failing=('1.5.1',), inject=True))
        events = self.events(result['children']['scanner'])
        inspected = next(e['data']['result'] for e in events if e['kind'] == 'tool'
                         and e['data']['name'] == 'inspect_observation')
        self.assertEqual(inspected['control_id'], '5.2.3')
        self.assertTrue(inspected['observations'])
        self.assertEqual(set(inspected['observations'][0]), {'name', 'state', 'reason'})
        self.assertEqual(names(events, 'tool_rejected'), ['inspect_observation'])  # the fourth control
        self.assertEqual(names(events).count('inspect_observation'), 3)
        for client in clients.values():
            self.assertFalse(any(INJECTION in text for text in client.seen))

    def test_check_history_and_inspect_finding_share_two_investigations(self):
        earlier = [('2026-11-08T10:00:00+00:00', 'Non-Compliant'), ('2026-11-07T10:00:00+00:00', 'Compliant')]
        analysis = [call('read_ranking'), call('check_history', control_id='1.5.1'),
                    call('inspect_finding', control_id='5.1.20'), call('check_history', control_id='5.1.20'),
                    call('submit_analysis', flags=[], gap_triage=[{'control_id': '2.4.1.2', 'triage_code': 'manual_review'}])]
        clients = team([call('delegate_scanner'), call('delegate_analysis')], scanner_ok(), analysis)
        result = self.round_with(clients, rank=lambda r, e: [finding('5.1.20', 1), finding('1.5.1', 2, D=3)],
                                 history=lambda cid: earlier if cid == '1.5.1' else [])
        events = self.events(result['children']['analysis'])
        history = next(e['data']['result'] for e in events if e['kind'] == 'tool' and e['data']['name'] == 'check_history')
        self.assertEqual(history, {'control_id': '1.5.1', 'D': 3, 'earlier': [
            {'assessed_at': at, 'status': status} for at, status in earlier]})
        self.assertEqual(names(events, 'tool_rejected'), ['check_history'])  # the third investigation
        self.assertIsNotNone(result['analysis'])

    def test_read_ranking_lists_the_codes_each_finding_and_gap_fits(self):
        analysis = [call('read_ranking'), call('submit_analysis', flags=[], gap_triage=[
            {'control_id': '2.4.1.2', 'triage_code': 'manual_review'}, {'control_id': '1.5.4', 'triage_code': 'rescan'}])]
        clients = team([call('delegate_scanner'), call('delegate_analysis')], scanner_ok(), analysis)
        result = self.round_with(clients, collect=self.collect_with(errors=True),
                                 rank=lambda r, e: [finding('5.1.20', 1), finding('1.5.1', 2, D=3)])
        ranking = next(e['data']['result'] for e in self.events(result['children']['analysis'])
                       if e['kind'] == 'tool' and e['data']['name'] == 'read_ranking')
        codes = {f['control_id']: f['attention_codes'] for f in ranking['findings']}
        self.assertEqual(codes, {'5.1.20': ['affects_remote_access', 'highest_risk'],
                                 '1.5.1': ['highest_risk', 'persistent_failure']})
        triage = {g['control_id']: g['triage_codes'] for g in ranking['gaps']}
        self.assertIn('rescan', triage['1.5.4'])  # an Error gap
        self.assertNotIn('rescan', triage['2.4.1.2'])  # an Unknown gap: a rescan cannot change it
        self.assertEqual(result['analysis']['triage'][1], {'control_id': '1.5.4', 'triage_code': 'rescan'})

    def test_a_rescan_triage_for_an_unknown_gap_is_refused(self):
        analysis = [call('read_ranking'), call('submit_analysis', flags=[], gap_triage=[
            {'control_id': '2.4.1.2', 'triage_code': 'rescan'}])]
        clients = team([call('delegate_scanner'), call('delegate_analysis')], scanner_ok(), analysis)
        result = self.round_with(clients)
        refused = [e['data']['error'] for e in self.events(result['children']['analysis']) if e['kind'] == 'tool_rejected']
        self.assertEqual(len(refused), 1)
        self.assertIn('does not fit this gap', refused[0])
        self.assertIsNone(result['analysis'])

    def test_a_rescan_request_lets_the_orchestrator_rescan_once_and_analyse_again(self):
        triage = [{'control_id': '2.4.1.2', 'triage_code': 'manual_review'}, {'control_id': '1.5.4', 'triage_code': 'rescan'}]
        analysis = [call('read_ranking'), call('submit_analysis', flags=[], gap_triage=triage),
                    call('read_ranking'), call('submit_analysis', flags=[], gap_triage=triage)]
        # The second Scanner run may not rescan again: its rescan is refused, so the round collects twice, not three times.
        scanner = scanner_ok() + [call('scan_target'), call('read_coverage'), call('rescan', reason='again'),
                                  call('handoff_analysis', reason='ok')]
        orchestrator = [call('delegate_scanner'), call('delegate_analysis'), call('delegate_scanner'),
                        call('delegate_analysis'), call('delegate_scanner'),
                        plan_call([{'control_id': c, 'decision': 'defer', 'reason_code': 'no_registered_action'}
                                   for c in ('1.5.1', '5.1.20')])]
        result = self.round_with(team(orchestrator, scanner, analysis), collect=self.collect_with(errors=True))
        self.assertEqual(len(self.collected), 2)
        self.assertEqual((result['scanned_runs'], result['run_id']), (['run-1', 'run-2'], 'run-2'))
        self.assertIsNotNone(result['plan'])
        events = self.events(result['orchestrator_run_id'])
        first_analysis = [e['data']['result'] for e in events if e['kind'] == 'tool'
                          and e['data']['name'] == 'delegate_analysis'][0]
        self.assertEqual(first_analysis['rescan_requested'], ['1.5.4'])
        self.assertEqual(names(events, 'tool_rejected'), ['delegate_scanner'])  # a third delegation

    def test_a_scanner_that_stopped_without_a_decision_gets_one_more_delegation(self):
        scanner = [call('scan_target'), NOTHING, NOTHING] + scanner_ok()
        orchestrator = [call('delegate_scanner'), call('delegate_scanner'), call('delegate_analysis'),
                        plan_call([{'control_id': c, 'decision': 'defer', 'reason_code': 'no_registered_action'}
                                   for c in ('1.5.1', '5.1.20')])]
        analysis = [call('read_ranking'), call('submit_analysis', flags=[], gap_triage=[
            {'control_id': '2.4.1.2', 'triage_code': 'manual_review'}])]
        result = self.round_with(team(orchestrator, scanner, analysis))
        first = next(e['data']['result'] for e in self.events(result['orchestrator_run_id']) if e['kind'] == 'tool')
        self.assertEqual(first, {'status': 'scanner_stopped', 'retry_allowed': True})
        self.assertEqual(len(self.collected), 2)
        self.assertIsNotNone(result['plan'])

    def test_a_reported_scan_failure_still_ends_the_round(self):
        clients = team([call('delegate_scanner'), call('delegate_scanner')],
                       [call('scan_target'), call('report_failure', reason='helper refused')])
        result = self.round_with(clients, collect=self.collect_with(fail=True))
        self.assertEqual(self.events(result['orchestrator_run_id'])[-1]['data']['outcome']['outcome'], 'scan_failed')
        self.assertIsNone(result['run_id'])


for _name in [n for n in dir(base.AgentRoundTests) if n.startswith('test')]:
    setattr(AssessmentFeatureTests, _name, None)  # only the harness is inherited


class FixOrderTests(unittest.TestCase):
    def test_listed_fixes_keep_the_orchestrators_order_and_the_rest_follow_risk_rank(self):
        from tests.integration.test_ubuntu_plan_errors import tools_for
        failing = ['1.5.1', '4.1.4', '5.1.20']
        tools = tools_for(failing, {c: 'ubuntu.%s.v1' % c for c in failing})
        tools.rounds.ranked = lambda: [finding('5.1.20', 1), finding('1.5.1', 2), finding('4.1.4', 3)]
        tools.call('submit_plan', {'target_id': 'ubuntu:fixture', 'fixes': [
            {'control_id': '4.1.4', 'action_id': 'ubuntu.4.1.4.v1', 'reason_code': 'unblocks_other'}]})
        self.assertEqual([f['control_id'] for f in tools.rounds.plan['fixes']], ['4.1.4', '5.1.20', '1.5.1'])


# ---------------------------------------------------------------- remediation phase
def scan(statuses):
    return N(expected=N(evidence_mode='fixture'), assessments=[N(control_id=c, status=s) for c, s in statuses.items()])


REQUESTS = [{'request_id': 'r' + c.replace('.', ''), 'control_id': c, 'action_id': 'ubuntu.%s.v1' % c,
             'title': 'Fix ' + c, 'expires_at': '2026-11-09T12:00:00+00:00', 'rank': n}
            for n, c in enumerate(('1.5.1', '5.2.3', '4.1.4'), 1)]


class RemediationPhaseTests(unittest.TestCase):
    def setUp(self):
        from backends.ubuntu.storage import AgentLogStore, UbuntuStore
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.log = AgentLogStore(UbuntuStore(Path(folder.name)/'ubuntu.sqlite3').paths[2])
        self.executed, self.skips, self.verified = [], [], []

    def phase(self, *, requests=REQUESTS[:2], outcomes=None, facts=None, after=None, eligible_after=()):
        from backends.ubuntu.remediation_agents import Phase
        outcomes, facts = outcomes or {}, facts or {}

        def execute(rid):
            self.executed.append(rid)
            return outcomes.get(rid, ('completed', 'applied'))

        def verify(rids):
            self.verified.append(sorted(rids))
            return 'verify-run', scan(after or {r['control_id']: COMPLIANT for r in requests})
        return Phase(target_id=TARGET, round_id='round-1', log_store=self.log, requests=requests,
                     precheck=lambda rid: facts.get(rid, {}), execute=execute,
                     skip=lambda rid, reason: self.skips.append((rid, reason)), verify=verify,
                     eligible=lambda ev: {c: 'x' for c in eligible_after} if ev is not None and ev != 'before' else {},
                     before='before')

    def run_phase(self, phase, review, remediation, scanner=()):
        from backends.ubuntu.remediation_agents import REMEDIATION, run_remediation_phase
        from backends.ubuntu.agents import ORCHESTRATOR, SCANNER
        clients = {ORCHESTRATOR: Scripted(review), REMEDIATION: Scripted(remediation), SCANNER: Scripted(scanner)}
        self.clients = clients
        return run_remediation_phase(phase, client_factory=clients.__getitem__)

    def events(self, run_id):
        from hardening.investigation import InvestigationLog
        return InvestigationLog(self.log).get(run_id)['events']

    def test_a_full_phase_executes_in_the_agents_order_verifies_and_finishes(self):
        result = self.run_phase(
            self.phase(),
            [call('delegate_remediation'), call('delegate_verification'),
             call('submit_review', next_step='finish', reason_code='all_verified')],
            [call('precheck'), call('execute_fixes', control_ids=['5.2.3', '1.5.1']), call('report_results')],
            [call('scan_target'), call('read_coverage'), call('handoff_verification', reason='done')])
        self.assertEqual(self.executed, ['r523', 'r151'])  # the Remediation Agent's order, not the plan's
        self.assertEqual(self.verified, [['r151', 'r523']])
        self.assertEqual((result['review']['outcome'], result['review']['reason_code']), ('finish', 'all_verified'))
        self.assertIn('Applied: 5.2.3, 1.5.1.', result['review']['reason'])
        self.assertEqual(result['verification']['run_id'], 'verify-run')
        self.assertEqual(set(result['children']), {'remediation', 'verification'})
        roles = {self.events(i)[0]['kind'] for i in result['children'].values()}
        self.assertEqual(roles, {'request'})

    def test_a_fix_that_is_not_ready_cannot_run_and_is_skipped_with_its_code(self):
        result = self.run_phase(
            self.phase(facts={'r151': {'precondition_changed': True}}),
            [call('delegate_remediation'), call('delegate_verification'),
             call('submit_review', next_step='finish', reason_code='all_verified')],
            [call('precheck'), call('execute_fixes', control_ids=['1.5.1', '5.2.3']),
             call('skip_fix', control_id='1.5.1', reason_code='precondition_changed'),
             call('execute_fixes', control_ids=['5.2.3']), call('report_results')],
            scanner_ok()[:2] + [call('handoff_verification', reason='done')])
        self.assertEqual(self.executed, ['r523'])  # the refused list ran nothing
        self.assertEqual([rid for rid, _ in self.skips], ['r151'])
        self.assertIn('changed since approval', self.skips[0][1])
        self.assertEqual(result['remediation']['skipped'],
                         [{'request_id': 'r151', 'control_id': '1.5.1', 'reason_code': 'precondition_changed'}])

    def test_a_skip_code_must_fit_the_precheck(self):
        self.run_phase(self.phase(), [call('delegate_remediation')],
                       [call('precheck'), call('skip_fix', control_id='1.5.1', reason_code='expired')])
        self.assertEqual(self.skips, [])

    def test_a_refused_fix_pauses_and_stop_execution_closes_the_rest(self):
        result = self.run_phase(
            self.phase(requests=REQUESTS, outcomes={'r151': ('refused', 'stale_read_set')}),
            [call('delegate_remediation'), call('submit_review', next_step='finish', reason_code='nothing_executed'),
             call('submit_review', next_step='remediation_review', reason_code='fix_refused')],
            [call('precheck'), call('execute_fixes', control_ids=['1.5.1', '5.2.3', '4.1.4']), call('stop_execution')])
        self.assertEqual(self.executed, ['r151'])
        self.assertEqual(sorted(rid for rid, _ in self.skips), ['r414', 'r523'])
        self.assertEqual(result['review']['reason_code'], 'fix_refused')
        rejected = [e['data'] for e in self.events(result['orchestrator_run_id']) if e['kind'] == 'tool_rejected']
        self.assertIn('does not fit finish', rejected[0]['error'])

    def test_after_an_uncertain_outcome_nothing_more_runs(self):
        for state in ('unresolved', 'running'):
            with self.subTest(state=state):
                self.executed, self.skips = [], []
                code = {'unresolved': 'uncertain_outcome', 'running': 'awaiting_confirmation'}[state]
                result = self.run_phase(
                    self.phase(outcomes={'r151': (state, 'no_trusted_receipt')}),
                    [call('delegate_remediation'), call('submit_review', next_step='remediation_review',
                                                        reason_code=code)],
                    [call('precheck'), call('execute_fixes', control_ids=['1.5.1', '5.2.3']),
                     call('execute_fixes', control_ids=['5.2.3']), call('report_results')])
                self.assertEqual(self.executed, ['r151'])
                self.assertEqual(result['remediation']['not_attempted'], ['5.2.3'])
                self.assertEqual(result['review']['reason_code'], code)
                self.assertEqual(self.verified, [])  # nothing applied: no verification is offered

    def test_verification_comes_first_and_a_review_code_must_be_true(self):
        result = self.run_phase(
            self.phase(after={'1.5.1': FAILING, '5.2.3': COMPLIANT}),
            [call('delegate_remediation'), call('submit_review', next_step='finish', reason_code='all_verified'),
             call('delegate_verification'), call('submit_review', next_step='finish', reason_code='all_verified'),
             call('submit_review', next_step='remediation_review', reason_code='verification_failed')],
            [call('precheck'), call('execute_fixes', control_ids=['1.5.1', '5.2.3']), call('report_results')],
            scanner_ok()[:2] + [call('handoff_verification', reason='done')])
        rejected = [e['data']['error'] for e in self.events(result['orchestrator_run_id']) if e['kind'] == 'tool_rejected']
        self.assertEqual(len(rejected), 2)
        self.assertIn('Tool not available now', rejected[0])
        self.assertIn('true codes: remediation_review: verification_failed', rejected[1])
        self.assertEqual(result['review']['reason_code'], 'verification_failed')
        self.assertIn('1.5.1 did not verify Compliant', result['review']['reason'])

    def test_remaining_registered_failures_lead_to_a_next_round(self):
        result = self.run_phase(
            self.phase(eligible_after=('6.3.1.2',)),
            [call('delegate_remediation'), call('delegate_verification'),
             call('submit_review', next_step='next_round', reason_code='unblocked_findings')],
            [call('precheck'), call('execute_fixes', control_ids=['1.5.1', '5.2.3']), call('report_results')],
            scanner_ok()[:2] + [call('handoff_verification', reason='done')])
        self.assertEqual((result['review']['outcome'], result['verification']['unblocked']), ('next_round', ['6.3.1.2']))

    def test_unapproved_controls_and_invented_tools_are_refused(self):
        result = self.run_phase(
            self.phase(), [call('delegate_remediation')],
            [call('run_shell', command='ufw disable'), call('precheck'),
             call('execute_fixes', control_ids=['6.3.1.2'])])
        self.assertEqual(self.executed, [])
        rejected = names(self.events(result['children']['remediation']), 'tool_rejected')
        self.assertEqual(rejected, ['run_shell', 'execute_fixes'])

    def test_the_backend_reads_the_agents_skips_from_its_recorded_tool_results(self):
        from backends.ubuntu.adapter import UbuntuBackend
        self.run_phase(self.phase(facts={'r151': {'expired': True}}), [call('delegate_remediation')],
                       [call('precheck'), call('skip_fix', control_id='1.5.1', reason_code='expired'),
                        call('execute_fixes', control_ids=['5.2.3']), call('report_results')])
        proposals = [N(decision='approved', approved_raw=json.dumps({'request_id': r['request_id']}).encode(),
                       payload={'fields': {'control_id': r['control_id']}, 'action': {'action_id': r['action_id']}})
                     for r in REQUESTS[:2]]
        backend = UbuntuBackend.__new__(UbuntuBackend)
        skipped = backend._agent_skipped(N(agent_log=lambda: self.log), 'round-1', proposals)
        self.assertEqual(skipped, {'r151': 'the approval has expired'})
        self.assertEqual(backend._agent_skipped(N(agent_log=lambda: self.log), 'another-round', proposals), {})


# ---------------------------------------------------------------- backend: the agentic execution path
def approved(request_id, control_id):
    return N(proposal_id='p-' + request_id, decision='approved', receipts=(),
             payload={'action': {'action_id': 'ubuntu.%s.v1' % control_id}, 'title': 'Fix ' + control_id,
                      'fields': {'control_id': control_id}},
             approved_raw=json.dumps({'request_id': request_id, 'expires_at': '2026-11-09T12:00:00+00:00'}).encode())


class AgenticExecutionTests(unittest.TestCase):
    def backend(self, *, model=True, skipped=None, phase_result=None, unverified=()):
        from backends.ubuntu.adapter import UbuntuBackend
        backend = UbuntuBackend.__new__(UbuntuBackend)
        self.calls = {'verify': [], 'phase': []}
        batch = [approved('a151', '1.5.1'), approved('a523', '5.2.3')]
        store = N(proposals=lambda binding, round_id: batch, agent_log=lambda: None)

        def run_phase(phase, client_factory):
            self.calls['phase'].append([r['control_id'] for r in phase.requests])
            return phase_result or {'remediation': {'results': [{'request_id': 'a151', 'result': 'applied'}]}}

        def verify(store_, binding, latest, applied, state):
            self.calls['verify'].append(list(applied))
            return state
        patches = mock.patch.multiple(
            backend, create=True, check=lambda *a: 'binding', _store=lambda: store, model_probe=lambda: model,
            _latest=lambda *a: N(round_id='r', evidence_sha256='d'), _agent_skipped=lambda *a: dict(skipped or {}),
            _evidence=lambda *a: 'evidence', _findings=lambda *a: (), _verify=verify,
            _unverified=lambda *a: list(unverified), session=N(target_id=TARGET), model_client_factory=None)
        return backend, patches, run_phase

    def execute(self, backend, patches, run_phase):
        with patches, mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()), \
                mock.patch('backends.ubuntu.remediation_agents.run_remediation_phase', run_phase):
            return backend.execute_approved('c', 'w', 'round', ('a151', 'a523'), False, 'op')

    def test_code_runs_the_verification_scan_when_the_orchestrator_left_it_out(self):
        handle = self.execute(*self.backend(unverified=['a151']))
        self.assertEqual(self.calls['phase'], [['1.5.1', '5.2.3']])
        self.assertEqual(self.calls['verify'], [['a151']])
        self.assertEqual(handle.state, 'completed')

    def test_the_phase_gets_only_open_fixes_and_reports_the_worst_outcome(self):
        handle = self.execute(*self.backend(skipped={'a151': 'the approval has expired'}, phase_result={
            'remediation': {'results': [{'request_id': 'a523', 'result': 'uncertain'}]}}))
        self.assertEqual(self.calls['phase'], [['5.2.3']])
        self.assertEqual(handle.state, 'unresolved')

    def test_without_the_model_nothing_is_dispatched(self):
        backend, patches, run_phase = self.backend(model=False)
        with self.assertRaisesRegex(ValueError, 'no write was dispatched and every approval stays open'):
            self.execute(backend, patches, run_phase)
        self.assertEqual(self.calls['phase'], [])

    def test_the_path_without_ai_never_runs_a_fix_the_agent_skipped(self):
        backend, patches, _ = self.backend(skipped={'a151': 'the approval has expired'})
        dispatched = []
        with patches, mock.patch.object(backend, '_dispatch_one', create=True,
                                        new=lambda s, b, p, o: dispatched.append(p.proposal_id) or N(state='completed')), \
                mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            backend.execute_approved('c', 'w', 'round', ('a151', 'a523'), True, 'op')
        self.assertEqual(dispatched, ['p-a523'])

    def test_precheck_compares_a_fresh_preview_with_the_approved_plan(self):
        from backends.ubuntu.adapter import UbuntuBackend
        backend = UbuntuBackend.__new__(UbuntuBackend)
        proposal = approved('a151', '1.5.1')
        proposal.payload['fields'].update(parameters={}, before_state_sha256='b' * 64, expected_after_sha256='e' * 64)
        answers = {'same': {'action_id': 'ubuntu.1.5.1.v1', 'before_state_sha256': 'b' * 64, 'expected_after_sha256': 'e' * 64},
                   'changed': {'action_id': 'ubuntu.1.5.1.v1', 'before_state_sha256': 'c' * 64, 'expected_after_sha256': 'e' * 64}}
        for answer, expected in (('same', {}), ('changed', {'precondition_changed': True})):
            backend.session = N(channel=N(invoke_runner=lambda data, a=answer: json.dumps(answers[a]).encode()))
            facts = backend._precheck(proposal)
            self.assertEqual({k for k, v in facts.items() if v and k != 'expired'}, set(expected))

        def refuse(data):
            raise ValueError('Ubuntu fixed helper command refused or is not installed (exit status 2)')
        backend.session = N(channel=N(invoke_runner=refuse))
        self.assertTrue(backend._precheck(proposal)['preview_refused'])

        def lost(data):
            raise OSError('connection reset')
        backend.session = N(channel=N(invoke_runner=lost))
        with self.assertRaises(OSError):  # the agent then stops without skipping anything
            backend._precheck(proposal)


# ---------------------------------------------------------------- finding explanation (FR17)
class ExplanationTests(unittest.TestCase):
    def test_the_explanation_is_cut_to_ninety_words_without_thinking(self):
        from backends.ubuntu.agents import explain_finding
        client = Scripted([{'role': 'assistant', 'content': '<think>private</think>' + ' word' * 120}])
        text = explain_finding({'control_id': '1.5.1'}, client)
        self.assertEqual(len(text.replace(' …', '').split()), 90)
        self.assertTrue(text.endswith(' …'))
        self.assertNotIn('private', text)
        self.assertEqual(client.tools_seen, [[]])  # no tools: the explanation can change nothing

    def test_the_backend_sends_only_code_written_facts_of_the_finding(self):
        from backends.ubuntu.adapter import UbuntuBackend
        from system.contracts import ControlRow, FindingRow, Subcheck
        backend = UbuntuBackend.__new__(UbuntuBackend)
        control = ControlRow('1.5.1', 'Ensure ASLR is enabled', 'Process hardening', 'L1', 'CIS p.1', FAILING,
                             'applicable', 'fail 1', 'kernel.randomize_va_space = 2',
                             (Subcheck('sysctl.runtime', FAILING, 'runtime value differs'),))
        row = FindingRow('1.5.1', 5, 3, 4, 4, 3, 72, 'High', ('I=5: ...', 'D=3: persistent'), 'v1', 1)
        client = Scripted([{'role': 'assistant', 'content': 'ASLR makes memory addresses unpredictable.'}])
        backend.model_client_factory = lambda role: client
        with mock.patch.object(backend, 'snapshot', create=True,
                               new=lambda *a: N(findings=(row,), controls=(control,))):
            text = backend.explain_finding('c', 'w', '1.5.1')
        self.assertEqual(text, 'ASLR makes memory addresses unpredictable.')
        facts = json.loads(json.loads(client.seen[0])[1]['content'])
        self.assertEqual(facts['subchecks'], [{'name': 'sysctl.runtime', 'status': 'Non-Compliant',
                                               'reason': 'runtime value differs'}])
        self.assertEqual((facts['risk_score'], facts['factors']['D']), (72, 3))
        self.assertNotIn('observed', facts)

    def test_a_skipped_fix_has_its_own_card_state(self):
        from system.ui.components import SKIPPED, _card_state
        fix = N(reference=N(record_id='p1'), decision='approved')
        state = _card_state(N(decision='Fix proposed'), fix, [], {'p1': N(execution_state='skipped')})
        self.assertEqual(state, SKIPPED)


if __name__ == '__main__':
    unittest.main()
