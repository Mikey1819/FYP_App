"""Scripted-model contract tests; real inference evidence is recorded separately."""
from pathlib import Path
import tempfile
import unittest

from hardening.agent_team import AgentTeam, SpecialistTools, SCANNER, ANALYSIS, REMEDIATION, ORCHESTRATOR
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.lifecycle import RemediationLifecycle
from hardening.vm_bridge import BridgeStore, encode
from hardening.scan_exchange import ScanExchange
from test_evidence_import import MACHINE_UUID
from test_local_security_controls import local_security_fixture
from test_expanded_controls import observation
from test_investigation import MockClient


def scripted_clients(target, *, branch='proposal'):
    def message(name, reason=False, password=False):
        args = {'target_id': target}
        if password:
            args['control_id'] = '1.1.4'
        if reason:
            args['reason'] = 'Fixture decision from validated evidence and structured context.'
        return {'tool_calls': [{'function': {'name': name, 'arguments': args}}]}
    root = ['delegate_scanner']
    scan = [message('read_scan_coverage'), message('request_recollection' if branch == 'missing' else 'handoff_analysis', True)]
    analysis = [message('read_findings')]
    if branch != 'missing':
        root.append('delegate_analysis')
        if branch == 'compliant':
            analysis.append(message('finish_no_action', True))
        else:
            analysis += [message('read_operational_context'), message('handoff_remediation' if branch == 'proposal' else 'request_human_review', True)]
    if branch == 'proposal':
        root.append('delegate_remediation')
    clients = {
        ORCHESTRATOR: MockClient([message(name) for name in root] + [message('finish_team', True)]),
        SCANNER: MockClient(scan), ANALYSIS: MockClient(analysis),
        REMEDIATION: MockClient([message(name, name == 'submit_remediation_proposal', True) for name in
            ('get_finding_evidence', 'get_operational_context', 'get_supported_remediation', 'submit_remediation_proposal')]),
    }
    return clients


class AgentTeamTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.imports = ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3')
        self.runtime = AssessmentOrchestrator(self.imports)
        self.bridge = BridgeStore(Path(folder.name) / 'bridge.sqlite3', self.imports)
        self.lifecycle = RemediationLifecycle(self.runtime, self.bridge)

    def team(self, branch='proposal'):
        doc = local_security_fixture()
        observation(doc, '1.1.4')['value'] = 14 if branch == 'compliant' else 0
        if branch == 'missing':
            observation(doc, '1.1.4').update(state='missing', value=None)
        run = self.runtime.start(encode(doc), expected_hostname='FIXTURE-SERVER', expected_machine_uuid=MACHINE_UUID)
        self.runtime.complete_assessment(run.run_id)
        if branch != 'unknown':
            self.lifecycle.save_context(run.run_id, compatibility='incompatible' if branch == 'blocked' else 'compatible',
                operator='fixture', note='Synthetic test context only.')
        clients = scripted_clients(run.target_id, branch=branch)
        return AgentTeam(self.lifecycle, run.run_id, client_factory=clients.__getitem__), clients

    def test_four_isolated_conversations_and_durable_unapproved_handoff(self):
        team, clients = self.team()
        result = team.run()
        self.assertEqual(result['events'][-1]['data']['outcome']['outcome'], 'awaiting_approval')
        self.assertEqual(set(team.children), {SCANNER, ANALYSIS, REMEDIATION})
        prompts = [client.received[0][0]['content'] for client in clients.values()]
        self.assertEqual(len(set(prompts)), 4)
        for role, client in clients.items():
            self.assertEqual(len(client.received[0]), 2)
            self.assertIn(role, client.received[0][0]['content'])
        proposal = self.bridge.get(team.proposal_id)
        self.assertIsNone(proposal['decision']); self.assertIsNone(proposal['request'])
        reopened = BridgeStore(self.bridge.path, ImportedEvidenceStore(self.imports.path))
        traces = AgentTeam.traces(reopened, team.framework_run_id, team.team_id)
        self.assertEqual({t['agent_role'] for t in traces}, {ORCHESTRATOR, SCANNER, ANALYSIS, REMEDIATION})
        self.assertTrue(all(t['framework_run_id'] == team.framework_run_id for t in traces))
        self.assertEqual(AgentTeam.traces(reopened, 'other-run', team.team_id), [])

    def test_observation_dependent_routes_skip_unnecessary_agents(self):
        for branch, expected, count in [('compliant', 'no_action', 2), ('missing', 'awaiting_evidence', 1),
                                         ('unknown', 'manual_review', 2), ('blocked', 'manual_review', 2)]:
            with self.subTest(branch=branch):
                team, _ = self.team(branch)
                result = team.run()
                self.assertEqual(result['events'][-1]['data']['outcome']['outcome'], expected)
                self.assertEqual(len(team.children), count)
                self.assertIsNone(team.proposal_id)

    def test_specialists_cannot_cross_roles_or_approve(self):
        team, _ = self.team()
        for role in (SCANNER, ANALYSIS):
            tools = SpecialistTools(team, role, {})
            for name in ('submit_remediation_proposal', 'approve', 'execute', 'delegate_remediation'):
                with self.assertRaises(ValueError): tools.call(name, {'target_id': team.target_id})
        scanner = SpecialistTools(team, SCANNER, {})
        with self.assertRaises(ValueError): scanner.call('read_findings', {'target_id': team.target_id})
        with self.assertRaises(ValueError): scanner.call('read_scan_coverage', {'target_id': 'OTHER'})
        with self.assertRaises(ValueError): scanner.call('inspect_observation', {'target_id': team.target_id, 'control_id': 'invented'})
        with self.assertRaises(ValueError): scanner.call('read_scan_coverage', {'target_id': team.target_id, 'command': 'anything'})

    def test_handoff_order_no_action_and_repeat_guards(self):
        team, _ = self.team()
        args = {'target_id': team.target_id}
        with self.assertRaises(ValueError): team.call('delegate_remediation', args)
        with self.assertRaises(ValueError): team.call('delegate_analysis', args)
        with self.assertRaises(ValueError): team.call('finish_team', {**args, 'reason': 'skip'})
        team.call('delegate_scanner', args)
        with self.assertRaises(ValueError): team.call('delegate_scanner', args)
        with self.assertRaises(ValueError): team.call('finish_team', {**args, 'reason': 'skip Analysis'})
        analysis = SpecialistTools(team, ANALYSIS, team._outcome(SCANNER))
        with self.assertRaises(ValueError): analysis.call('handoff_remediation', {**args, 'reason': 'skip evidence'})
        analysis.call('read_findings', args)
        with self.assertRaises(ValueError): analysis.call('finish_no_action', {**args, 'reason': 'hide noncompliance'})

    def test_unknown_context_cannot_be_handed_to_remediation(self):
        team, _ = self.team('unknown')
        tools = SpecialistTools(team, ANALYSIS, {})
        args = {'target_id': team.target_id}
        tools.call('read_findings', args); tools.call('read_operational_context', args)
        with self.assertRaises(ValueError): tools.call('handoff_remediation', {**args, 'reason': 'ignore unknown'})
        self.assertFalse(self.lifecycle.get(team.framework_run_id)['attempts'])

    def test_context_revision_change_invalidates_team(self):
        team, _ = self.team()
        team.call('delegate_scanner', {'target_id': team.target_id})
        self.lifecycle.save_context(team.framework_run_id, compatibility='incompatible', operator='fixture', note='Changed dependency')
        with self.assertRaisesRegex(ValueError, 'context changed'):
            team.call('delegate_analysis', {'target_id': team.target_id})
        self.assertFalse(self.lifecycle.get(team.framework_run_id)['attempts'])

    def test_failed_specialist_has_no_successful_handoff(self):
        team, clients = self.team()
        clients[SCANNER] = MockClient([TimeoutError('fixture model unavailable')])
        team.call('delegate_scanner', {'target_id': team.target_id})
        self.assertIsNone(team._outcome(SCANNER))
        with self.assertRaises(ValueError): team.call('delegate_analysis', {'target_id': team.target_id})
        result = team.call('finish_team', {'target_id': team.target_id, 'reason': 'Scanner unavailable.'})
        self.assertEqual(result['outcome'], 'incomplete')
        self.assertIsNone(team.proposal_id)

    def test_model_cannot_report_execution_by_finishing_with_false_prose(self):
        team, _ = self.team()
        for name in ('delegate_scanner', 'delegate_analysis', 'delegate_remediation'):
            team.call(name, {'target_id': team.target_id})
        result = team.call('finish_team', {'target_id': team.target_id,
            'reason': 'All settings were applied and every control is now compliant.'})
        self.assertEqual(result['outcome'], 'awaiting_approval')
        self.assertIn('No change was executed', result['reason'])
        self.assertIn('Unverified', result['commentary_status'])
        self.assertIn('All settings were applied', result['model_commentary'])
        self.assertIsNone(self.bridge.get(team.proposal_id)['decision'])

    def test_analysis_receives_observation_separate_from_requirement(self):
        team, _ = self.team()
        tools = SpecialistTools(team, ANALYSIS, {})
        result = tools.call('read_findings', {'target_id': team.target_id})
        self.assertEqual(result['findings'][0]['observed_value'], 0)
        self.assertEqual(result['findings'][0]['required_rule']['expected'], 14)

    def test_scanner_recollection_queues_bound_request_and_stops_team(self):
        team, _ = self.team('missing')
        team.collection_exchange = ScanExchange(self.runtime, self.imports.path.parent / 'queue')
        run = team.run()
        outcome = run['events'][-1]['data']['outcome']
        self.assertEqual(outcome['outcome'], 'awaiting_evidence')
        self.assertEqual(outcome['collection_request']['state'], 'awaiting_worker')
        self.assertEqual(set(team.children), {SCANNER})
        import json
        request = json.loads(team.collection_exchange.get(outcome['collection_request']['request_id']))
        self.assertEqual('windows:' + request['machine_uuid'], team.target_id)
        self.assertEqual(request['operation'], 'collect_server2022_evidence')
        self.assertFalse(self.lifecycle.get(team.framework_run_id)['attempts'])

    def test_only_scanner_can_read_worker_status_without_treating_it_as_evidence(self):
        team, _ = self.team('missing')
        team.collection_exchange = ScanExchange(self.runtime, self.imports.path.parent / 'queue')
        tools = SpecialistTools(team, SCANNER, {})
        self.assertEqual(tools.call('get_collection_status', {'target_id':team.target_id})['state'], 'not_seen')
        with self.assertRaises(ValueError):
            tools.call('handoff_analysis', {'target_id':team.target_id,'reason':'worker status is enough'})
        analysis = SpecialistTools(team, ANALYSIS, {})
        with self.assertRaises(ValueError):
            analysis.call('get_collection_status', {'target_id':team.target_id})
