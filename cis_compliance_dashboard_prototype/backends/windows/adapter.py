"""Adapter around the original sibling Windows services. Their schemas and rules stay unchanged."""
from pathlib import Path
from uuid import uuid4
from dataclasses import replace

from backends.base import BoundBackend
from hardening.action_library import LIBRARY
from hardening.agentic import AgenticHardening, risk_analysis, verdict_kind
from hardening.domain import summarise
from hardening.framework import AssessmentRuns
from hardening.import_storage import ImportedEvidenceStore
from hardening.remediation import RemediationStore
from hardening.risk import analyse, BASELINE_VERSION, rule_text
from hardening.winrm_channel import LiveScanner
from system.contracts import (AssessmentMode, AssessmentSummary, Capabilities, ComparisonResult, ComplianceStatus,
    ControlRow, DecisionResult, FindingRow, HistoryRow, OperationState, ProposalRow, RecordRef, ResultRow,
    RoundHandle, TargetSummary, WorkspaceSnapshot)
from tools.baseline import verify_import_origin


def original_services(database_path, target, *, scanner_factory=LiveScanner):
    verify_import_origin(Path(__file__).resolve().parents[2])
    database_path = Path(database_path)
    imports = ImportedEvidenceStore(database_path)
    runtime = AssessmentRuns(imports)
    store = RemediationStore(database_path.with_name(database_path.stem + '_agentic.sqlite3'), imports)
    return runtime, store, AgenticHardening(runtime, store, scanner_factory(runtime, target))


class WindowsBackend(BoundBackend):
    def __init__(self, database_path, *, session, ledger, scanner_factory=LiveScanner, allow_mutation=False):
        super().__init__(session=session, ledger=ledger)
        self.runtime, self.store, self.engine = original_services(database_path, session.target, scanner_factory=scanner_factory)
        self.allow_mutation = allow_mutation

    def capabilities(self, connection_session_id):
        self.check(connection_session_id)
        return Capabilities(True, self.allow_mutation, True, False,
                            () if self.allow_mutation else ('Live execution is disabled until the coordination acceptance gate passes.',))

    def _ref(self, record):
        return RecordRef('windows', self.session.target_id, record)

    def _target(self, mode='Live (WinRM)'):
        s = self.session
        return TargetSummary(self._ref(s.target_id), s.identity.hostname, 'Windows Server 2022', 'winrm', mode,
                             'connected' if s.active else 'disconnected')

    def _rounds(self, binding):
        rounds = self.store.rounds(binding.backend_session_id)
        for row in rounds:
            if row['framework_run_id'] and self.runtime.get(row['framework_run_id']).target_id != self.session.target_id:
                raise ValueError('Stored Windows round has another target')
        return rounds

    def _latest(self, binding):
        rows = [r for r in self._rounds(binding) if r['kind'] == 'assessment']
        if not rows:
            raise ValueError('No assessment round')
        return rows[-1]

    def start_round(self, connection_session_id, workflow_session_id, goal, mode, operation_id):
        binding = self.check(connection_session_id, workflow_session_id)
        if goal:  # removed by the administrator (2026-11-07): results were too inconsistent
            raise ValueError('Round goals were removed. No scan was run.')
        if binding is None:
            s = self.session
            binding = self.ledger.assessment_binding('windows', s.target_id, s.registration_epoch, operation_id)
        mode = AssessmentMode(mode)
        owner, state = self.ledger.claim(binding, operation_id, 'assessment',
                                         {'intent': operation_id, 'mode': mode.value, 'goal': goal})
        if not owner:
            reference = self._ref(state.detail) if state.state == 'completed' and state.detail else None
            return RoundHandle(state.operation_id, binding, reference, state.state)
        try:
            if mode == AssessmentMode.AGENTIC:
                result = self.engine.run_round(binding.backend_session_id)
                round_id = result['round_id']
            else:
                scanned = self.engine.scanner.request(self.session.identity.hostname, self.session.identity.machine_identity)
                run_id = scanned['framework_run_id']
                analysis = risk_analysis(self.runtime.record(run_id), self.engine.history.previous_records(run_id))
                self.engine.history.record_drift(run_id)
                round_id = self.store.add_round(binding.backend_session_id, 'assessment', run_id,
                    orchestrator_run_id=None, children={}, analysis=analysis, analysis_outcome=None,
                    goal=None, scanned_runs=[run_id], mode='deterministic',
                    outcome={'outcome': 'no_fix_proposed', 'proposals': [], 'skipped': [],
                             'reason': 'Deterministic assessment without AI; no agent decisions or proposals were created.'})
            self.ledger.transition(operation_id, 'completed', detail=round_id)
            return RoundHandle(operation_id, binding, self._ref(round_id), 'completed')
        except Exception:
            self.ledger.transition(operation_id, 'unresolved', detail='Assessment interrupted; inspect durable records before continuing.')
            raise

    def snapshot(self, connection_session_id, workflow_session_id, round_ref=None):
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        if not binding:
            return WorkspaceSnapshot(self._target(), available_commands=('start_round',))
        rounds = self._rounds(binding)
        assessments = [r for r in rounds if r['kind'] == 'assessment']
        if not assessments:
            return WorkspaceSnapshot(self._target(), binding, available_commands=('start_round',))
        row = next((r for r in assessments if r['round_id'] == round_ref.record_id), None) if round_ref else assessments[-1]
        if row is None:
            raise ValueError('Round is outside this workflow')
        reference = self._ref(row['round_id'])
        if not row['framework_run_id']:
            return WorkspaceSnapshot(self._target(), binding, reference, step_states=('failed',) + ('pending',) * 5)
        run_id = row['framework_run_id']
        record = self.runtime.record(run_id)
        results = record.assessment.results
        counts = summarise(results)
        summary = AssessmentSummary.from_counts(self._ref(run_id), counts.selected, counts.compliant,
            counts.non_compliant, counts.unknown, counts.errors, results[0].control.catalogue_version,
            results[0].evidence.collected_at.isoformat())
        controls = tuple(ControlRow(r.control.control_id, r.control.title, r.control.area, r.control.profile,
            r.control.source_reference, ComplianceStatus(r.status.value), 'applicable', repr(r.evidence.value),
            rule_text(r.control.rule), evidence_references=(self._ref(run_id),)) for r in results)
        ranked = analyse(record, self.engine.history.previous_records(run_id))
        findings = tuple(FindingRow(f.control_id, **f.factors, score=f.score, level=f.level,
            derivation_reasons=tuple(f.factor_reasons.values()) + (f.exposure_reason, f.drift_reason),
            risk_policy_version=BASELINE_VERSION, rank=n) for n, f in enumerate(ranked, 1))
        proposals, receipts = [], []
        latest = row['round_id'] == assessments[-1]['round_id']
        for item in self.store.for_run(run_id):
            p = item['proposal']; action = LIBRARY[p['action_id']]; decision = item['decision_record'] or {}
            ref = self._ref(p['request_id'])
            proposals.append(ProposalRow(ref, 'control_remediation', p['control_id'], p['action_id'], action.title,
                'schema2', f"{p['expected_before']!r} → {p['value']!r}", (action.impact,), 'Registered VM recovery snapshot',
                (), item['decision'], decision.get('expires_at'), p['reason'],
                ('approve', 'reject') if latest and item['decision'] is None else ()))
            if item['verdict']:
                receipts.append(ResultRow(ref, verdict_kind(item['verdict']),
                    ComplianceStatus.COMPLIANT if item['verdict'] == 'Verified compliant' else None,
                    ref, None, 'not_requested', item['verdict']))
        deterministic = row.get('mode') == 'deterministic'
        steps = ('done', 'done', 'skipped' if deterministic else 'done',
                 'current' if any(p.decision is None for p in proposals) else 'skipped',
                 'done' if receipts else 'pending', 'done' if receipts else 'pending')
        goal = row.get('goal') or {}
        return WorkspaceSnapshot(self._target(results[0].evidence.mode.value), binding, reference, summary, controls,
            findings, tuple(proposals), tuple(receipts), (), steps, goal.get('text'), goal.get('read_as'),
            ('start_round', 'decide', 'execute_approved') if latest else (), row['created_at'])

    def decide(self, connection_session_id, workflow_session_id, proposal_ref, approved, operator, comment, operation_id):
        binding = self.check(connection_session_id, workflow_session_id, proposal_ref)
        if type(approved) is not bool:
            raise ValueError('Decision must be a boolean')
        latest = self._latest(binding)
        proposal = self.store.get(proposal_ref.record_id)['proposal']
        if proposal['framework_run_id'] != latest['framework_run_id'] or proposal['session_id'] != binding.backend_session_id:
            raise ValueError('Decisions are restricted to the latest round in this workflow')
        owner, state = self.ledger.claim(binding, operation_id, 'decision',
            {'proposal': proposal_ref.record_id, 'approved': approved, 'operator': operator, 'comment': comment})
        if not owner:
            return DecisionResult(proposal_ref, ('approved' if approved else 'rejected')
                                  if state.state == 'completed' else state.state, True)
        try:
            self.store.decide(proposal_ref.record_id, approve=approved, operator=operator, comment=comment)
            self.ledger.transition(operation_id, 'completed')
        except ValueError:
            self.ledger.transition(operation_id, 'refused', detail='Decision validation failed.')
            raise
        return DecisionResult(proposal_ref, 'approved' if approved else 'rejected')

    def execute_approved(self, connection_session_id, workflow_session_id, round_ref,
                         expected_approved_request_ids, deterministic, operation_id):
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        if not self.allow_mutation:
            raise ValueError('Live Windows dispatch is disabled until coordination acceptance passes')
        latest = self._latest(binding)
        if latest['round_id'] != round_ref.record_id:
            raise ValueError('Only the latest round may execute')
        def pending():
            return tuple(sorted(r['proposal']['request_id'] for r in self.store.for_run(latest['framework_run_id'])
                                if r['decision'] == 'approved' and r['verdict'] is None))
        expected = tuple(sorted(expected_approved_request_ids))
        if not expected or len(set(expected)) != len(expected) or pending() != expected:
            raise ValueError('Approved request set changed; review a new confirmation')
        owner, state = self.ledger.claim(binding, operation_id, 'execute',
            {'round': round_ref.record_id, 'approved': expected}, mutation=True)
        if not owner:
            return RoundHandle(operation_id, binding, round_ref, state.state)
        if pending() != expected:
            self.ledger.transition(operation_id, 'refused', detail='Approval set changed before dispatch.')
            raise ValueError('Approval set changed before dispatch')
        try:
            self.engine.execute_approved(binding.backend_session_id, deterministic=deterministic)
            records = [self.store.get(identifier) for identifier in expected]
            uncertain = any(not r['verdict'] or verdict_kind(r['verdict']) == 'uncertain' for r in records)
            self.ledger.transition(operation_id, 'unresolved' if uncertain else 'completed')
        except Exception:
            self.ledger.transition(operation_id, 'unresolved', detail='Dispatch may have happened; do not retry.')
            raise
        return RoundHandle(operation_id, binding, round_ref, 'unresolved' if uncertain else 'completed')

    def history(self, target_id=None, limit=50):
        self.check(self.session.connection_session_id)
        if target_id not in (None, self.session.target_id) or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('Invalid history scope')
        items = []
        allowed = self._epoch_runs()
        runs = [r for r in self.engine.history.runs(self.session.target_id) if r['run_id'] in allowed]
        for r in runs[-limit:]:
            summary = AssessmentSummary.from_counts(self._ref(r['run_id']), r['controls'], r['compliant'],
                r['non_compliant'], r['unknown'], r['error'], 'Windows Server 2022 CIS 2.0.0', r['created_at'])
            items.append(HistoryRow(summary.reference, self._target(r['evidence']), r['created_at'], summary.catalogue_id,
                                    summary, r['evidence'], 'assessment', None))
        return tuple(items)

    def _epoch_runs(self):
        bindings = self.ledger.bindings_for_target('windows', self.session.target_id, self.session.registration_epoch)
        return {row['framework_run_id'] for binding in bindings for row in self._rounds(binding)
                if row['framework_run_id']}

    def compare(self, before, after):
        self.check(self.session.connection_session_id)
        if (before.platform, before.target_id) != (after.platform, after.target_id) or before.target_id != self.session.target_id:
            return ComparisonResult(False, 'Different platform or target')
        if before.platform != 'windows':
            return ComparisonResult(False, 'Unsupported platform')
        allowed = self._epoch_runs()
        if before.record_id not in allowed or after.record_id not in allowed:
            return ComparisonResult(False, 'Assessment is outside this registration epoch')
        ordered = [r['run_id'] for r in self.engine.history.runs(self.session.target_id) if r['run_id'] in allowed]
        if ordered.index(before.record_id) >= ordered.index(after.record_id):
            return ComparisonResult(False, 'Choose distinct assessments in chronological order')
        a, b = self.runtime.record(before.record_id), self.runtime.record(after.record_id)
        if a.assessment.target_id != self.session.target_id or b.assessment.target_id != self.session.target_id:
            return ComparisonResult(False, 'Stored target mismatch')
        changes = self.engine.history.compare(before.record_id, after.record_id)
        return ComparisonResult(True, '', tuple((r['control_id'], str(r['before']), str(r['after'])) for r in changes))
