"""Ubuntu connection/capability boundary.

Assessment and execution stay closed until the source, collector, runner and recovery gates are met.
Stored assessments are served read-only after re-validation; this backend never invents findings,
risk scores or execution outcomes. Status is tracked in docs/INTEGRATION_PROGRESS.md.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from uuid import uuid4
from backends.base import BoundBackend
from system.contracts import (AgentEvent, AssessmentMode, AssessmentSummary, Capabilities, ComparisonResult, ComplianceStatus,
                              ControlRow, DecisionResult, HistoryRow, PlanRow, ProposalRow, RecordRef, ResultRow, RoundHandle,
                              Subcheck, TargetSummary, WorkspaceSnapshot)

APP = Path(__file__).resolve().parents[2]
CATALOGUE_LABEL = 'CIS Ubuntu Linux 22.04 LTS v2.0.0 (selected 30)'
CHECK_STATUS = {'pass': ComplianceStatus.COMPLIANT, 'fail': ComplianceStatus.NON_COMPLIANT, 'error': ComplianceStatus.ERROR}


LOCK = APP/'catalogues'/'source-lock.json'


@lru_cache(maxsize=1)
def _catalogue():
    from .catalogue import load_catalogue
    return load_catalogue(APP/'catalogues'/'ubuntu2204.json', LOCK)


def _controls():
    return {c.control_id: c for c in _catalogue().controls}


REFUSAL_DETAIL = {
    'stale_read_set': ('Not applied (stale_read_set): what this plan was approved against has changed since, usually '
                       'because another fix in this round changed the same file first. Nothing was written. Start a new '
                       'round to re-plan it, then approve and execute it on its own.')}


def refusal_detail(code):
    return REFUSAL_DETAIL.get(code, 'Not applied (' + code + ').')


def assessment_gate():
    """Reasons a live read-only Ubuntu assessment must not run. Empty means the gate is open."""
    try:
        ready = _catalogue().activation_ready
    except (OSError, ValueError):
        return ('Ubuntu assessment is not enabled: the pinned catalogue or source lock failed validation.',)
    if not ready:
        return ('Ubuntu assessment is not enabled: source/site-policy review is pending and the target OpenSCAP '
                'version is not recorded (catalogue activation is false). The collector helper must also be '
                'installed through approved setup.',)
    return ()


def execution_gate(backend=None):
    """Reasons Ubuntu writes must not be dispatched; empty only on evidence.

    Open only when the deployed runner matches this application (helper digest, every family version and hash,
    systemd launcher, enabled boot rollback) and this target passed both live acceptance scenarios against that
    same deployment: a commit-confirm change confirmed over a fresh login, and one restored by the rollback timer.
    """
    prefix = 'Ubuntu execution is not enabled: '
    if backend is None:
        return (prefix + 'the runner deployment and live acceptance are unverified; no write was dispatched.',)
    return tuple(prefix + reason for reason in backend._execution_reasons())


@dataclass(frozen=True)
class DeploymentStatus:
    ok: bool
    reasons: tuple
    runner_digest: str | None


@dataclass(frozen=True)
class AcceptanceRun:
    request_id: str
    scenario: str
    nonce: str
    state: str
    code: str
    outcome: str | None


@dataclass(frozen=True)
class PendingChange:
    """An approved Ubuntu change still running, waiting for confirmation or unresolved on this target."""
    workflow_session_id: str
    round_reference: object
    request_id: str
    control_id: str
    title: str
    outcome: str
    code: str


def _host_now():
    """Freshness of a preview is judged on the host clock alone: when the host received it. The VM's own stamp
    can be skewed; the runner re-reads the exact before-state at execution anyway (stale_read_set)."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


MAX_CLOCK_OFFSET_SECONDS = 30
# Auxiliary operations are never part of the CIS fix execution set.
AUXILIARY_PREFIXES = ('recovery.', 'maintenance.', 'acceptance.')


def _execution_operation(request_id):
    """One ledger operation per approved request, whatever page action dispatched it: never dispatched twice."""
    return 'ubuntu-execute:' + request_id


def accepted_engine_version():
    return json.loads(LOCK.read_text(encoding='utf-8'))['openscap_version']


@lru_cache(maxsize=1)
def _risk_policy():
    from .risk import load_policy
    return load_policy()


def _plan_rows(details, evidence, catalogue):
    """One row per Non-Compliant control: what the orchestrator decided and why, from its fixed reason codes."""
    from .agents import DEFAULT_FIX_REASONS, DEFER_REASONS, FIX_REASONS, FLAGS, LEGACY_FIX_REASONS
    plan = details.get('plan') or {}
    words = {**LEGACY_FIX_REASONS, **FIX_REASONS, **DEFAULT_FIX_REASONS}
    decided = {e['control_id']: ('Fix proposed', words.get(e['reason_code'], e['reason_code']))
               for e in plan.get('fixes', ())}
    decided.update({e['control_id']: ('Deferred', DEFER_REASONS.get(e['reason_code'], e['reason_code']))
                    for e in plan.get('decisions', ())})
    decided.update({e['control_id']: ('Deferred (by the app)', DEFER_REASONS[e['reason_code']])
                    for e in plan.get('deferred_by_code', ()) if e['reason_code'] in DEFER_REASONS})
    missing = ('Not decided', 'The planner left it out of its plan') if plan else (
        'No plan', 'The round stopped before the planner submitted a plan')
    flags = {}
    for f in (details.get('analysis') or {}).get('flags', ()):
        flags.setdefault(f['control_id'], []).append(FLAGS.get(f['flag_code'], f['flag_code']))
    return tuple(PlanRow(a.control_id, catalogue[a.control_id].title, *decided.get(a.control_id, missing),
                         '; '.join(flags.get(a.control_id, ())))
                 for a in evidence.assessments if a.status is ComplianceStatus.NON_COMPLIANT)


def preview_text(preview):
    """The stored target preview as readable lines for the Fixes tab; every key and value is kept."""
    lines = []
    for key in sorted(preview):
        label, value = key.replace('_', ' ').capitalize(), preview[key]
        if isinstance(value, dict):
            lines += [label + ':'] + ['  - %s = %s' % (k, _plain(v)) for k, v in sorted(value.items())]
        elif isinstance(value, (list, tuple)):
            lines += [label + ':'] + ['  - ' + _plain(v) for v in value]
        else:
            lines.append(label + ': ' + _plain(value))
    return chr(10).join(lines)


def _plain(value):
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


class UbuntuBackend(BoundBackend):
    def __init__(self, database_path, *, session, ledger, registered_firewall_manager=None,
                 model_client_factory=None, model_probe=None, families=None):
        super().__init__(session=session, ledger=ledger)
        self.database_path = Path(database_path)
        # UFW ownership is a reviewed deployment registration, never inferred from a running service.
        self.registered_firewall_manager = registered_firewall_manager
        if model_client_factory is None:
            from hardening.ollama_client import OllamaClient
            from .agents import ANALYSIS, ORCHESTRATOR
            # Output budgets per role. A plan deciding all 30 controls is ~1,400 tokens: the old shared 384-token
            # client truncated qwen3:8b's submit_plan live (empty reply, round "Unavailable", no proposals).
            # 2048 output plus a ~1,600-token prompt still fits the client's fixed 4,096-token context.
            clients = {role: OllamaClient(budget) for role, budget in ((ORCHESTRATOR, 2048), (ANALYSIS, 768))}
            default = OllamaClient(512)
            model_client_factory = lambda role: clients.get(role, default)  # noqa: E731 - loopback clients only
        if model_probe is None:
            from hardening.ollama_client import model_available as model_probe
        self.model_client_factory, self.model_probe = model_client_factory, model_probe
        if families is None:
            from .actions import FAMILIES as families  # empty until reviewed families are implemented
        self.families = families
        self._deployment = None  # read-only runner probe, cached for this verified connection

    def capabilities(self, connection_session_id):
        self.check(connection_session_id)
        gate = assessment_gate()
        model = not gate and self.model_probe()
        reasons = gate + (() if model or gate else
                          ('The local model (qwen3:8b) is unavailable; Assess without AI remains usable.',))
        if not self.families:
            reasons += ('No Ubuntu fix is registered: rounds defer every finding and propose no fix.',)
        reasons += execution_gate(self)
        if not _risk_policy().activated:
            reasons += ('Ubuntu risk ranking is withheld: the risk-attribute manifest is pending human review.',)
        return Capabilities(not gate, bool(self.families) and not execution_gate(self), bool(model), bool(gate), reasons)

    def _findings(self, store, row, evidence):
        """Deterministic ranking only under a reviewed policy; prior rounds of this target/epoch give D."""
        policy = _risk_policy()
        if not policy.activated:
            return ()
        from .risk import RiskInput, rank
        s = self.session
        previous = [RiskInput(self._ref(r.framework_run_id), r.round_id, self._evidence(store, r.evidence_sha256))
                    for b in self.ledger.bindings_for_target('ubuntu', s.target_id, s.registration_epoch)
                    for r in store.rounds(b) if r.round_id != row.round_id]
        return rank(RiskInput(self._ref(row.framework_run_id), row.round_id, evidence), previous, policy)

    # ---- stored, validated records (read-only) ----------------------------------------------
    def _store(self):
        # Never create the Ubuntu store just to read it.
        if not self.database_path.exists():
            return None
        from .storage import UbuntuStore
        return UbuntuStore(self.database_path)

    def _ref(self, record_id):
        return RecordRef('ubuntu', self.session.target_id, record_id)

    def _target(self, mode='No assessment collected'):
        s = self.session
        return TargetSummary(self._ref(s.target_id), s.identity.hostname, 'Ubuntu Server 22.04', 'ssh', mode,
                             'connected' if s.active else 'disconnected')

    def _evidence(self, store, digest):
        s = self.session
        evidence = store.get_evidence(digest, s.target_id, s.registration_epoch)
        if (evidence.expected.machine_id != s.identity.machine_identity
                or evidence.expected.hostname.casefold() != s.identity.hostname.casefold()):
            raise ValueError('Stored Ubuntu evidence does not match the verified target identity')
        return evidence

    def _runs(self, store):
        """Assessed runs of recorded rounds in registered workflows of this target/epoch (as Windows lists rounds' runs).

        A scan superseded by a rescan in the same round, or evidence left by an interrupted round, is not history.
        """
        s = self.session
        bindings = self.ledger.bindings_for_target('ubuntu', s.target_id, s.registration_epoch)
        assessed = {r.framework_run_id for b in bindings for r in store.rounds(b)}
        return [r for r in store.history(s.target_id, s.registration_epoch) if r.run_id in assessed]

    def _summary(self, run_id, evidence):
        counts = {status: sum(a.status is status for a in evidence.assessments) for status in ComplianceStatus}
        return AssessmentSummary.from_counts(self._ref(run_id), len(evidence.assessments),
            counts[ComplianceStatus.COMPLIANT], counts[ComplianceStatus.NON_COMPLIANT], counts[ComplianceStatus.UNKNOWN],
            counts[ComplianceStatus.ERROR], CATALOGUE_LABEL, evidence.completed_at)

    def history(self, target_id=None, limit=50):
        self.check(self.session.connection_session_id)
        if target_id not in (None, self.session.target_id) or type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError('Invalid history scope')
        store = self._store()
        if store is None:
            return ()
        rows = []
        for run in self._runs(store)[-limit:]:
            evidence = self._evidence(store, run.digest)
            mode = evidence.expected.evidence_mode
            rows.append(HistoryRow(self._ref(run.run_id), self._target(mode), evidence.completed_at, CATALOGUE_LABEL,
                                   self._summary(run.run_id, evidence), mode, 'assessment', None))
        return tuple(rows)

    def compare(self, before, after):
        self.check(self.session.connection_session_id)
        target = ('ubuntu', self.session.target_id)
        if (before.platform, before.target_id) != target or (after.platform, after.target_id) != target:
            return ComparisonResult(False, 'Different platform or target')
        store = self._store()
        ordered = [r.run_id for r in self._runs(store)] if store else []
        runs = {r.run_id: r for r in self._runs(store)} if store else {}
        if before.record_id not in runs or after.record_id not in runs:
            return ComparisonResult(False, 'Assessment is outside this registration epoch')
        if ordered.index(before.record_id) >= ordered.index(after.record_id):
            return ComparisonResult(False, 'Choose distinct assessments in chronological order')
        a, b = (self._evidence(store, runs[ref.record_id].digest) for ref in (before, after))
        old = {x.control_id: x.status for x in a.assessments}
        return ComparisonResult(True, '', tuple((x.control_id, old[x.control_id].value, x.status.value)
                                                for x in b.assessments if old[x.control_id] is not x.status))

    def snapshot(self, connection_session_id, workflow_session_id, round_ref=None):
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store() if binding else None
        all_rounds = store.rounds(binding) if store else ()
        rounds = tuple(r for r in all_rounds if r.kind == 'assessment')
        if not rounds:
            return WorkspaceSnapshot(self._target(), binding)
        row = next((r for r in rounds if r.round_id == round_ref.record_id), None) if round_ref else rounds[-1]
        if row is None:
            raise ValueError('Round is outside this workflow')
        evidence = self._evidence(store, row.evidence_sha256)
        catalogue = _controls()
        controls = []
        for result in evidence.assessments:
            control = catalogue[result.control_id]
            states = [c.state for c in result.checks]
            controls.append(ControlRow(control.control_id, control.title, control.area,
                f'L{control.server_level} Server ({control.cis_assessment_type})',
                'CIS Ubuntu 22.04 v2.0.0 p.' + ','.join(map(str, control.source_pages)), result.status,
                'not applicable' if states and set(states) == {'inapplicable'} else 'applicable',
                ', '.join(f'{name} {states.count(name)}' for name in sorted(set(states))) or 'no subchecks',
                control.assessment_contract,
                tuple(Subcheck(c.name, CHECK_STATUS.get(c.state, ComplianceStatus.UNKNOWN), c.reason or c.state)
                      for c in result.checks),
                (self._ref(row.framework_run_id),)))
        findings = self._findings(store, row, evidence)
        details = row.details or {}
        proposals, results = self._proposal_rows(store, binding, row, rounds[-1].round_id == row.round_id, all_rounds)
        if row.mode == 'agentic':
            decided = [p for p in proposals if p.decision]
            executed = [r for r in results]
            steps = ('done', 'done' if details.get('analysis') else 'failed', 'done' if details.get('plan') else 'failed',
                     ('current' if len(decided) < len(proposals) else 'done') if proposals else 'skipped',
                     ('done' if executed else 'pending') if any(p.decision == 'approved' for p in proposals) else 'skipped',
                     ('done' if all(r.verification_status is not None for r in executed) else 'pending')
                     if executed else 'skipped')  # verification is a fresh scan
            events = self._agent_events(store, details)
            plan = _plan_rows(details, evidence, catalogue)
        else:
            plan = ()
            steps = ('done', 'done' if _risk_policy().activated else 'pending', 'skipped', 'skipped', 'skipped', 'skipped')
            events = (AgentEvent(row.round_id, 'system', 'deterministic_assessment', '', '',
                                 'Read-only scan and deterministic predicates; no model was called and no proposal was created.',
                                 'no_ai', row.created_at, 'Deterministic (no AI)'),)
        return WorkspaceSnapshot(self._target(evidence.expected.evidence_mode), binding, self._ref(row.round_id),
                                 self._summary(row.framework_run_id, evidence), tuple(controls), findings,
                                 proposals, results, events=events, step_states=steps, goal=details.get('goal'),
                                 plan=plan)

    def _proposal_rows(self, store, binding, row, latest, all_rounds=()):
        proposals, results = [], []
        checks = [r for r in all_rounds if r.kind == 'verification' and (r.details or {}).get('verifies_round') == row.round_id]
        verified = self._evidence(store, checks[-1].evidence_sha256) if checks else None
        fresh = {a.control_id: a.status for a in verified.assessments} if verified else {}
        for p in store.proposals(binding, row.round_id):
            approved = json.loads(p.approved_raw) if p.approved_raw else None
            recovery = p.payload['fields']['recovery']
            action_id = p.payload['action']['action_id']
            kind = {'recovery.restore.v1': 'recovery', 'maintenance.apt_refresh.v1': 'metadata_refresh',
                    'maintenance.reboot.v1': 'reboot'}.get(action_id, 'control_remediation')
            proposals.append(ProposalRow(self._ref(p.proposal_id), kind, p.payload['fields']['control_id'],
                p.payload['action']['action_id'], p.payload['title'], 'v%d' % p.payload['action']['version'],
                preview_text(p.payload['preview']), (), recovery['kind'] + ': ' + ', '.join(recovery['scope']),
                (), p.decision, approved['expires_at'] if approved else None,
                'Deterministic plan from the registered family; the target preview supplied the before/after digests.',
                ('approve', 'reject') if latest and p.decision is None else (),
                approved['request_id'] if approved else None, approved['before_state_sha256'] if approved else None))
            if p.receipts:
                last = p.receipts[-1]
                applied = last['outcome'] in ('applied', 'reconciled_applied')
                status = fresh.get(p.payload['fields']['control_id']) if applied and verified else None
                if applied and status is None:
                    detail = 'Applied as approved; a fresh verification scan is required before it counts as compliant.'
                elif applied:
                    detail = 'Applied; fresh verification: ' + status.value + '.' + (
                        '' if status is ComplianceStatus.COMPLIANT else ' No automatic retry; review before any new plan.')
                elif last['outcome'] == 'unresolved':
                    detail = 'Outcome unknown; reconcile before any further change.'
                elif (last['outcome'], last['code']) == ('running', 'awaiting_reboot'):
                    detail = ('Reboot scheduled. The connection drops; reconnect when the VM is back, then Check status: '
                              'the new boot ID is verified and a fresh scan follows.')
                elif (last['outcome'], last['code']) == ('running', 'awaiting_confirmation'):
                    detail = ('Applied and waiting for confirmation. Disconnect, reconnect to the VM (a fresh login '
                              'proves SSH still works), then confirm before the rollback timer restores it.')
                elif last['outcome'] == 'running':
                    detail = 'Running under systemd supervision (' + last['code'] + '); check its status.'
                elif last['outcome'] == 'rolled_back':
                    detail = ('Rolled back (' + last['code'] + '): not confirmed in time or failed, so the target '
                              'restored the before-state. Not applied.')
                else:
                    detail = refusal_detail(last['code'])
                results.append(ResultRow(self._ref(p.proposal_id), last['outcome'], status, self._ref(last['request_id']),
                                         self._ref(checks[-1].framework_run_id) if status is not None else None,
                                         'not_requested', detail))
        return tuple(proposals), tuple(results)

    def _agent_events(self, store, details):
        """Durable Coordinator events of the round's agents, as common Agent log rows."""
        from hardening.investigation import InvestigationLog
        log, rows = InvestigationLog(store.agent_log()), []
        for run_id in [details['orchestrator_run_id'], *details['children'].values()]:
            run = log.get(run_id)
            for event in run['events']:
                data, kind = event['data'], event['kind']
                if kind == 'tool':
                    summary, code = json.dumps(data.get('result'), sort_keys=True)[:300], ''
                elif kind == 'tool_rejected':
                    summary, code = 'Refused: ' + str(data.get('error', ''))[:200], 'refused'
                elif kind == 'nudge':
                    summary, code = 'Reminded to answer with exactly one tool call.', ''
                elif kind == 'finished':
                    outcome = data.get('outcome') or {}
                    summary, code = (str(data.get('status')) + ': ' + str(data.get('summary', ''))[:200]), str(outcome.get('outcome', ''))
                else:
                    continue
                rows.append(AgentEvent(run_id, str(run.get('agent_role', 'unknown')), kind, str(data.get('name', ''))[:80],
                                       json.dumps(data.get('arguments', {}), sort_keys=True)[:300], summary, code,
                                       event['created_at'], f"{run['provenance']} ({run['model']})"))
        return tuple(sorted(rows, key=lambda r: r.timestamp))

    # ---- closed commands --------------------------------------------------------------------
    def _collection_request(self, request_id):
        """Ownership the helper must echo and the host re-validates; built only from verified session facts."""
        from .envelope import ExpectedEvidence
        from vm.ubuntu.provenance import collector_digest
        s, lock_bytes = self.session, LOCK.read_bytes()
        expected = ExpectedEvidence(s.target_id, s.registration_epoch, s.identity.hostname, s.identity.machine_identity,
                                    request_id, json.loads(lock_bytes)['benchmark_sha256'],
                                    hashlib.sha256(lock_bytes).hexdigest(), collector_digest(APP/'vm'/'ubuntu'),
                                    'Live (SSH)')
        request = {k: getattr(expected, k) for k in ('target_id', 'registration_epoch', 'hostname', 'machine_id',
                   'request_id', 'benchmark_sha256', 'source_lock_sha256', 'evidence_mode')}
        return request, expected

    def start_round(self, connection_session_id, workflow_session_id, goal, mode, operation_id):
        """Read-only deterministic assessment: one helper invocation, validated and stored, at most once per operation."""
        binding = self.check(connection_session_id, workflow_session_id)
        if goal:  # disabled by the administrator (2026-11-07) and due for removal
            raise ValueError('Round goals are disabled for Ubuntu. No scan was run.')
        gate = assessment_gate()
        if gate:
            raise ValueError(gate[0] + ' No scan was run.')
        mode = AssessmentMode(mode)
        if mode is AssessmentMode.AGENTIC and not self.model_probe():
            raise ValueError('The local model is unavailable; use Assess without AI. No scan was run.')
        s = self.session
        if binding is None:
            binding = self.ledger.assessment_binding('ubuntu', s.target_id, s.registration_epoch, operation_id)
        owner, state = self.ledger.claim(binding, operation_id, 'assessment',
                                         {'intent': operation_id, 'mode': mode.value, 'goal': goal})
        if not owner:
            reference = self._ref(state.detail) if state.state == 'completed' and state.detail else None
            return RoundHandle(state.operation_id, binding, reference, state.state)
        from .storage import UbuntuStore
        store = UbuntuStore(self.database_path)
        collect = lambda: self._collect(store, binding)  # noqa: E731
        try:
            if mode is AssessmentMode.DETERMINISTIC:
                run_id, _ = collect()
                round_id = store.record_round(binding, run_id, mode='deterministic')
            else:
                round_id = self._agentic_round(store, binding, collect, goal)
        except Exception:
            # Read-only: nothing changed on the VM. Partial evidence is reported as an orphan, never a round.
            self.ledger.transition(operation_id, 'refused', detail='Read-only Ubuntu assessment did not complete.')
            raise
        self.ledger.transition(operation_id, 'completed', detail=round_id)
        return RoundHandle(operation_id, binding, self._ref(round_id), 'completed')

    def _collect(self, store, binding):
        """One read-only helper invocation, validated and stored before it is used."""
        request, expected = self._collection_request(uuid4().hex)
        message = json.dumps({'request': request, 'scap_engine_version': accepted_engine_version(),
                              'registered_firewall_manager': self.registered_firewall_manager},
                             sort_keys=True, separators=(',', ':')).encode('ascii')
        run = store.start_run(self.session.channel.invoke_helper(message), expected, binding)
        return run.run_id, self._evidence(store, run.digest)

    def _agentic_round(self, store, binding, collect, goal):
        from .agents import run_agentic_round
        def rank(run_id, evidence):
            policy = _risk_policy()
            if not policy.activated:
                return None
            from .risk import RiskInput, rank as derive
            return derive(RiskInput(self._ref(run_id), 'current', evidence), (), policy)
        result = run_agentic_round(client_factory=self.model_client_factory, collect=collect, log_store=store.agent_log(),
                                   target_id=self.session.target_id, titles={c: x.title for c, x in _controls().items()},
                                   rank=rank, goal=goal, eligible=self._eligible)
        if result['run_id'] is None:
            raise ValueError(f"The agentic round stopped before an assessment was collected ({result['status']}). Its agent "
                             'log is kept; use Assess without AI for a deterministic assessment.')
        details = {k: result[k] for k in ('orchestrator_run_id', 'children', 'scanned_runs', 'status', 'analysis', 'plan', 'goal')}
        round_id = store.record_round(binding, result['run_id'], mode='agentic', details=details)
        for fix in (result['plan'] or {}).get('fixes', []):
            self._propose(store, binding, round_id, result['evidence'], fix)
        return round_id

    # ---- remediation proposals, decisions and gated execution --------------------------------
    def _eligible(self, evidence):
        """Confirmed failures a registered family can plan deterministically: control -> action ID."""
        failing = {a.control_id for a in evidence.assessments if a.status is ComplianceStatus.NON_COMPLIANT}
        eligible = {}
        for action_id, spec in sorted(self.families.items()):
            for cid in spec.control_ids:
                if cid in failing and cid not in eligible and spec.propose and spec.propose(cid, evidence) is not None:
                    eligible[cid] = action_id
        return eligible

    def _propose(self, store, binding, round_id, evidence, fix):
        """Read-only target preview, then a stored deterministic plan. A failed preview creates no proposal."""
        from vm.ubuntu.remediation_schema import canonical
        from .actions import plan_action
        spec = self.families[fix['action_id']]
        params = spec.propose(fix['control_id'], evidence)
        header = canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params})
        try:
            preview = json.loads(self.session.channel.invoke_runner(header + b'\n'))
            if type(preview) is not dict or preview.get('action_id') != spec.action_id:
                raise ValueError('Preview for another action')
            s = self.session
            plan = plan_action(spec, families=self.families, parameters=params, target_id=s.target_id,
                               registration_epoch=s.registration_epoch, hostname=s.identity.hostname,
                               machine_id=s.identity.machine_identity, workflow_session_id=binding.workflow_session_id,
                               round_id=round_id, evidence_sha256=evidence.raw_sha256, control_id=fix['control_id'],
                               predicate_id=_controls()[fix['control_id']].predicate_id,
                               before_state_sha256=preview['before_state_sha256'],
                               expected_after_sha256=preview['expected_after_sha256'],
                               before_state_collected_at=_host_now(), recovery=spec.recovery,
                               job_deadline_seconds=spec.max_seconds)
            store.add_proposal(binding, plan, title=spec.title, preview=preview['summary'])
        except (ValueError, KeyError, TypeError, OSError, TimeoutError):
            return None
        return plan.proposal_id

    def _latest(self, store, binding, round_ref=None):
        rounds = tuple(r for r in (store.rounds(binding) if store else ()) if r.kind == 'assessment')
        if not rounds or (round_ref is not None and rounds[-1].round_id != round_ref.record_id):
            raise ValueError('Only the latest round of this workflow can be decided or executed')
        return rounds[-1]

    def decide(self, connection_session_id, workflow_session_id, proposal_ref, approved, operator, comment, operation_id):
        """Approve (exact request bytes) or reject one proposal of the latest round. Writes nothing on the VM."""
        from datetime import datetime, timezone
        from .actions import ActionPlan
        from .approvals import approve
        binding = self.check(connection_session_id, workflow_session_id, proposal_ref)
        if binding is None:
            raise ValueError('A workflow is required to decide')
        store = self._store()
        latest = self._latest(store, binding)
        payload = store._proposal(binding, proposal_ref.record_id)
        if payload['round_id'] != latest.round_id:
            raise ValueError('Only proposals of the latest round can be decided')
        owner, state = self.ledger.claim(binding, operation_id, 'decision',
                                         {'proposal_id': proposal_ref.record_id, 'approved': bool(approved)})
        if not owner:
            return DecisionResult(proposal_ref, state.detail or state.state, True)
        now = datetime.now(timezone.utc)
        try:
            if approved:
                from .actions import AUXILIARY
                spec = dict(self.families, **AUXILIARY).get(payload['action']['action_id'])
                if spec is None or (spec.version, spec.implementation_sha256) != (
                        payload['action']['version'], payload['action']['implementation_sha256']):
                    raise ValueError('The proposal\'s action family is no longer registered at this version')
                request = approve(ActionPlan(spec, proposal_ref.record_id, payload['fields']), operator, now)
                existing = store.record_decision(binding, proposal_ref.record_id, approved=request)
            else:
                existing = store.record_decision(binding, proposal_ref.record_id, rejected=(operator, now))
            if comment:
                store.add_comment(binding, proposal_ref.record_id, operator, comment, now)
        except Exception:
            self.ledger.transition(operation_id, 'refused', detail='Decision was not recorded.')
            raise
        result = 'approved' if approved else 'rejected'
        self.ledger.transition(operation_id, 'completed', detail=result)
        return DecisionResult(proposal_ref, result, existing)

    def execute_approved(self, connection_session_id, workflow_session_id, round_ref,
                         expected_approved_request_ids, deterministic, operation_id):
        """Dispatch exactly the expected approved set, sequentially; stop at the first uncertain outcome."""
        from datetime import datetime, timezone
        from vm.ubuntu.remediation_schema import parse_request
        from .approvals import ApprovedRequest
        from .executor import execute
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        gate = execution_gate(self)
        if gate:
            raise ValueError(gate[0])
        store = self._store()
        latest = self._latest(store, binding, round_ref)
        approved = [p for p in store.proposals(binding, latest.round_id)
                    if p.decision == 'approved' and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)]
        requests = {json.loads(p.approved_raw)['request_id']: p for p in approved}
        if not requests or set(expected_approved_request_ids) != set(requests):
            raise ValueError('The approved set changed or is empty; review the current approvals. No write was dispatched.')
        state, applied = 'completed', []
        for request_id, proposal in requests.items():
            if proposal.receipts:
                continue  # already dispatched once; never again
            result = self._dispatch_one(store, binding, proposal, operation_id)
            if result.state == 'completed':
                applied.append(request_id)
                continue
            state = result.state
            if result.state != 'refused':
                break  # uncertain (unresolved, running): nothing more until it is settled
            # A refusal is definite (nothing was written), so the independent fixes still run. Live 13:44: after 1.5.1
            # changed the shared sysctl file, 1.5.3/3.3.1/3.3.8 were refused stale and 5.2.3 never ran.
        return RoundHandle(operation_id, binding, round_ref, self._verify(store, binding, latest, applied, state))

    def _dispatch_one(self, store, binding, proposal, operation_id):
        from datetime import datetime, timezone
        from vm.ubuntu.remediation_schema import parse_request
        from .approvals import ApprovedRequest
        from .executor import execute
        raw = proposal.approved_raw
        request_id = json.loads(raw)['request_id']
        result = execute(ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw)), ledger=self.ledger,
                         binding=binding, operation_id=_execution_operation(request_id),
                         dispatch=lambda data: self.session.channel.invoke_runner(b'{"op":"execute"}\n' + data),
                         now=datetime.now(timezone.utc))
        if result.receipt_raw is not None:
            store.record_receipt(binding, proposal.proposal_id, result.receipt_raw)
        return result

    # ---- execution acceptance: deployment probe and the two live scenarios ----------------------------
    def deployment_status(self, connection_session_id):
        """Read-only probe of the root-owned runner, cached per verified connection."""
        self.check(connection_session_id)
        if self._deployment is None:
            self._deployment = self._probe_deployment()
        return self._deployment

    def _probe_deployment(self):
        from vm.ubuntu.provenance import collector_digest
        from .actions import AUXILIARY
        from datetime import datetime, timezone
        try:
            sent = datetime.now(timezone.utc)
            probe = json.loads(self.session.channel.invoke_runner(b'{"op":"probe"}\n'))
            received = datetime.now(timezone.utc)
            if type(probe) is not dict or set(probe) != {'collector_digest', 'now', 'families', 'launcher', 'boot_rollback'}:
                raise ValueError('Unexpected probe')
            offset = (datetime.fromisoformat(probe['now']) - (sent + (received - sent) / 2)).total_seconds()
        except Exception:
            return DeploymentStatus(False, ('The root-owned runner is not deployed or refused the probe; install-runner.sh '
                                            'needs its separate approval.',), None)
        reasons = []
        if abs(offset) > MAX_CLOCK_OFFSET_SECONDS:
            reasons.append('The VM clock differs from this computer by %d s (more than %d s); fix time sync on the VM '
                           '(timedatectl) and reconnect.' % (round(offset), MAX_CLOCK_OFFSET_SECONDS))
        if probe['collector_digest'] != collector_digest(APP / 'vm' / 'ubuntu'):
            reasons.append('The deployed helper differs from this application; reinstall the bundle first.')
        expected = {aid: [spec.version, spec.implementation_sha256] for aid, spec in dict(self.families, **AUXILIARY).items()}
        if any(probe['families'].get(aid) != value for aid, value in expected.items()):
            reasons.append('The deployed runner registers different fix families or versions.')
        if probe['launcher'] is not True:
            reasons.append('systemd-run is unavailable on the VM, so supervised jobs cannot run.')
        if probe['boot_rollback'] != 'enabled':
            reasons.append('The boot rollback unit is not enabled (install-runner.sh).')
        return DeploymentStatus(not reasons, tuple(reasons), probe['collector_digest'])

    def _acceptance_runs(self):
        s = self.session
        return self.ledger.acceptance_runs(s.target_id, s.registration_epoch)

    def _execution_reasons(self):
        deployment = self.deployment_status(self.session.connection_session_id)
        if not deployment.ok:
            return deployment.reasons
        passed = {(r['scenario'], r['outcome']) for r in self._acceptance_runs()
                  if r['runner_digest'] == deployment.runner_digest}
        reasons = []
        if ('confirm', 'confirmed') not in passed:
            reasons.append('Execution acceptance pending: run the confirm scenario (apply, reconnect, confirm).')
        if ('rollback', 'rolled_back') not in passed:
            reasons.append('Execution acceptance pending: run the rollback scenario (apply, do not confirm; '
                           'the timer restores it).')
        return tuple(reasons)

    def _acceptance_view(self, run, receipt=None):
        params = json.loads(run['raw'])['parameters']
        code = receipt['code'] if receipt is not None else (run['outcome'] or 'job_started')
        state = receipt['outcome'] if receipt is not None else ('settled' if run['outcome'] else 'running')
        return AcceptanceRun(run['request_id'], run['scenario'], params['nonce'], state, code, run['outcome'])

    def _settle_acceptance(self, run, receipt):
        if receipt['outcome'] == 'applied' and receipt['code'] == 'confirmed':
            outcome = 'confirmed'
        elif receipt['outcome'] == 'rolled_back':
            outcome = 'rolled_back'
        elif receipt['outcome'] in ('running', 'unresolved'):
            return None
        else:
            outcome = 'failed:' + receipt['code']
        self.ledger.settle_acceptance(run['request_id'], outcome)
        return outcome

    def start_acceptance(self, connection_session_id, scenario, operator, operation_id):
        """Apply the harmless marker through the real approval, runner and systemd path."""
        from datetime import datetime, timezone
        from vm.ubuntu.remediation_schema import canonical
        from .actions import AUXILIARY, plan_action
        from .approvals import approve
        from .executor import execute
        self.check(connection_session_id)
        if scenario not in ('confirm', 'rollback') or type(operator) is not str or not operator.strip():
            raise ValueError('Choose the confirm or rollback scenario and name the operator')
        deployment = self.deployment_status(connection_session_id)
        if not deployment.ok:
            raise ValueError(deployment.reasons[0])
        if any(r['outcome'] is None for r in self._acceptance_runs()):
            raise ValueError('An acceptance run is still open; check its status first')
        s, spec, nonce = self.session, AUXILIARY['acceptance.marker.v1'], uuid4().hex
        params = {'scenario': scenario, 'nonce': nonce}
        preview = json.loads(self.session.channel.invoke_runner(
            canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params}) + b'\n'))
        binding = self.ledger.assessment_binding('ubuntu', s.target_id, s.registration_epoch, 'acceptance:' + operation_id)
        plan = plan_action(spec, families=AUXILIARY, parameters=params, target_id=s.target_id,
                           registration_epoch=s.registration_epoch, hostname=s.identity.hostname,
                           machine_id=s.identity.machine_identity, workflow_session_id=binding.workflow_session_id,
                           round_id=nonce, evidence_sha256=hashlib.sha256(deployment.runner_digest.encode()).hexdigest(),
                           control_id='acceptance', predicate_id='ubuntu.acceptance.predicate.v1',
                           before_state_sha256=preview['before_state_sha256'],
                           expected_after_sha256=preview['expected_after_sha256'],
                           before_state_collected_at=_host_now(), recovery=spec.recovery,
                           job_deadline_seconds=spec.max_seconds)
        approved = approve(plan, operator, datetime.now(timezone.utc))
        request_id = approved.request['request_id']
        self.ledger.add_acceptance(request_id, s.target_id, s.registration_epoch, scenario, deployment.runner_digest,
                                   approved.raw)
        result = execute(approved, ledger=self.ledger, binding=binding, operation_id=_execution_operation(request_id),
                         dispatch=lambda data: self.session.channel.invoke_runner(b'{"op":"execute"}\n' + data),
                         now=datetime.now(timezone.utc))
        run = next(r for r in self._acceptance_runs() if r['request_id'] == request_id)
        if result.receipt is not None:
            self._settle_acceptance(run, result.receipt)
            run = next(r for r in self._acceptance_runs() if r['request_id'] == request_id)
        return self._acceptance_view(run, result.receipt)

    def acceptance_status(self, connection_session_id):
        """Target status of open acceptance runs (never a write); settled runs are read from the ledger."""
        from vm.ubuntu.remediation_schema import canonical, parse_request
        from .approvals import ApprovedRequest
        from .executor import reconcile
        self.check(connection_session_id)
        views = []
        for run in self._acceptance_runs():
            receipt = None
            if run['outcome'] is None:
                raw = run['raw']
                approved = ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))
                header = canonical({'op': 'reconcile', 'request_id': run['request_id']})
                result = reconcile(approved, ledger=self.ledger, operation_id=_execution_operation(run['request_id']),
                                   status=lambda rid: self.session.channel.invoke_runner(header + b'\n'))
                receipt = result.receipt
                if receipt is not None:
                    operation = _execution_operation(run['request_id'])
                    if (receipt['code'] == 'awaiting_confirmation'
                            and self.ledger.first_event(operation, 'awaiting_confirmation') is None):
                        self.ledger.note(operation, 'awaiting_confirmation')
                    if self._settle_acceptance(run, receipt):
                        run = next(r for r in self._acceptance_runs() if r['request_id'] == run['request_id'])
            views.append(self._acceptance_view(run, receipt))
        return tuple(views)

    def confirm_acceptance(self, connection_session_id, request_id):
        """The confirm scenario only, over a login begun after the host saw it waiting."""
        from datetime import datetime
        from vm.ubuntu.remediation_schema import canonical, parse_request
        from .approvals import ApprovedRequest
        from .executor import confirm
        self.check(connection_session_id)
        run = next((r for r in self._acceptance_runs() if r['request_id'] == request_id and r['outcome'] is None), None)
        if run is None:
            raise ValueError('No open acceptance run with this request')
        if run['scenario'] != 'confirm':
            raise ValueError('The rollback scenario must be left to its timer; do not confirm it')
        operation = _execution_operation(request_id)
        observed = self.ledger.first_event(operation, 'awaiting_confirmation')
        login = self.session.connected_at
        if observed is None or not login or datetime.fromisoformat(login) <= datetime.fromisoformat(observed):
            raise ValueError('Confirmation needs a fresh login: disconnect, reconnect to the VM, then confirm. '
                             'That new login is the proof the change kept SSH working.')
        raw = run['raw']
        approved = ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))
        header = canonical({'op': 'confirm', 'request_id': request_id})
        result = confirm(approved, ledger=self.ledger, operation_id=operation,
                         send=lambda rid: self.session.channel.invoke_runner(header + b'\n'))
        if result.receipt is not None:
            self._settle_acceptance(run, result.receipt)
        run = next(r for r in self._acceptance_runs() if r['request_id'] == request_id)
        return self._acceptance_view(run, result.receipt)

    # ---- supervised jobs: status and reconnect-to-confirm ---------------------------------------
    def _open_requests(self, store, binding, latest):
        for p in store.proposals(binding, latest.round_id):
            if p.decision == 'approved' and p.receipts and p.receipts[-1]['outcome'] in ('running', 'unresolved'):
                yield p

    def _record_status(self, store, binding, proposal, result):
        """Store a status receipt only when outcome or code changed; note the first awaiting_confirmation."""
        receipt = result.receipt
        if receipt is None:
            return
        last = proposal.receipts[-1] if proposal.receipts else None
        if last is None or (last['outcome'], last['code']) != (receipt['outcome'], receipt['code']):
            store.record_receipt(binding, proposal.proposal_id, result.receipt_raw)
        operation = _execution_operation(receipt['request_id'])
        if receipt['code'] == 'awaiting_confirmation' and self.ledger.first_event(operation, 'awaiting_confirmation') is None:
            self.ledger.note(operation, 'awaiting_confirmation')

    def pending_supervised(self, connection_session_id):
        """Open changes on this target across its workflows, so a fresh login can find what waits for it."""
        self.check(connection_session_id)
        s, store, found = self.session, self._store(), []
        if store is None:
            return ()  # no assessment stored yet, so no approved change can be open
        for binding in self.ledger.bindings_for_target('ubuntu', s.target_id, s.registration_epoch):
            rounds = [r for r in store.rounds(binding) if r.kind == 'assessment']
            if not rounds:
                continue
            for p in store.proposals(binding, rounds[-1].round_id):
                if p.decision == 'approved' and p.receipts and p.receipts[-1]['outcome'] in ('running', 'unresolved'):
                    last = p.receipts[-1]
                    found.append(PendingChange(binding.workflow_session_id, self._ref(rounds[-1].round_id),
                                               last['request_id'], p.payload['fields']['control_id'], p.payload['title'],
                                               last['outcome'], last['code']))
        return tuple(found)

    def refresh_execution(self, connection_session_id, workflow_session_id, round_ref, operation_id):
        """Ask the target for the status of running or unresolved requests. Never dispatches a write."""
        from vm.ubuntu.remediation_schema import canonical, parse_request
        from .approvals import ApprovedRequest
        from .executor import reconcile
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store()
        latest = self._latest(store, binding, round_ref)
        state, applied = 'completed', []
        for proposal in self._open_requests(store, binding, latest):
            raw = proposal.approved_raw
            approved = ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))
            request_id = approved.request['request_id']
            header = canonical({'op': 'reconcile', 'request_id': request_id})
            result = reconcile(approved, ledger=self.ledger, operation_id=_execution_operation(request_id),
                               status=lambda rid: self.session.channel.invoke_runner(header + b'\n'))
            self._record_status(store, binding, proposal, result)
            if result.state == 'running':
                state = 'awaiting_confirmation' if result.receipt['code'] == 'awaiting_confirmation' else 'running'
            elif result.state == 'completed':
                if not proposal.payload['action']['action_id'].startswith('recovery.'):
                    applied.append(request_id)  # CIS fixes and maintenance are followed by a fresh scan
            elif state == 'completed':
                state = result.state
        return RoundHandle(operation_id, binding, round_ref, self._verify(store, binding, latest, applied, state))

    def confirm_change(self, connection_session_id, workflow_session_id, round_ref, request_id, operation_id):
        """Confirm a commit-confirm change over this connection, which must be a login begun after the host saw
        the change waiting. Without a confirmation the target's timer restores the before-state."""
        from datetime import datetime
        from vm.ubuntu.remediation_schema import canonical, parse_request
        from .approvals import ApprovedRequest
        from .executor import confirm
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store()
        latest = self._latest(store, binding, round_ref)
        proposal = next((p for p in store.proposals(binding, latest.round_id) if p.approved_raw
                         and json.loads(p.approved_raw)['request_id'] == request_id), None)
        if (proposal is None or not proposal.receipts
                or (proposal.receipts[-1]['outcome'], proposal.receipts[-1]['code']) != ('running', 'awaiting_confirmation')):
            raise ValueError('This change is not waiting for confirmation; check its status first.')
        operation = _execution_operation(request_id)
        observed = self.ledger.first_event(operation, 'awaiting_confirmation')
        login = self.session.connected_at
        if observed is None or not login or datetime.fromisoformat(login) <= datetime.fromisoformat(observed):
            raise ValueError('Confirmation needs a fresh login: disconnect, reconnect to the VM, then confirm. '
                             'That new login is the proof the change kept SSH working.')
        raw = proposal.approved_raw
        approved = ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))
        header = canonical({'op': 'confirm', 'request_id': request_id})
        result = confirm(approved, ledger=self.ledger, operation_id=operation,
                         send=lambda rid: self.session.channel.invoke_runner(header + b'\n'))
        self._record_status(store, binding, proposal, result)
        applied = [request_id] if result.state == 'completed' else []
        return RoundHandle(operation_id, binding, round_ref, self._verify(store, binding, latest, applied, result.state))

    def _verify(self, store, binding, latest, applied, state):
        if applied:
            # Fresh read-only verification with the same predicates; failure leaves Verify pending, never a retry.
            try:
                run_id, _ = self._collect(store, binding)
                store.record_round(binding, run_id, mode='deterministic', kind='verification',
                                   details={'verifies_round': latest.round_id, 'request_ids': sorted(applied)})
            except Exception:
                state = 'verification_pending'  # applied, but no fresh evidence yet; never a retry
        return state

    # ---- auxiliary: approved restore of an applied fix ------------------------------------------
    def _request_maintenance(self, binding, kind, inputs, operation_id):
        """Metadata refresh or reboot as an auxiliary proposal of the latest round (approve, then dispatch)."""
        from system.contracts import AuxiliaryKind, MetadataRefreshInput, RebootInput
        from vm.ubuntu.remediation_schema import canonical
        from .actions import AUXILIARY, plan_action
        if binding is None:
            raise ValueError('Maintenance belongs to a workflow: run an assessment first')
        store = self._store()
        latest = self._latest(store, binding)
        proposals = store.proposals(binding, latest.round_id)
        nonce = uuid4().hex
        if kind is AuxiliaryKind.METADATA_REFRESH:
            if type(inputs) is not MetadataRefreshInput or type(inputs.repository_digest) is not str:
                raise ValueError('Metadata refresh needs the repository digest input')
            spec, params = AUXILIARY['maintenance.apt_refresh.v1'], {'nonce': nonce}
        else:
            if (type(inputs) is not RebootInput or inputs.maintenance_window != 'now'
                    or type(inputs.staged_request_ids) is not tuple):
                raise ValueError('A reboot needs the applied changes it completes and the window "now"')
            applied = {json.loads(p.approved_raw)['request_id'] for p in proposals
                       if p.approved_raw and p.receipts and p.receipts[-1]['outcome'] in ('applied', 'reconciled_applied')
                       and not p.payload['action']['action_id'].startswith(('recovery.', 'maintenance.'))}
            staged = sorted(set(inputs.staged_request_ids))
            if not staged or not set(staged) <= applied:
                raise ValueError('A reboot must name changes of the latest round that are already applied')
            spec = AUXILIARY['maintenance.reboot.v1']
            params = {'nonce': nonce, 'staged_request_ids': staged, 'maintenance_window': 'now'}
        preview = json.loads(self.session.channel.invoke_runner(
            canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params}) + b'\n'))
        if type(preview) is not dict or preview.get('action_id') != spec.action_id:
            raise ValueError('Maintenance preview for another action')
        if kind is AuxiliaryKind.METADATA_REFRESH and inputs.repository_digest not in (
                '', preview['summary'].get('repository_digest')):
            raise ValueError('The apt sources changed since they were shown; review the new preview')
        s = self.session
        plan = plan_action(spec, families=AUXILIARY, parameters=params, target_id=s.target_id,
                           registration_epoch=s.registration_epoch, hostname=s.identity.hostname,
                           machine_id=s.identity.machine_identity, workflow_session_id=binding.workflow_session_id,
                           round_id=latest.round_id, evidence_sha256=latest.evidence_sha256, control_id='maintenance',
                           predicate_id='ubuntu.maintenance.predicate.v1',
                           before_state_sha256=preview['before_state_sha256'],
                           expected_after_sha256=preview['expected_after_sha256'],
                           before_state_collected_at=_host_now(), recovery=spec.recovery,
                           job_deadline_seconds=spec.max_seconds)
        store.add_proposal(binding, plan, title=spec.title, preview=preview['summary'])
        return self._ref(plan.proposal_id)

    def request_auxiliary(self, connection_session_id, workflow_session_id, kind, basis, inputs, operation_id):
        """Recovery of an applied fix, a package-list refresh or a reboot completing applied changes: preview and
        store an auxiliary proposal of the latest round. Approval and dispatch follow like any other proposal."""
        from system.contracts import AuxiliaryKind, OperationState, RecoveryInput
        from vm.ubuntu.remediation_schema import canonical
        from .actions import AUXILIARY, plan_action
        binding = self.check(connection_session_id, workflow_session_id, basis)
        if AuxiliaryKind(kind) in (AuxiliaryKind.METADATA_REFRESH, AuxiliaryKind.REBOOT):
            return self._request_maintenance(binding, AuxiliaryKind(kind), inputs, operation_id)
        if AuxiliaryKind(kind) is not AuxiliaryKind.RECOVERY:
            return OperationState(operation_id, 'refused', code='unsupported',
                                  detail='This auxiliary operation is not implemented for Ubuntu.')
        if binding is None or type(inputs) is not RecoveryInput or inputs.restoration_choice != 'restore_before_state':
            raise ValueError('Recovery needs a workflow and the restore_before_state choice')
        store = self._store()
        latest = self._latest(store, binding)
        original = next((p for p in store.proposals(binding, latest.round_id) if p.proposal_id == basis.record_id), None)
        if (original is None or original.payload['action']['action_id'].startswith('recovery.') or not original.receipts
                or original.receipts[-1]['outcome'] not in ('applied', 'reconciled_applied')):
            raise ValueError('Only an applied fix of the latest round can be restored')
        request = json.loads(original.approved_raw)
        if (inputs.original_request_id, inputs.backup_manifest_digest) != (request['request_id'], request['before_state_sha256']):
            raise ValueError('Recovery inputs do not name this fix and its recorded backup')
        spec = AUXILIARY['recovery.restore.v1']
        params = {'restores_request_id': request['request_id'],
                  'restores_request_sha256': hashlib.sha256(original.approved_raw).hexdigest()}
        preview = json.loads(self.session.channel.invoke_runner(
            canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params}) + b'\n'))
        if type(preview) is not dict or preview.get('action_id') != spec.action_id:
            raise ValueError('Restore preview for another action')
        f = original.payload['fields']
        plan = plan_action(spec, families=AUXILIARY, parameters=params,
                           **{k: f[k] for k in ('target_id', 'registration_epoch', 'hostname', 'machine_id',
                                                'workflow_session_id', 'round_id', 'evidence_sha256', 'control_id',
                                                'predicate_id')},
                           before_state_sha256=preview['before_state_sha256'],
                           expected_after_sha256=preview['expected_after_sha256'],
                           before_state_collected_at=_host_now(), recovery=spec.recovery,
                           job_deadline_seconds=spec.max_seconds)
        store.add_proposal(binding, plan, title='Restore before-state of ' + f['control_id'] + ' (undo '
                           + original.payload['action']['action_id'] + ')', preview=preview['summary'])
        return self._ref(plan.proposal_id)

    def dispatch_auxiliary(self, connection_session_id, workflow_session_id, proposal_ref, operation_id):
        """Run one approved recovery proposal once, behind the same gates, then verify with a fresh scan."""
        binding = self.check(connection_session_id, workflow_session_id, proposal_ref)
        gate = execution_gate(self)
        if gate:
            raise ValueError(gate[0])
        store = self._store()
        latest = self._latest(store, binding)
        proposal = next((p for p in store.proposals(binding, latest.round_id) if p.proposal_id == proposal_ref.record_id), None)
        if (proposal is None or not proposal.payload['action']['action_id'].startswith(('recovery.', 'maintenance.'))
                or proposal.decision != 'approved'):
            raise ValueError('Only an approved recovery or maintenance proposal of the latest round can be dispatched')
        if proposal.receipts:
            return RoundHandle(operation_id, binding, self._ref(latest.round_id), 'completed')  # never twice
        result = self._dispatch_one(store, binding, proposal, operation_id)
        applied = [json.loads(proposal.approved_raw)['request_id']] if result.state == 'completed' else []
        return RoundHandle(operation_id, binding, self._ref(latest.round_id),
                           self._verify(store, binding, latest, applied, result.state))
