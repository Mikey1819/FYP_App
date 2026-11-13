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
    'not_eligible': ("Not applied: the server's own check refused it just before writing (for a package fix, usually "
                     "apt busy with Ubuntu's automatic updates). Nothing was written; the next round plans it again."),
    'not_claimed': ('Not applied: the server has no record of this request (it was restored from a snapshot or reset '
                    'after the fix was sent), so nothing of it is on the server now. Nothing more of this execution runs '
                    'by itself; start a new round to plan the open controls again.'),
    'before_state': ('Not applied: the job ended and nothing changed on the server (its state is the same as before). '
                     'For a package install this is usually the package lock held by Ubuntu\'s automatic updates, or '
                     'a download that failed; a new round plans it again.'),
    'stale_read_set': ('Not applied (stale_read_set): what this plan was approved against has changed since, usually '
                       'because another fix in this round changed the same file first. Nothing was written. Start a new '
                       'round to re-plan it, then approve and execute it on its own.')}


def _scoped_files():
    """Shared files whose fixes check and restore only their own part (keys, lines, account fields), so a fix of one
    control never makes another stale and they can be approved and executed together (administrator request
    2026-11-11). UFW's files are not here: enabling the firewall depends on the allow rules."""
    from vm.ubuntu.family_aging import LOGIN_DEFS
    from vm.ubuntu.family_auth import SUDO_MANAGED
    from vm.ubuntu.family_ssh import MANAGED as SSHD_MANAGED
    from vm.ubuntu.family_sysctl import MANAGED as SYSCTL_MANAGED
    return frozenset({SYSCTL_MANAGED, SSHD_MANAGED, SUDO_MANAGED, LOGIN_DEFS, '/etc/shadow'})


def _files(payload):
    return {s for s in payload['fields']['recovery']['scope'] if not s.startswith('runtime:')} - _scoped_files()


# 4.1.4 and 4.1.7 each check and restore only their own part of UFW's files (family_ufw, 13 November 2026), so the
# two may be approved and executed together; enabling UFW (4.1.3) still reads every rule.
UFW_SCOPED = frozenset({'4.1.4', '4.1.7'})
UFW_FILES = frozenset({'/etc/default/ufw', '/etc/ufw/user.rules', '/etc/ufw/user6.rules'})


def shared_file_conflict(payload, proposals):
    """The control of an approved, not yet executed fix that restores a file this proposal also restores, or None.
    Such fixes cannot run in one execution: the second is refused stale once the first changes the file (live
    2026-11-07 13:44). Restores and maintenance are not counted, nor files whose fixes are scoped per control."""
    files = _files(payload)
    for other in proposals:
        action = other.payload['action']['action_id']
        shared = files & _files(other.payload)
        if {payload['fields']['control_id'], other.payload['fields']['control_id']} <= UFW_SCOPED:
            shared -= UFW_FILES
        if (other.payload['proposal_id'] != payload['proposal_id'] and other.decision == 'approved' and not other.receipts
                and action.startswith('ubuntu.') and shared):
            return other.payload['fields']['control_id']
    return None


def shared_file_message(control_id, other):
    return ('%s changes the same file as %s, which is approved and not executed yet, so they cannot run together. '
            'execute %s first, then start a new round to re-plan %s.' % (control_id, other, other, control_id))


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


@lru_cache(maxsize=1)
def _fixed_controls():
    """Controls some registered fix family can change."""
    from .actions import FAMILIES
    return frozenset(c for spec in FAMILIES.values() for c in spec.control_ids)


@dataclass(frozen=True)
class DeploymentStatus:
    ok: bool
    reasons: tuple
    runner_digest: str | None
    clock_offset: float | None = None  # seconds the server clock runs ahead (negative: behind); None if unmeasured


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


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _registered_waits():
    """Action ID -> what its fix waits for after the server ran it ('job', 'confirm'), from the same family classes
    the runner on the server registers (their `supervision`); fixes that finish at once are absent."""
    global _WAITS
    if _WAITS is None:
        from vm.ubuntu.families import build
        _WAITS = {aid: f.supervision for aid, f in build(None).items() if getattr(f, 'supervision', None)}
    return _WAITS


_WAITS = None


def accepted_engine_version():
    return json.loads(LOCK.read_text(encoding='utf-8'))['openscap_version']


@lru_cache(maxsize=1)
def _risk_policy():
    from .risk import load_policy
    return load_policy()


AUDITD_PACKAGE = '6.3.1.1'
NEEDS_AUDITD = frozenset({'6.3.1.2', '6.3.3.4', '6.3.3.6', '6.3.3.8'})
AUDITD_WAIT = ('Planned after 6.3.1.1 installs auditd: its fix needs auditd on the server, so the next round after '
               '6.3.1.1 is applied plans it')


def _step_times(events):
    """Event index -> (model seconds, retried) for the first event each model request produced (module 2). The n-th
    `request` event of a run matches the n-th entry of its `model_timing` record."""
    timing = next((e['data'].get('steps', ()) for e in events if e['kind'] == 'model_timing'), ())
    found, request, waiting = {}, 0, False
    for index, event in enumerate(events):
        if event['kind'] == 'request':
            request, waiting = request + 1, True
        elif event['kind'] != 'model_timing' and waiting:
            waiting = False
            if request <= len(timing):
                found[index] = (timing[request - 1]['seconds'], bool(timing[request - 1]['retried']))
    return found


def _fix_failed(register_rows):
    """Controls whose approved fix was applied on this server and did not verify Compliant: the one fact that makes
    persistent_failure true and lets a needs_manual_review deferral stand (2026-11-13)."""
    return frozenset(r['control_id'] for r in register_rows if r['status'] == 'Applied, not verified')


# Settled without a verification scan: a restore, and the package-list refresh, which sets nothing a control checks
# (administrator, 13 November 2026: the Maintenance box waited for a full scan after apt-get update).
NO_SCAN_AFTER = ('recovery.', 'maintenance.apt_refresh.')


def execution_seconds(starts, first_dispatches, scans):
    """Seconds from the start of an execution (its first agent run or dispatch) to its last verification scan, from
    the stored ISO times; None before anything ran or before a scan (administrator, 13 November 2026: the page said
    "Remediation took 2 min 29 s", the agents' own time, for an execution of about 10 minutes)."""
    from datetime import datetime
    begun = [datetime.fromisoformat(t) for t in list(starts) + list(first_dispatches)]
    if not begun:
        return None
    ended = [t for t in (datetime.fromisoformat(s) for s in scans) if t >= min(begun)]
    return (max(ended) - min(begun)).total_seconds() if ended else None


def _refusal_hint(why):
    """What the administrator can do about a known refusal reason (empty when nothing specific is known)."""
    if 'unavailable from the configured sources' in why or 'apt could not plan' in why:
        return (' Click Refresh package lists in the Maintenance box (the server needs internet for apt: a NAT adapter '
                'beside the host-only one), then run the next round.')
    if 'No SSH allow rule' in why:
        # The server runs an older helper: since 13 November 4.1.3 adds the SSH rule itself.
        return (' The server runs an older helper; run the new fyp-pair-ubuntu.py on it (sudo python3 '
                'fyp-pair-ubuntu.py), which lets 4.1.3 add the SSH allow rule itself, then run the next round.')
    return ''


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
    # The server's reason a planned fix got no plan, with what to do for the known cases (2026-11-13).
    for cid, why in (details.get('preview_refused') or {}).items():
        if cid in decided and decided[cid][0] == 'Fix proposed':
            decided[cid] = ('Fix proposed', decided[cid][1] + ' · The server refused its read-only check: ' + why
                            + '.' + _refusal_hint(why))
    # Task 4: the auditd service and audit-rule fixes are planned from a read-only preview on a server that has auditd,
    # so while 6.3.1.1 (install auditd) fails they cannot be planned in this round. Say so, instead of the generic code.
    failing = {a.control_id for a in evidence.assessments if a.status is ComplianceStatus.NON_COMPLIANT}
    if AUDITD_PACKAGE in failing:
        for e in plan.get('deferred_by_code', ()):
            if e['control_id'] in NEEDS_AUDITD and e['reason_code'] == 'no_registered_action':
                decided[e['control_id']] = ('Deferred (by the app)', AUDITD_WAIT)
    missing = ('Not decided', 'The planner left it out of its plan') if plan else (
        'No plan', 'The round stopped before the planner submitted a plan')
    flags = {}
    for f in (details.get('analysis') or {}).get('flags', ()):
        flags.setdefault(f['control_id'], []).append(FLAGS.get(f['flag_code'], f['flag_code']))
    return tuple(PlanRow(a.control_id, catalogue[a.control_id].title, *decided.get(a.control_id, missing),
                         '; '.join(flags.get(a.control_id, ())))
                 for a in evidence.assessments if a.status is ComplianceStatus.NON_COMPLIANT)


def recovery_text(recovery):
    """How a change is undone, as the page shows it. The approved request keeps the registered record unchanged."""
    words = {'VM console and recovery snapshot': 'manually at the server console',
             'VirtualBox recovery snapshot': 'from your own backup of the server', 'VM console': 'the server console'}
    scope = ', '.join(words.get(item, item) for item in recovery['scope'])
    kind = {'snapshot_restore': 'cannot be undone automatically', 'manual_console': 'manual'}.get(recovery['kind'],
                                                                                                 recovery['kind'])
    return kind + ': ' + scope


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
                          ('The local model (qwen3:8b) is unavailable: start Ollama with qwen3:8b to run a round.',))
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

    # ---- read models for the Overview and History pages (the Windows pages' sections, read-only) ----------------
    def _all_rounds(self, store):
        """Every recorded round with a scan, of every workflow of this target and registration epoch, oldest first."""
        s = self.session
        found = [(r, b) for b in self.ledger.bindings_for_target('ubuntu', s.target_id, s.registration_epoch)
                 for r in store.rounds(b) if r.framework_run_id]
        return sorted(found, key=lambda pair: pair[0].created_at)

    def previous_workflow(self, connection_session_id):
        """The workflow of this server's newest assessment round, so the page can resume it after a reconnect, as
        the Windows page does: (workflow ID, round time, fixes still awaiting a decision or execution). None before
        the first round. Read-only."""
        from datetime import datetime, timezone
        self.check(connection_session_id)
        store = self._store()
        rounds = [(r, b) for r, b in (self._all_rounds(store) if store else ()) if r.kind == 'assessment']
        if not rounds:
            return None
        row, binding = rounds[-1]
        snapshot = self.snapshot(connection_session_id, binding.workflow_session_id)
        executed = {r.proposal_reference for r in snapshot.results}
        now = datetime.now(timezone.utc)
        open_count = sum(1 for p in snapshot.proposals if p.kind == 'control_remediation' and p.reference not in executed
                         and ((p.decision is None and p.eligible_commands) or
                              (p.decision == 'approved' and p.expiry and datetime.fromisoformat(p.expiry) > now)))
        return binding.workflow_session_id, row.created_at, open_count

    def overview(self, connection_session_id):
        """What the Overview page shows, as on Windows: the latest scan (an assessment or a verification re-scan) with
        its compliance by area and risk ranking, the scan before it, regressions between them, the fixes still
        awaiting a decision, how many fixes were verified, and the recent rounds. None before the first scan."""
        from collections import Counter
        self.check(connection_session_id)
        store = self._store()
        rounds = self._all_rounds(store) if store else []
        if not rounds:
            return None
        catalogue = _controls()
        latest = rounds[-1][0]
        evidence = self._evidence(store, latest.evidence_sha256)
        summary = self._summary(latest.framework_run_id, evidence)
        previous = None
        if len(rounds) > 1:
            before = rounds[-2][0]
            previous = self._summary(before.framework_run_id, self._evidence(store, before.evidence_sha256))
        regressions = ()
        if previous is not None and previous.reference != summary.reference:
            result = self.compare(previous.reference, summary.reference)
            if result.comparable:
                regressions = tuple(c for c, old, new in result.changes if (old, new) == ('Compliant', 'Non-Compliant'))
        snapshots = {}

        def snap(row, binding):
            if row.round_id not in snapshots:
                snapshots[row.round_id] = self.snapshot(connection_session_id, binding.workflow_session_id,
                                                        self._ref(row.round_id))
            return snapshots[row.round_id]

        def verdicts(snapshot):
            kinds = Counter()
            for r in snapshot.results:
                if r.execution_state in ('applied', 'reconciled_applied'):
                    if r.verification_status is None:
                        kinds['awaiting verification'] += 1
                    else:
                        kinds['verified' if r.verification_status is ComplianceStatus.COMPLIANT else 'failed'] += 1
                elif r.execution_state == 'running':
                    kinds['running'] += 1
                elif r.execution_state == 'skipped':
                    kinds['skipped'] += 1
                else:
                    kinds['refused' if r.execution_state in ('refused', 'rolled_back', 'reconciled_not_applied')
                          else 'uncertain'] += 1
            return kinds

        assessments = [(r, b) for r, b in rounds if r.kind == 'assessment']
        latest_assessment = assessments[-1][0].round_id if assessments else None
        awaiting = verified = 0
        for r, b in assessments:
            s = snap(r, b)
            verified += verdicts(s)['verified']
            if r.round_id == latest_assessment:
                awaiting = sum(p.kind == 'control_remediation' and p.decision is None and 'approve' in p.eligible_commands
                               for p in s.proposals)
        activity = []
        for r, b in reversed(rounds[-8:]):
            if r.kind == 'assessment':
                s = snap(r, b)
                fixes = [p for p in s.proposals if p.kind == 'control_remediation']
                undecided = sum(p.decision is None for p in fixes)
                if r.mode == 'deterministic':
                    entry = ('Assessment (no AI)', 'Scan only, no fixes proposed', 'Finished')
                elif not (r.details or {}).get('plan'):
                    entry = ('Assessment round', 'No plan', 'Stopped early')
                else:
                    deferred = sum(row.decision != 'Fix proposed' for row in s.plan)
                    status = ('No fix proposed' if not fixes else 'All decided' if not undecided
                              else f'{undecided} awaiting approval' if r.round_id == latest_assessment
                              else 'Replaced by a later round')
                    entry = ('Assessment round', f'{len(fixes)} fix(es) proposed, {deferred} deferred', status)
            else:
                # A verification scan names the approved requests it checks: a fix is verified when this scan reads
                # its control Compliant; an executed restore is reported as restored (its control is meant to revert).
                requested = set((r.details or {}).get('request_ids') or ())
                verifies = next((x for x in assessments if x[0].round_id == (r.details or {}).get('verifies_round')), None)
                status = {a.control_id: a.status for a in self._evidence(store, r.evidence_sha256).assessments}
                kinds = Counter()
                for q in (snap(*verifies).proposals if verifies else ()):
                    if q.approved_request_id not in requested:
                        continue
                    if q.kind == 'recovery':
                        kinds['restored'] += 1
                    elif q.kind == 'control_remediation':
                        kinds['verified' if status.get(q.control_id) is ComplianceStatus.COMPLIANT else 'failed'] += 1
                    else:
                        kinds[q.kind.replace('_', ' ')] += 1
                entry = ('Restore and verification' if set(kinds) == {'restored'} else 'Remediation and verification',
                         ', '.join(f'{n} {kind}' for kind, n in kinds.items()) or 'Verification scan', 'Finished')
            activity.append({'Time': r.created_at, 'Activity': entry[0], 'Result': entry[1], 'Status': entry[2]})
        fixes = {cid: spec.title for spec in self.families.values() for cid in spec.control_ids}
        return {'summary': summary, 'previous': previous, 'regressions': regressions,
                'areas': tuple((catalogue[a.control_id].area, a.status) for a in evidence.assessments),
                'findings': self._findings(store, latest, evidence), 'awaiting': awaiting, 'verified': verified,
                'activity': tuple(activity), 'fixes': fixes,
                'titles': {cid: c.title for cid, c in catalogue.items()}}

    @staticmethod
    def _change(before, after):
        if (before, after) == ('Compliant', 'Non-Compliant'):
            return 'Regression'
        if (before, after) == ('Non-Compliant', 'Compliant'):
            return 'Improvement'
        return 'Unchanged' if before == after else f'{before} -> {after}'

    def compare_rows(self, before, after):
        """Every control of two assessments of this target (as the Windows Compare): title, before, after, change."""
        result = self.compare(before, after)
        if not result.comparable:
            raise ValueError(result.reason)
        store = self._store()
        runs = {r.run_id: r for r in self._runs(store)}
        old, new = (self._evidence(store, runs[ref.record_id].digest) for ref in (before, after))
        titles, previous = {cid: c.title for cid, c in _controls().items()}, {a.control_id: a.status.value
                                                                               for a in old.assessments}
        return tuple({'control_id': a.control_id, 'title': titles[a.control_id], 'before': previous[a.control_id],
                      'after': a.status.value, 'change': self._change(previous[a.control_id], a.status.value)}
                     for a in new.assessments)

    def drift(self):
        """Changes between each assessment and the previous one of this target, oldest first (as Windows records drift)."""
        rows = self.history(limit=1000)
        records = []
        for older, newer in zip(rows, rows[1:]):
            for row in self.compare_rows(older.run_reference, newer.run_reference):
                if row['change'] != 'Unchanged':
                    records.append(dict(row, detected_at=newer.time, runs=older.run_reference.record_id[:8] + ' → '
                                        + newer.run_reference.record_id[:8]))
        return tuple(records)

    def snapshot(self, connection_session_id, workflow_session_id, round_ref=None, *, newest_scan=False):
        """The round's records. `newest_scan` (as on Windows): the summary and control rows come from the newest
        verification scan of this round, so the Controls tab shows the server as it is after the fixes; findings,
        plan, proposals and results always stay those of the round's own first scan."""
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
        checks = [r for r in all_rounds if r.kind == 'verification'
                  and (r.details or {}).get('verifies_round') == row.round_id] if newest_scan else []
        scan = checks[-1] if checks else row
        scanned = self._evidence(store, scan.evidence_sha256) if checks else evidence
        catalogue = _controls()
        controls = []
        for result in scanned.assessments:
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
                (self._ref(scan.framework_run_id),),
                fix='Program fix' if control.control_id in _fixed_controls() else 'Manual: not automated'))
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
            events = self._agent_events(store, details, row.round_id)
            plan = _plan_rows(details, evidence, catalogue)
        else:
            plan = ()
            steps = ('done', 'done' if _risk_policy().activated else 'pending', 'skipped', 'skipped', 'skipped', 'skipped')
            events = (AgentEvent(row.round_id, 'system', 'deterministic_assessment', '', '',
                                 'Read-only scan and deterministic predicates; no model was called and no proposal was created.',
                                 'no_ai', row.created_at, 'Deterministic (no AI)'),)
        return WorkspaceSnapshot(self._target(evidence.expected.evidence_mode), binding, self._ref(row.round_id),
                                 self._summary(scan.framework_run_id, scanned), tuple(controls), findings,
                                 proposals, results, events=events, step_states=steps, goal=details.get('goal'),
                                 plan=plan)

    def _proposal_rows(self, store, binding, row, latest, all_rounds=()):
        proposals, results = [], []
        checks = [r for r in all_rounds if r.kind == 'verification' and (r.details or {}).get('verifies_round') == row.round_id]
        verified = self._evidence(store, checks[-1].evidence_sha256) if checks else None
        fresh = {a.control_id: a.status for a in verified.assessments} if verified else {}
        round_proposals = store.proposals(binding, row.round_id)
        skipped = self._agent_skipped(store, row.round_id, round_proposals)
        for p in round_proposals:
            approved = json.loads(p.approved_raw) if p.approved_raw else None
            recovery = p.payload['fields']['recovery']
            blocked = (shared_file_conflict(p.payload, round_proposals)
                       if latest and p.decision is None and p.payload['action']['action_id'].startswith('ubuntu.') else None)
            action_id = p.payload['action']['action_id']
            kind = {'recovery.restore.v1': 'recovery', 'maintenance.apt_refresh.v1': 'metadata_refresh',
                    'maintenance.reboot.v1': 'reboot'}.get(action_id, 'control_remediation')
            proposals.append(ProposalRow(self._ref(p.proposal_id), kind, p.payload['fields']['control_id'],
                p.payload['action']['action_id'], p.payload['title'], 'v%d' % p.payload['action']['version'],
                preview_text(p.payload['preview']), (), recovery_text(recovery),
                (), p.decision, approved['expires_at'] if approved else None,
                shared_file_message(p.payload['fields']['control_id'], blocked) if blocked else
                'Deterministic plan from the registered family; the target preview supplied the before/after digests.',
                (('reject',) if blocked else ('approve', 'reject')) if latest and p.decision is None else (),
                approved['request_id'] if approved else None, approved['before_state_sha256'] if approved else None,
                approved.get('approver') if approved else None, p.rejected_by, p.comments))
            if not p.receipts and approved and approved['request_id'] in skipped:
                results.append(ResultRow(self._ref(p.proposal_id), 'skipped', None, None, None, 'not_requested',
                                         'Skipped by the Remediation Agent: ' + skipped[approved['request_id']]
                                         + '. Not executed; a new round plans it again.'))
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
                    detail = ('Reboot scheduled. The connection drops while the server restarts; the page reconnects by '
                              'itself when it is back, verifies the new boot ID, and a fresh scan follows.')
                elif (last['outcome'], last['code']) == ('running', 'awaiting_confirmation'):
                    detail = ('Applied and waiting for confirmation: the dashboard confirms it over a fresh SSH login by '
                              'itself (that login proves SSH still works); without it the server restores the '
                              'before-state.')
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

    def _phase_runs(self, store, round_id):
        """The remediation phases' agent runs for one assessment round (review, Remediation Agent, verification),
        oldest first. They share the phase's team ID in the agent log; nothing else is stored for them."""
        from hardening.investigation import InvestigationLog
        from .remediation_agents import Phase
        log = store.agent_log()
        team = Phase.team_prefix + round_id
        with log._connection() as db:
            rows = db.execute("SELECT run_id FROM investigation_runs WHERE json_extract(payload, '$.team_id')=? "
                              'ORDER BY rowid', (team,)).fetchall()
        reader = InvestigationLog(log)
        return [reader.get(run_id) for (run_id,) in rows]

    def _agent_skipped(self, store, round_id, proposals):
        """Approved fixes of this round the Remediation Agent closed unexecuted: request ID -> the code-written reason.
        Read from its own recorded tool results (skip_fix, stop_execution), never from model text or comments."""
        from .remediation_agents import REMEDIATION, SKIP_REASONS
        requests = {p.payload['fields']['control_id']: json.loads(p.approved_raw)['request_id']
                    for p in proposals if p.decision == 'approved' and p.approved_raw
                    and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)}
        skipped = {}
        for run in self._phase_runs(store, round_id) if requests else ():
            if run.get('agent_role') != REMEDIATION:
                continue
            for event in run['events']:
                data = event['data']
                if event['kind'] != 'tool' or data.get('name') not in ('skip_fix', 'stop_execution'):
                    continue
                result = data.get('result') or {}
                for entry in [result] if data['name'] == 'skip_fix' else result.get('skipped', ()):
                    if entry.get('control_id') in requests and entry.get('reason_code') in SKIP_REASONS:
                        skipped[requests[entry['control_id']]] = SKIP_REASONS[entry['reason_code']]
        return skipped

    def _agent_events(self, store, details, round_id=None):
        """Durable Coordinator events of the round's agents (and of its remediation phases), as Agent log rows."""
        from hardening.investigation import InvestigationLog
        log, rows = InvestigationLog(store.agent_log()), []
        runs = [(log.get(run_id), 'Assessment phase')
                for run_id in [details['orchestrator_run_id'], *details['children'].values()]]
        for run, phase in runs + [(r, 'Remediation phase') for r in (self._phase_runs(store, round_id) if round_id else [])]:
            run_id = run['run_id']
            times = _step_times(run['events'])
            for index, event in enumerate(run['events']):
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
                finished = kind == 'finished'
                rows.append(AgentEvent(run_id, str(run.get('agent_role', 'unknown')), kind, str(data.get('name', ''))[:80],
                                       json.dumps(data.get('arguments', {}), sort_keys=True)[:300], summary, code,
                                       event['created_at'], f"{run['provenance']} ({run['model']})", phase,
                                       data.get('tool_calls') if finished else None,
                                       data.get('duration_seconds') if finished else None,
                                       *times.get(index, (None, False))))
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
        self._refuse_completed(binding)
        if goal:  # disabled by the administrator (2026-11-07) and due for removal
            raise ValueError('Round goals are disabled for Ubuntu. No scan was run.')
        gate = assessment_gate()
        if gate:
            raise ValueError(gate[0] + ' No scan was run.')
        mode = AssessmentMode(mode)
        if mode is AssessmentMode.AGENTIC and not self.model_probe():
            raise ValueError('The local model is unavailable: start Ollama with qwen3:8b, then start the round again. '
                             'No scan was run.')
        if self._collector_installed() is False:
            raise ValueError('This server is not set up yet: the FYP helper is not installed. On the server, run '
                             'sudo python3 fyp-pair-ubuntu.py (download it from Servers; it sets the server up before '
                             'showing a code), then reconnect. '
                             'No scan was run.')
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
                              'registered_firewall_manager': self.firewall_manager()},
                             sort_keys=True, separators=(',', ':')).encode('ascii')
        run = store.start_run(self.session.channel.invoke_helper(message), expected, binding)
        return run.run_id, self._evidence(store, run.digest)

    def _earlier_assessments(self, store):
        """Every stored scan of this target and registration epoch (assessment and verification rounds) as
        (round, evidence), newest first: the history the risk engine's D factor and check_history read."""
        found = [(r, self._evidence(store, r.evidence_sha256)) for r, _ in self._all_rounds(store)]
        return sorted(found, key=lambda pair: pair[1].completed_at, reverse=True)

    def _agentic_round(self, store, binding, collect, goal):
        from .agents import run_agentic_round
        from .risk import RiskInput, rank as derive
        earlier = []  # loaded once, on first use, from rounds stored before this one

        def previous():
            if not earlier:
                earlier.append(self._earlier_assessments(store))
            return earlier[0]

        def rank(run_id, evidence):
            policy = _risk_policy()
            if not policy.activated:
                return None
            # The same history as the Risk ranking tab, so D (and the persistent_failure flag) can be true here too.
            prior = [RiskInput(self._ref(r.framework_run_id), r.round_id, ev) for r, ev in previous()]
            return derive(RiskInput(self._ref(run_id), 'current', evidence), prior, policy)

        def history(control_id):
            return [(ev.completed_at, a.status.value) for _, ev in previous() for a in ev.assessments
                    if a.control_id == control_id]
        result = run_agentic_round(client_factory=self.model_client_factory, collect=collect, log_store=store.agent_log(),
                                   target_id=self.session.target_id, titles={c: x.title for c, x in _controls().items()},
                                   rank=rank, goal=goal, eligible=self._eligible, history=history,
                                   fix_failed=_fix_failed(self.live_validation(self.session.connection_session_id)))
        if result['run_id'] is None:
            raise ValueError(f"The agentic round stopped before an assessment was collected ({result['status']}). Its agent "
                             'log is kept; start the round again.')
        details = {k: result[k] for k in ('orchestrator_run_id', 'children', 'scanned_runs', 'status', 'analysis', 'plan', 'goal')}
        # Each planned fix's read-only preview runs before the round is recorded, so a refusal's reason is kept with
        # the round and shown (2026-11-13: two package fixes stayed without a plan and the page could not say why).
        previews, refused = {}, {}
        for fix in (result['plan'] or {}).get('fixes', []):
            preview, reason = self._preview(fix, result['evidence'])
            if preview is None:
                refused[fix['control_id']] = reason
            else:
                previews[fix['control_id']] = preview
        if refused:
            details['preview_refused'] = refused
        round_id = store.record_round(binding, result['run_id'], mode='agentic', details=details)
        for fix in (result['plan'] or {}).get('fixes', []):
            if fix['control_id'] in previews:
                self._propose(store, binding, round_id, result['evidence'], fix, preview=previews[fix['control_id']])
        return round_id

    def _preview(self, fix, evidence):
        """(preview, None) when the server accepts the planned fix's read-only check, else (None, why): the runner's
        own reason when it gives one, otherwise what is known."""
        from vm.ubuntu.remediation_schema import canonical
        spec = self.families[fix['action_id']]
        params = spec.propose(fix['control_id'], evidence)
        header = canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params})
        try:
            preview = json.loads(self.session.channel.invoke_runner(header + b'\n'))
        except (OSError, TimeoutError):
            return None, 'the server did not answer the read-only check'
        except ValueError:
            return None, ('the server refused it without a reason (a fix runner from before 13 November 2026: run '
                          'the helper on the server again)')
        if type(preview) is not dict or preview.get('action_id') != spec.action_id:
            return None, 'the server answered for another fix'
        if 'refused' in preview:
            reason = ''.join(ch for ch in str(preview['refused']) if ' ' <= ch <= '~')[:200]
            return None, reason or 'not eligible'
        return preview, None

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

    def _propose(self, store, binding, round_id, evidence, fix, *, preview=None):
        """Read-only target preview (or the one just taken), then a stored deterministic plan. A failed preview creates
        no proposal."""
        from vm.ubuntu.remediation_schema import canonical
        from .actions import plan_action
        spec = self.families[fix['action_id']]
        params = spec.propose(fix['control_id'], evidence)
        header = canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params})
        try:
            if preview is None:
                preview = json.loads(self.session.channel.invoke_runner(header + b'\n'))
            if type(preview) is not dict or preview.get('action_id') != spec.action_id or 'refused' in preview:
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
        self._refuse_completed(binding)
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
                payload, proposal_ref = self._fresh_plan(store, binding, payload, proposal_ref, operator, now)
                now = datetime.now(timezone.utc)  # Approval time after any re-read, never before the plan was read.
                if payload['action']['action_id'].startswith('ubuntu.'):
                    other = shared_file_conflict(payload, store.proposals(binding, latest.round_id))
                    if other:
                        raise ValueError(shared_file_message(payload['fields']['control_id'], other))
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

    # A plan may be approved only within five minutes of reading the server (MAX_BEFORE_STATE_AGE, checked again by
    # the runner). Approving later re-reads the server instead of refusing outright; this margin keeps the fresh plan
    # well inside the limit.
    FRESH_MARGIN_SECONDS = 30

    def _fresh_plan(self, store, binding, payload, proposal_ref, operator, now):
        """The plan to approve: this one while it is fresh; otherwise a fresh copy of exactly the same change.

        The read-only preview is run again. Only if the server's before-state and the expected after-state are byte for
        byte the ones planned is a new plan stored (same round, parameters and evidence; a fresh read time) and the old
        one closed as rejected with a comment saying it was replaced. If anything on the server changed, nothing is
        stored and the administrator is asked to run a new round, as before."""
        from dataclasses import replace
        from vm.ubuntu.remediation_schema import MAX_BEFORE_STATE_AGE, canonical, utc
        from .actions import PLAN_FIELDS, plan_action
        fields, spec = payload['fields'], self.families.get(payload['action']['action_id'])
        age = (now - utc(fields['before_state_collected_at'])).total_seconds()
        if spec is None or age <= MAX_BEFORE_STATE_AGE - self.FRESH_MARGIN_SECONDS:
            return payload, proposal_ref
        changed = ValueError('The server has changed since this fix was planned, so the plan is no longer exact. '
                             'Run a new round to plan it again.')
        try:
            preview = json.loads(self.session.channel.invoke_runner(canonical(
                {'op': 'preview', 'action_id': spec.action_id, 'parameters': fields['parameters']}) + b'\n'))
        except (ValueError, KeyError, TypeError, OSError, TimeoutError):
            raise changed from None
        if (type(preview) is not dict or preview.get('action_id') != spec.action_id
                or preview.get('before_state_sha256') != fields['before_state_sha256']
                or preview.get('expected_after_sha256') != fields['expected_after_sha256']):
            raise changed
        kept = {k: fields[k] for k in PLAN_FIELDS if k not in ('parameters', 'before_state_collected_at')}
        plan = plan_action(spec, families=self.families, parameters=fields['parameters'],
                           **dict(kept, before_state_collected_at=_host_now()))
        store.add_proposal(binding, plan, title=payload['title'], preview=preview.get('summary', payload['preview']))
        store.record_decision(binding, proposal_ref.record_id, rejected=(operator, now))
        store.add_comment(binding, proposal_ref.record_id, operator, 'Replaced by a fresh plan of the same change: '
                          'this plan was more than five minutes old and the server was unchanged.', now)
        return store._proposal(binding, plan.proposal_id), replace(proposal_ref, record_id=plan.proposal_id)

    def execute_approved(self, connection_session_id, workflow_session_id, round_ref,
                         expected_approved_request_ids, deterministic, operation_id):
        """Run exactly the expected approved set. With the model (deterministic=False): the remediation phase, in which
        the Orchestrator delegates the Remediation Agent and a verification scan and decides the next step. Without it
        (the administrator's choice): sequentially in plan order, stopping at the first uncertain outcome. The same
        executor, ledger claim and runner checks guard both, and a fix is never dispatched twice."""
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        self._refuse_completed(binding)
        gate = execution_gate(self)
        if gate:
            raise ValueError(gate[0])
        store = self._store()
        latest = self._latest(store, binding, round_ref)
        proposals = store.proposals(binding, latest.round_id)
        approved = [p for p in proposals
                    if p.decision == 'approved' and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)]
        requests = {json.loads(p.approved_raw)['request_id']: p for p in approved}
        if not requests or set(expected_approved_request_ids) != set(requests):
            raise ValueError('The approved set changed or is empty; review the current approvals. No write was dispatched.')
        skipped = self._agent_skipped(store, latest.round_id, proposals)  # closed by the Remediation Agent: never run
        if any(not p.receipts and rid not in skipped for rid, p in requests.items()):
            self._record_execution(binding, latest, requests, operation_id)
        return self._run_requests(store, binding, latest, requests, skipped, deterministic, round_ref, operation_id)

    def _execution_command(self, latest, requests):
        return {'round_id': latest.round_id, 'requests': sorted(requests)}

    def _record_execution(self, binding, latest, requests, operation_id):
        """The administrator confirmed executing exactly this approved set: recorded, so the fixes left waiting behind
        a fix that waits may continue once it settles (continue_execution). Only the digest is kept; the same set
        executed again is the same record. A workflow still busy is left unrecorded: nothing then continues."""
        try:
            owner, _ = self.ledger.claim(binding, 'ubuntu-execution-set:' + operation_id, 'execution_set',
                                         self._execution_command(latest, requests))
        except ValueError:
            return
        if owner:
            self.ledger.transition('ubuntu-execution-set:' + operation_id, 'completed', detail='recorded')

    def _waits(self, proposal):
        """None, 'job' or 'confirm': what this fix waits for once the server ran it. Registered families answer from
        the server's registry; a family given to this backend directly (test fixtures) answers from its own class."""
        action_id = proposal.payload['action']['action_id']
        kind = _registered_waits().get(action_id)
        if kind is None:
            family = getattr(getattr(self.families.get(action_id), 'validate', None), '__self__', None)
            kind = getattr(family, 'supervision', None)
        return kind

    def _run_requests(self, store, binding, latest, requests, skipped, deterministic, round_ref, operation_id):
        if not deterministic:
            return self._agentic_execution(store, binding, latest, requests, skipped, round_ref, operation_id)
        from .remediation_agents import WAIT_ORDER
        state, applied, waiting = 'completed', [], False
        # Nothing more runs while a fix waits (a supervised job, a confirmation after a fresh login), so those run after
        # the others, in plan order within each kind (problem 5, live 11 November). Commit-confirm changes are the
        # exception since 13 November 2026: each is sent once the one before it waits for its confirmation, so one
        # fresh login confirms them all (the runner and the ledger stack them; each keeps its own rollback timer).
        ordered = sorted(requests.items(), key=lambda item: WAIT_ORDER[self._waits(item[1])])
        confirms = [rid for rid, p in ordered if not p.receipts and rid not in skipped and self._waits(p) == 'confirm']
        for request_id, proposal in ordered:
            if proposal.receipts or request_id in skipped:
                continue  # already dispatched once, or closed unexecuted by the Remediation Agent; never again
            confirm_mode = self._waits(proposal) == 'confirm'
            if waiting and not confirm_mode:
                break
            try:
                result = self._dispatch_one(store, binding, proposal, operation_id, stack=waiting and confirm_mode)
            except ValueError:
                if waiting:
                    break  # not stackable after all: it follows once the waiting ones are confirmed
                raise
            if result.state == 'completed':
                applied.append(request_id)
                continue
            state = result.state
            if result.state == 'running' and confirm_mode and confirms[-1] != request_id:
                # Another commit-confirm change follows: wait for this one to apply, then stack the next on it.
                state = self._await_confirmation(store, binding, proposal)
                if state == 'awaiting_confirmation':
                    waiting = True
                    continue
            if result.state != 'refused':
                break  # uncertain (unresolved, running): nothing more until it is settled
            # A refusal is definite (nothing was written), so the independent fixes still run. Live 13:44: after 1.5.1
            # changed the shared sysctl file, 1.5.3/3.3.1/3.3.8 were refused stale and 5.2.3 never ran.
        return RoundHandle(operation_id, binding, round_ref, self._verify_when_settled(store, binding, latest, state))

    @staticmethod
    def _pause(seconds):
        import time
        time.sleep(seconds)

    CONFIRM_WAIT_SECONDS = 120  # for a commit-confirm job to apply before the next one is stacked on it

    def _await_confirmation(self, store, binding, proposal):
        """Ask the server every second how a just-sent commit-confirm change is doing: 'awaiting_confirmation' once it
        applied and waits for its fresh-login confirmation (the next one may then be stacked), else the settled state,
        or 'running' after CONFIRM_WAIT_SECONDS. Reads status only; never dispatches again."""
        from vm.ubuntu.remediation_schema import canonical, parse_request
        from .approvals import ApprovedRequest
        from .executor import reconcile
        raw = proposal.approved_raw
        approved = ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))
        request_id = approved.request['request_id']
        header = canonical({'op': 'reconcile', 'request_id': request_id})
        for _ in range(self.CONFIRM_WAIT_SECONDS):
            self._pause(1)
            result = reconcile(approved, ledger=self.ledger, operation_id=_execution_operation(request_id),
                               status=lambda rid: self.session.channel.invoke_runner(header + b'\n'))
            self._record_status(store, binding, proposal, result)
            if result.state != 'running':
                return result.state
            if result.receipt['code'] == 'awaiting_confirmation':
                return 'awaiting_confirmation'
        return 'running'

    # Last outcomes after which the rest of an execution may go on: applied, or refused with nothing written. A change
    # the server rolled back (no confirmation came) or an unknown outcome stops it: a person looks first.
    CONTINUE_AFTER = ('applied', 'reconciled_applied', 'refused', 'reconciled_not_applied')

    def _continuable(self, store, binding, latest):
        """The approved fixes that may continue without a new click (problem 7): the administrator confirmed executing
        exactly the round's current approved set, a fix of it waited (a supervised job, a confirmation after a fresh
        login) and has settled, nothing is open or went wrong, and these are neither run, skipped nor expired."""
        from vm.ubuntu.remediation_schema import utc
        proposals = store.proposals(binding, latest.round_id)
        approved = [p for p in proposals
                    if p.decision == 'approved' and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)]
        requests = {json.loads(p.approved_raw)['request_id']: p for p in approved}
        if not requests or not self.ledger.recorded(binding, 'execution_set', self._execution_command(latest, requests)):
            return {}, ()
        if any(p.receipts and p.receipts[-1]['outcome'] not in self.CONTINUE_AFTER for p in approved):
            return {}, ()
        if any(p.receipts and p.receipts[-1]['code'] == 'not_claimed' for p in approved):
            return {}, ()  # the server has no record of a fix that was sent: restored or reset; a person looks first
        if not any(r['outcome'] == 'running' for p in approved for r in p.receipts):
            return {}, ()  # nothing waited: a stop for another reason is the administrator's to resolve
        skipped, now = self._agent_skipped(store, latest.round_id, proposals), _utcnow()
        return {rid: p for rid, p in requests.items() if not p.receipts and rid not in skipped
                and utc(json.loads(p.approved_raw)['expires_at']) > now}, skipped

    def continuation(self, connection_session_id, workflow_session_id):
        """Request IDs of the latest round that continue_execution would send now, in no particular order (read-only)."""
        binding = self.check(connection_session_id, workflow_session_id)
        store = self._store() if binding else None
        rounds = [r for r in store.rounds(binding) if r.kind == 'assessment'] if store else []
        return tuple(self._continuable(store, binding, rounds[-1])[0]) if rounds else ()

    def continue_execution(self, connection_session_id, workflow_session_id, round_ref, deterministic, operation_id):
        """Send the rest of an execution once the fix it waited for has settled, without a new click: the same
        approvals (expired ones are left), the same order rule, one dispatch each under its ledger claim, then a fresh
        verification scan. None when nothing may continue."""
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store()
        latest = self._latest(store, binding, round_ref)
        remaining, skipped = self._continuable(store, binding, latest)
        if not remaining:
            return None
        gate = execution_gate(self)
        if gate:
            raise ValueError(gate[0])
        return self._run_requests(store, binding, latest, remaining, skipped, deterministic, round_ref, operation_id)

    def _precheck(self, proposal):
        """Read-only readiness of one approved fix, for the Remediation Agent: approval expiry, and a fresh preview
        compared byte for byte with the approved plan. Raises only when the server cannot be reached (nothing is
        then skipped); a refused or malformed preview is a fact, not an error."""
        from datetime import datetime, timezone
        from vm.ubuntu.remediation_schema import canonical, utc
        fields, action = proposal.payload['fields'], proposal.payload['action']['action_id']
        facts = {'expired': datetime.now(timezone.utc) >= utc(json.loads(proposal.approved_raw)['expires_at']),
                 'precondition_changed': False, 'preview_refused': False}
        header = canonical({'op': 'preview', 'action_id': action, 'parameters': fields['parameters']})
        try:
            preview = json.loads(self.session.channel.invoke_runner(header + b'\n'))
        except ValueError:  # The runner refused (non-zero exit) or answered with something that is not JSON.
            facts['preview_refused'] = True
            return facts
        if type(preview) is not dict or preview.get('action_id') != action or 'refused' in preview:
            facts['preview_refused'] = True
        elif (preview.get('before_state_sha256'), preview.get('expected_after_sha256')) != (
                fields['before_state_sha256'], fields['expected_after_sha256']):
            facts['precondition_changed'] = True
        return facts

    def _agentic_execution(self, store, binding, latest, requests, skipped, round_ref, operation_id):
        """The remediation phase with the local model (remediation_agents.py). Code keeps every hard guard; when the
        Orchestrator leaves an applied fix without a verification scan, code runs that scan itself."""
        from datetime import datetime, timezone
        from .remediation_agents import Phase, run_remediation_phase
        if not self.model_probe():
            raise ValueError('The local model became unavailable, so no write was dispatched and every approval stays '
                             'open. Start Ollama with qwen3:8b and confirm again; while the model stays unavailable, '
                             'Confirm runs the approved fixes in plan order.')
        open_requests = {rid: p for rid, p in requests.items() if not p.receipts and rid not in skipped}
        if not open_requests:
            raise ValueError('Every approved fix of this round has already run or was skipped. No write was dispatched.')
        evidence = self._evidence(store, latest.evidence_sha256)
        ranks = {f.control_id: f.rank for f in self._findings(store, latest, evidence)}
        rows = [{'request_id': rid, 'control_id': p.payload['fields']['control_id'],
                 'action_id': p.payload['action']['action_id'], 'title': p.payload['title'],
                 'expires_at': json.loads(p.approved_raw)['expires_at'],
                 'rank': ranks.get(p.payload['fields']['control_id']), 'waits': self._waits(p)}
                for rid, p in open_requests.items()]

        def execute(request_id):
            try:
                result = self._dispatch_one(store, binding, open_requests[request_id], operation_id)
            except ValueError as exc:  # Refused before any dispatch, e.g. the approval expired meanwhile.
                return 'refused', 'refused_before_dispatch: ' + str(exc)[:60]
            return result.state, (result.receipt or {}).get('code', 'recorded')

        def skip(request_id, reason):
            store.add_comment(binding, open_requests[request_id].proposal_id, 'Remediation Agent',
                              'Skipped by the Remediation Agent: ' + reason + '. Not executed; a new round plans it '
                              'again.', datetime.now(timezone.utc))

        def verify(request_ids):
            run_id, scanned = self._collect(store, binding)
            store.record_round(binding, run_id, mode='deterministic', kind='verification',
                               details={'verifies_round': latest.round_id, 'request_ids': sorted(request_ids)})
            return run_id, scanned
        phase = Phase(target_id=self.session.target_id, round_id=latest.round_id, log_store=store.agent_log(),
                      requests=rows, precheck=lambda rid: self._precheck(open_requests[rid]), execute=execute,
                      skip=skip, verify=verify, eligible=self._eligible, before=evidence)
        result = run_remediation_phase(phase, client_factory=self.model_client_factory)
        kinds = {r['result'] for r in (result['remediation'] or {}).get('results', ())}
        state = ('unresolved' if 'uncertain' in kinds else 'running' if 'running' in kinds
                 else 'refused' if 'refused' in kinds else 'completed')
        # A possible write never stays unobserved: applied fixes no verification scan covers get one from code once
        # the execution has settled (one scan per execution).
        return RoundHandle(operation_id, binding, round_ref, self._verify_when_settled(store, binding, latest, state))

    def remediation_review(self, connection_session_id, workflow_session_id, round_ref=None):
        """The latest remediation phase's next-step decision for the given assessment round (default: the latest),
        code-written, or None. When the agents stopped early and a fix of the round then ran without them, this is
        the Windows engine's `fallback` outcome instead: executed without AI."""
        from .remediation_agents import REMEDIATION, REVIEW_ROLE
        binding = self.check(connection_session_id, workflow_session_id)
        store = self._store()
        rounds = [r for r in store.rounds(binding) if r.kind == 'assessment'] if store and binding else []
        if round_ref is not None:
            rounds = [r for r in rounds if r.round_id == round_ref.record_id]
        if not rounds:
            return None
        runs = self._phase_runs(store, rounds[-1].round_id)
        for run in reversed(runs):
            if run.get('agent_role') == REVIEW_ROLE and run['events']:
                # The run's last own event: a model_timing record (module 2) is stored after it.
                finished = [e for e in run['events'] if e['kind'] != 'model_timing'][-1]['data']
                outcome = finished.get('outcome')
                review = ({'next_step': outcome['outcome'], 'reason_code': outcome['reason_code'],
                           'reason': outcome['reason']} if outcome else
                          {'next_step': None, 'reason_code': None, 'reason': 'The Orchestrator stopped without deciding '
                           'the next step (' + str(finished.get('status')) + ').'})
                if review['next_step'] is None or review['reason_code'] == 'remediation_incomplete':
                    # Executed by the Remediation Agent: its own recorded execute_fixes results, never model text.
                    entries = [entry for r in runs if r.get('agent_role') == REMEDIATION
                               for e in r['events'] if e['kind'] == 'tool' and e['data'].get('name') == 'execute_fixes'
                               for entry in (e['data'].get('result') or {}).get('results', ())]
                    by_agents = {entry.get('control_id') for entry in entries}
                    if review['reason_code'] == 'remediation_incomplete' and any(
                            entry.get('result') == 'running' for entry in entries):
                        # The agent stopped because a fix waited (a supervised job, a confirmation), and the rest ran
                        # by code under the same approvals: the batched execution's design since 13 November 2026,
                        # not an early stop. Once it has settled, the outcome is decided again from the final scan.
                        return self._settled_review(store, binding, rounds[-1]) or review
                    if any(p.receipts and p.payload['fields']['control_id'] not in by_agents
                           and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)
                           for p in store.proposals(binding, rounds[-1].round_id)):
                        return {'next_step': 'fallback', 'reason_code': None,
                                'reason': 'Executed without AI after the agents stopped early: the remaining approved '
                                          'fixes ran in plan order with the same approvals and server checks, and a '
                                          'fresh verification scan checked the result.'}
                if review['reason_code'] == 'awaiting_confirmation':
                    return self._settled_review(store, binding, rounds[-1]) or review
                return review
        return None

    def _settled_review(self, store, binding, latest):
        """remediation_agents.settled_review for this round once no approved fix still runs or waits, else None."""
        from .remediation_agents import settled_review
        approved = [p for p in store.proposals(binding, latest.round_id) if p.decision == 'approved' and p.receipts
                    and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)]
        if any(p.receipts[-1]['outcome'] in ('running', 'unresolved') for p in approved):
            return None
        kind = {'applied': 'applied', 'reconciled_applied': 'applied'}
        results = {p.payload['fields']['control_id']: kind.get(p.receipts[-1]['outcome'], 'refused') for p in approved}
        controls = {p.receipts[-1]['request_id']: p.payload['fields']['control_id'] for p in approved}
        checks = [r for r in store.rounds(binding) if r.kind == 'verification'
                  and (r.details or {}).get('verifies_round') == latest.round_id]
        status, remaining = {}, []
        if checks:
            evidence = self._evidence(store, checks[-1].evidence_sha256)
            status = {a.control_id: a.status.value for a in evidence.assessments}
            remaining = sorted(self._eligible(evidence))
        unverified = [controls[r] for r in self._unverified(store, binding, latest) if r in controls]
        return settled_review(results=results, status=status, unverified=unverified, remaining=remaining)

    def execution_time(self, connection_session_id, workflow_session_id, round_ref):
        """execution_seconds for one assessment round of this workflow, from its stored records (read-only)."""
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store() if binding else None
        if store is None:
            return None
        proposals = [p for p in store.proposals(binding, round_ref.record_id) if p.decision == 'approved'
                     and p.receipts and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)]
        scans = [r.created_at for r in store.rounds(binding) if r.kind == 'verification'
                 and (r.details or {}).get('verifies_round') == round_ref.record_id]
        return execution_seconds([run['created_at'] for run in self._phase_runs(store, round_ref.record_id)],
                                 [p.receipts[0]['started_at'] for p in proposals], scans)

    def assessment_rounds(self, connection_session_id, workflow_session_id):
        """The workflow's assessment rounds, oldest first, as (round reference, started at), for the page's round
        picker as on Windows. Read-only."""
        binding = self.check(connection_session_id, workflow_session_id)
        store = self._store() if binding else None
        return tuple((self._ref(r.round_id), r.created_at)
                     for r in (store.rounds(binding) if store else ()) if r.kind == 'assessment')

    def verification_changes(self, connection_session_id, workflow_session_id, round_ref):
        """What the latest verification scan of a round found changed against the round's own scan, as the Windows
        Results tab shows: one row per control whose status or any sub-check state changed. None while the round has
        no verification scan. Sub-check states only; raw observed values are never shown."""
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store() if binding else None
        rounds = store.rounds(binding) if store else ()
        row = next((r for r in rounds if r.kind == 'assessment' and r.round_id == round_ref.record_id), None)
        if row is None:
            raise ValueError('Round is outside this workflow')
        checks = [r for r in rounds if r.kind == 'verification' and (r.details or {}).get('verifies_round') == row.round_id]
        if not checks:
            return None
        before, after = (self._evidence(store, r.evidence_sha256) for r in (row, checks[-1]))
        old = {a.control_id: a for a in before.assessments}
        titles = {cid: c.title for cid, c in _controls().items()}
        rows = []
        for a in after.assessments:
            b = old.get(a.control_id)
            if b is None:
                continue
            states = {c.name: c.state for c in b.checks}
            moved = [f'{c.name}: {states[c.name]} → {c.state}' for c in a.checks
                     if c.name in states and states[c.name] != c.state]
            if a.status is b.status and not moved:
                continue
            rows.append({'control_id': a.control_id, 'title': titles.get(a.control_id, ''), 'before': b.status.value,
                         'after': a.status.value, 'change': self._change(b.status.value, a.status.value),
                         'subchecks': '; '.join(moved) or 'No sub-check changed'})
        return tuple(rows)

    def explain_finding(self, connection_session_id, workflow_session_id, control_id, *, timeout=60, round_ref=None):
        """FR17: the local model's plain-language explanation of one finding of a round (the latest by default),
        from code-written facts only. Unverified text that changes nothing; the page labels it so."""
        from .agents import explain_finding
        snapshot = self.snapshot(connection_session_id, workflow_session_id, round_ref)
        finding = next((f for f in snapshot.findings if f.control_id == control_id), None)
        control = next((c for c in snapshot.controls if c.control_id == control_id), None)
        if control is None:
            raise ValueError('No such control in this assessment')
        facts = {'control_id': control.control_id, 'title': control.title, 'area': control.area,
                 'status': control.status.value, 'required': control.expected,
                 'subchecks': [{'name': s.name, 'status': s.status.value, 'reason': s.detail} for s in control.subchecks]}
        if finding is not None:
            facts.update(risk_score=finding.score, level=finding.level, rank=finding.rank,
                         factors={'I': finding.I, 'E': finding.E, 'P': finding.P, 'L': finding.L, 'D': finding.D},
                         factor_reasons=list(finding.derivation_reasons))
        return explain_finding(facts, self.model_client_factory('explanation'), timeout=timeout)

    def _dispatch_one(self, store, binding, proposal, operation_id, *, stack=False):
        from datetime import datetime, timezone
        from vm.ubuntu.remediation_schema import parse_request
        from .approvals import ApprovedRequest
        from .executor import execute
        raw = proposal.approved_raw
        request_id = json.loads(raw)['request_id']
        result = execute(ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw)), ledger=self.ledger,
                         binding=binding, operation_id=_execution_operation(request_id),
                         dispatch=lambda data: self.session.channel.invoke_runner(b'{"op":"execute"}\n' + data),
                         now=datetime.now(timezone.utc), stack=stack)
        if result.receipt_raw is not None:
            store.record_receipt(binding, proposal.proposal_id, result.receipt_raw)
        return result

    # ---- execution acceptance: deployment probe and the two live scenarios ----------------------------
    def _collector_installed(self):
        """True or False from the read-only stat probe of the root-owned collector; None when the channel cannot tell
        (fixture channels without read-only probes)."""
        read = getattr(self.session.channel, 'read', None)
        if read is None:
            return None
        try:
            return read('helper').strip() == '0 755 regular file'
        except ValueError:
            return False

    def setup_status(self, connection_session_id, *, refresh=False):
        """What the one-step setup (setup.sh) provides, read-only: the OpenSCAP scanner, the collector, the runner."""
        self.check(connection_session_id)
        if refresh:
            self._deployment = None
        read = getattr(self.session.channel, 'read', None)
        try:
            openscap = bool(read and read('openscap').startswith('OpenSCAP command line tool'))
        except ValueError:
            openscap = False
        return {'openscap': openscap, 'collector': bool(self._collector_installed()),
                'runner': self.deployment_status(connection_session_id).ok}

    def deployment_status(self, connection_session_id, *, refresh=False):
        """Read-only probe of the root-owned runner, cached per verified connection (`refresh` probes again)."""
        self.check(connection_session_id)
        if refresh or self._deployment is None:
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
            return DeploymentStatus(False, (self._runner_setup_steps(),), None)
        reasons = []
        if abs(offset) > MAX_CLOCK_OFFSET_SECONDS:
            reasons.append('The server clock differs from this computer by %d s (more than %d s): click Sync server clock '
                           'to this laptop on Agentic hardening.' % (round(offset), MAX_CLOCK_OFFSET_SECONDS))
        if probe['collector_digest'] != collector_digest(APP / 'vm' / 'ubuntu'):
            reasons.append('The FYP helper installed on the server differs from this version of the application. On '
                           'the server, run this version\'s sudo python3 fyp-pair-ubuntu.py (download it from Servers): '
                           'it replaces the older tools before showing a code. Then reconnect.')
        expected = {aid: [spec.version, spec.implementation_sha256] for aid, spec in dict(self.families, **AUXILIARY).items()}
        if any(probe['families'].get(aid) != value for aid, value in expected.items()):
            reasons.append('The deployed runner registers different fix families or versions.')
        if probe['launcher'] is not True:
            reasons.append('systemd-run is unavailable on the server, so supervised jobs cannot run.')
        if probe['boot_rollback'] != 'enabled':
            reasons.append('The fix runner\'s boot rollback unit is not enabled on the server. On the server, run '
                           'sudo python3 fyp-pair-ubuntu.py again (it reinstalls the tools before showing a code), then '
                           'reconnect.')
        return DeploymentStatus(not reasons, tuple(reasons), probe['collector_digest'], offset)

    def sync_clock(self, connection_session_id, workflow_session_id, operation_id):
        """Set the server's clock to this laptop's time on the administrator's click, as the Windows page does
        (administrator request 2026-11-11). The dashboard's account is not root on Ubuntu, so the root-owned runner's
        fixed `set_clock` operation does it; the runner refuses while a change is open. Recorded in the ledger as its
        own operation: the account, and the server's time before and after. The deployment is probed again after."""
        from datetime import datetime, timezone
        from vm.ubuntu.remediation_schema import canonical
        binding = self.check(connection_session_id, workflow_session_id) or self.new_binding(connection_session_id)
        account = self.session.username
        owner, _ = self.ledger.claim(binding, operation_id, 'clock_sync', {'intent': operation_id, 'account': account},
                                     mutation=True)
        if not owner:
            raise ValueError('This clock sync was already sent.')
        try:
            reported = json.loads(self.session.channel.invoke_runner(
                canonical({'op': 'set_clock', 'utc': datetime.now(timezone.utc).isoformat()}) + b'\n'))
            if type(reported) is not dict or set(reported) != {'outcome', 'code', 'before', 'after'}:
                raise ValueError('the server confirmed the new time in an unexpected form')
            if reported['outcome'] != 'set':
                raise ValueError('a change is still open on the server; settle it first' if reported['code'] == 'change_open'
                                 else 'the server did not set the clock (%s)' % str(reported['code'])[:40])
            before, after = datetime.fromisoformat(reported['before']), datetime.fromisoformat(reported['after'])
        except Exception as exc:
            reason = str(exc)[:200] if isinstance(exc, ValueError) else 'the server did not answer'
            self.ledger.transition(operation_id, 'refused', detail='Clock not set: ' + reason + '.')
            raise ValueError('Clock not set: ' + reason + '.') from None
        finally:
            self._deployment = None  # measured again on the next look
        self.ledger.transition(operation_id, 'completed', detail=json.dumps(
            {'account': account, 'server_before': before.isoformat(), 'server_after': after.isoformat()}))
        return {'before': before, 'after': after}

    def _runner_setup_steps(self):
        """What to do when the root-owned fix runner does not answer its read-only probe: run the pairing helper on the
        server, which sets it up before showing a code (since 13 November 2026), then reconnect."""
        host = self.session.identity.hostname
        return (f'The fix runner on {host} is not deployed, or it refused its read-only check (for example after a '
                f'snapshot restore). Fixes and the safety check need it: on {host}, run sudo python3 '
                'fyp-pair-ubuntu.py (download it from Servers; it sets the server up before showing a code), then '
                'reconnect.')

    def _acceptance_runs(self):
        s = self.session
        return self.ledger.acceptance_runs(s.target_id, s.registration_epoch)

    def _execution_reasons(self):
        deployment = self.deployment_status(self.session.connection_session_id)
        if not deployment.ok:
            return deployment.reasons
        passed = {(r['scenario'], r['outcome']) for r in self._acceptance_runs()
                  if r['runner_digest'] == deployment.runner_digest}
        if {('confirm', 'confirmed'), ('rollback', 'rolled_back')} <= passed:
            return ()
        # One button runs both tests, so one message (administrator, 13 November 2026).
        return ('the safety check has not passed yet. Click Run safety check below: it runs the confirm test and the '
                'rollback test with a harmless marker file, about a minute.',)

    def acceptance_complete(self, connection_session_id):
        """Both live scenarios passed for the deployed runner and none is open, so the acceptance panel is not needed.
        A reinstall changes the runner digest, which makes it needed again (administrator request 2026-11-08)."""
        self.check(connection_session_id)
        deployment = self.deployment_status(connection_session_id)
        if not deployment.ok or any(r['outcome'] is None for r in self._acceptance_runs()):
            return False
        passed = {(r['scenario'], r['outcome']) for r in self._acceptance_runs()
                  if r['runner_digest'] == deployment.runner_digest}
        return {('confirm', 'confirmed'), ('rollback', 'rolled_back')} <= passed

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
        if self.ledger.owner(self.session.target_id, self.session.registration_epoch):
            # Checked before anything is recorded (live 13 November 2026: the run was recorded, then refused by the
            # open change, and blocked every later safety check).
            raise ValueError('A change is still open on this server; check its status first (Check status settles '
                             'it), then run the safety check.')
        s, spec, nonce = self.session, AUXILIARY['acceptance.marker.v1'], uuid4().hex
        params = {'scenario': scenario, 'nonce': nonce}
        preview = json.loads(self.session.channel.invoke_runner(
            canonical({'op': 'preview', 'action_id': spec.action_id, 'parameters': params}) + b'\n'))
        if type(preview) is not dict or 'refused' in preview:
            raise ValueError('The server refused the safety check marker: ' + str((preview or {}).get('refused'))[:200])
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
            if run['outcome'] is None and self.ledger.operation_state(
                    _execution_operation(run['request_id'])).code == 'unknown_operation':
                # Recorded but never dispatched (its claim was refused): nothing reached the server.
                self.ledger.settle_acceptance(run['request_id'], 'failed:not_dispatched')
                run = next(r for r in self._acceptance_runs() if r['request_id'] == run['request_id'])
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
            raise ValueError('Confirmation needs a fresh login: disconnect, connect to the server again, then confirm. '
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

    # ---- per-server decisions (2026-11-13) -------------------------------------------------------
    def firewall_manager(self):
        """The firewall manager the collector is told this server uses: the code registration given at connect, else
        the administrator's recorded decision ('ufw'), else None (then no UFW fix is planned)."""
        from .server_decisions import decision
        if self.registered_firewall_manager:
            return self.registered_firewall_manager
        return 'ufw' if decision(self.session.identity.machine_identity, 'firewall_manager') == 'ufw' else None

    def server_decisions(self, connection_session_id):
        """Each per-server decision of this server: its value (or None), where it comes from, who and when."""
        from .server_decisions import CHOICES, ServerDecisions, decision, source, store_path
        self.check(connection_session_id)
        machine = self.session.identity.machine_identity
        recorded = ServerDecisions(store_path()).latest(machine) if store_path().exists() else {}
        return {key: {'value': decision(machine, key), 'source': source(machine, key),
                      'operator': (recorded.get(key) or {}).get('operator'),
                      'decided_at': (recorded.get(key) or {}).get('decided_at')} for key in CHOICES}

    def record_server_decision(self, connection_session_id, key, value, operator):
        """Record one decision for the connected server (its verified machine ID). A code registration stands."""
        from .server_decisions import ServerDecisions, source, store_path
        self.check(connection_session_id)
        machine = self.session.identity.machine_identity
        if source(machine, key) == 'code':
            raise ValueError('This decision is registered in the program for this server and cannot be changed here.')
        return ServerDecisions(store_path()).record(machine, key, value, operator=operator)

    # ---- Complete hardening (module 1, as on the Windows page) ------------------------------------
    def _completions(self):
        from .completion import CompletionStore
        return CompletionStore(self.database_path.with_name('ubuntu_completion.sqlite3'))

    def _refuse_completed(self, binding):
        if binding is not None and self._completions().completion(binding.target_id, binding.workflow_session_id):
            raise ValueError('This hardening session is already completed (read-only). Click New session to check the server '
                             'again.')

    def completion(self, connection_session_id, workflow_session_id):
        """This session's completion record, or None (read-only)."""
        binding = self.check(connection_session_id, workflow_session_id)
        return self._completions().completion(binding.target_id, workflow_session_id) if binding else None

    def completion_state(self, connection_session_id, workflow_session_id):
        """What is still open in the newest scan of the session's latest round, and its exceptions (read-only)."""
        from .completion import open_items
        binding = self.check(connection_session_id, workflow_session_id)
        if binding is None:
            raise ValueError('No hardening session to complete.')
        snapshot = self.snapshot(connection_session_id, workflow_session_id, newest_scan=True)
        exceptions = self._completions().exceptions(binding.target_id, workflow_session_id)
        return {'items': open_items(snapshot.controls, exceptions), 'exceptions': exceptions,
                'total': len(snapshot.controls), 'scanned_at': snapshot.summary.collected_at if snapshot.summary else None}

    def accept_exception(self, connection_session_id, workflow_session_id, control_id, operator, reason):
        """Accept one control that is open in the newest scan as an exception of this session, with a reason."""
        binding = self.check(connection_session_id, workflow_session_id)
        self._refuse_completed(binding)
        state = self.completion_state(connection_session_id, workflow_session_id)
        if control_id not in {i['control_id'] for i in state['items']}:
            raise ValueError(f'{control_id} is not open in the newest scan, so there is nothing to accept.')
        rounds = [r for r in self._store().rounds(binding) if r.kind == 'assessment']
        return self._completions().accept(binding.target_id, workflow_session_id, control_id, operator=operator,
                                          reason=reason, round_id=rounds[-1].round_id if rounds else None)

    def complete_hardening(self, connection_session_id, workflow_session_id, operator, operation_id):
        """Run the final read-only scan (claimed like an assessment, recorded as the latest round's newest scan) and
        complete the session if every control is Compliant or accepted as an exception. Returns completed=False with
        the open items otherwise. Writes nothing on the server."""
        from .completion import open_items
        binding = self.check(connection_session_id, workflow_session_id)
        if binding is None:
            raise ValueError('No hardening session to complete.')
        self._refuse_completed(binding)
        if not (operator or '').strip():
            raise ValueError('Type your name first: it is recorded with the completion.')
        gate = assessment_gate()
        if gate:
            raise ValueError(gate[0] + ' No scan was run.')
        store = self._store()
        latest = self._latest(store, binding)
        owner, _ = self.ledger.claim(binding, operation_id, 'assessment', {'intent': operation_id, 'mode': 'final_scan'})
        if not owner:
            raise ValueError('This final scan was already started.')
        try:
            run_id, evidence = self._collect(store, binding)
            store.record_round(binding, run_id, mode='deterministic', kind='verification',
                               details={'verifies_round': latest.round_id, 'request_ids': []})
        except Exception:
            self.ledger.transition(operation_id, 'refused', detail='Final scan failed; nothing was changed.')
            raise
        self.ledger.transition(operation_id, 'completed', detail=run_id)
        snapshot = self.snapshot(connection_session_id, workflow_session_id, newest_scan=True)
        completions = self._completions()
        exceptions = completions.exceptions(binding.target_id, workflow_session_id)
        items = open_items(snapshot.controls, exceptions)
        if items:
            return {'completed': False, 'items': items, 'run_id': run_id}
        compliant = sum(c.status.value == 'Compliant' for c in snapshot.controls)
        accepted = [{'control_id': c.control_id, 'title': c.title, 'status': c.status.value,
                     'reason': exceptions[c.control_id]['reason'], 'operator': exceptions[c.control_id]['operator']}
                    for c in snapshot.controls if c.status.value != 'Compliant']
        completions.complete(binding.target_id, workflow_session_id, operator=operator, final_run_id=run_id,
                             compliant=compliant, total=len(snapshot.controls), exceptions=accepted)
        return {'completed': True, 'compliant': compliant, 'total': len(snapshot.controls), 'exceptions': accepted,
                'run_id': run_id}

    def live_validation(self, connection_session_id):
        """Module 3: the live-validation register of this server, one row per selected control, from its stored
        approvals, receipts and verification scans (all workflows of this registration; read-only). The rows are
        tools.live_validation_register.register rows, the same as the command-line tool prints."""
        from tools.live_validation_register import register
        self.check(connection_session_id)
        store, s = self._store(), self.session
        decisions, receipts, verifications = [], [], {}
        for binding in self.ledger.bindings_for_target('ubuntu', s.target_id, s.registration_epoch) if store else ():
            rounds = store.rounds(binding)
            controls_of = {}
            for r in rounds:
                if r.kind != 'assessment':
                    continue
                for p in store.proposals(binding, r.round_id):
                    if p.decision != 'approved' or not p.approved_raw:
                        continue
                    request = json.loads(p.approved_raw)
                    decisions.append({'request_id': request['request_id'], 'control_id': request['control_id'],
                                      'action_id': request['action']['action_id'], 'approver': request.get('approver'),
                                      'round_id': r.round_id, 'workflow': binding.workflow_session_id})
                    receipts.extend(p.receipts)
                    controls_of[request['request_id']] = request['control_id']
            for r in rounds:
                if r.kind != 'verification':
                    continue
                statuses = {a.control_id: a.status.value for a in self._evidence(store, r.evidence_sha256).assessments}
                for request_id in (r.details or {}).get('request_ids', ()):
                    if controls_of.get(request_id) in statuses:
                        verifications[request_id] = statuses[controls_of[request_id]]
        ordered = sorted(_controls(), key=lambda c: [int(x) for x in c.split('.')])
        return register(ordered, decisions=decisions, receipts=receipts, verifications=verifications,
                        automated=_fixed_controls())  # as on Windows: a control without a fix is Manual on the server

    def pending_reboot(self, connection_session_id):
        """The approved reboot still running on this server (from the stored receipts; no SSH), or None: while it is
        open, a dropped connection means the server is restarting, and the page reconnects by itself (task 6)."""
        self.check(connection_session_id)
        store = self._store()
        for item in self.pending_supervised(connection_session_id) if store else ():
            binding = self.ledger.resume(item.workflow_session_id, 'ubuntu', self.session.target_id,
                                         self.session.registration_epoch)
            proposal = next((p for p in store.proposals(binding, item.round_reference.record_id) if p.approved_raw
                             and json.loads(p.approved_raw)['request_id'] == item.request_id), None)
            if proposal is not None and proposal.payload['action']['action_id'] == 'maintenance.reboot.v1':
                return item
        return None

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
            elif result.state != 'completed' and state == 'completed':
                state = result.state
        # CIS fixes and a reboot are followed by a fresh scan, once per execution (_verify_when_settled).
        return RoundHandle(operation_id, binding, round_ref, self._verify_when_settled(store, binding, latest, state))

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
            raise ValueError('Confirmation needs a fresh login: disconnect, connect to the server again, then confirm. '
                             'That new login is the proof the change kept SSH working.')
        raw = proposal.approved_raw
        approved = ApprovedRequest(raw, hashlib.sha256(raw).hexdigest(), parse_request(raw))
        header = canonical({'op': 'confirm', 'request_id': request_id})
        result = confirm(approved, ledger=self.ledger, operation_id=operation,
                         send=lambda rid: self.session.channel.invoke_runner(header + b'\n'))
        self._record_status(store, binding, proposal, result)
        return RoundHandle(operation_id, binding, round_ref,
                           self._verify_when_settled(store, binding, latest, result.state))

    def _unverified(self, store, binding, latest):
        """Request IDs of applied fixes and maintenance in this round that no verification scan has covered."""
        covered = {rid for r in store.rounds(binding) if r.kind == 'verification'
                   and (r.details or {}).get('verifies_round') == latest.round_id
                   for rid in (r.details or {}).get('request_ids', ())}
        found = []
        for p in store.proposals(binding, latest.round_id):
            if (p.decision == 'approved' and p.receipts and not p.payload['action']['action_id'].startswith(NO_SCAN_AFTER)
                    and p.receipts[-1]['outcome'] in ('applied', 'reconciled_applied')
                    and p.receipts[-1]['request_id'] not in covered):
                found.append(p.receipts[-1]['request_id'])
        return found

    def unverified_applied(self, connection_session_id, workflow_session_id):
        """Applied changes of the latest round still waiting for their verification scan (read only)."""
        binding = self.check(connection_session_id, workflow_session_id)
        store = self._store()
        if store is None or binding is None:
            return ()
        rounds = [r for r in store.rounds(binding) if r.kind == 'assessment']
        return tuple(self._unverified(store, binding, rounds[-1])) if rounds else ()

    def verify_applied(self, connection_session_id, workflow_session_id, round_ref, operation_id):
        """Run the read-only verification scan for applied changes that have none (e.g. the scan failed after a
        job settled). Never dispatches a change again (administrator request 2026-11-08)."""
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        store = self._store()
        latest = self._latest(store, binding, round_ref)
        applied = self._unverified(store, binding, latest)
        if not applied:
            return RoundHandle(operation_id, binding, round_ref, 'nothing_to_verify')
        return RoundHandle(operation_id, binding, round_ref, self._verify(store, binding, latest, applied, 'completed'))

    def _verify_when_settled(self, store, binding, latest, state):
        """One verification scan per execution (administrator, 13 November 2026: a full scan after each of the seven
        fixes that ran one by one took about 6 of 10 minutes). While a fix still runs or waits, or approved fixes of
        the execution continue, the scan waits; once it has settled, one scan covers every applied fix no scan
        covered yet. An execution that stops for a person is settled too, so nothing applied stays unobserved."""
        if state in ('running', 'awaiting_confirmation') or self._continuable(store, binding, latest)[0]:
            return state
        if any(p.decision == 'approved' and p.receipts and p.receipts[-1]['outcome'] == 'running'
               and not p.payload['action']['action_id'].startswith(AUXILIARY_PREFIXES)
               for p in store.proposals(binding, latest.round_id)):
            return state  # another change of the execution still waits (a stacked confirmation)
        return self._verify(store, binding, latest, self._unverified(store, binding, latest), state)

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

    # ---- auxiliary: package-list refresh and reboot -----------------------------------------------
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
        if 'refused' in preview:
            raise ValueError('The server refused it: ' + str(preview['refused'])[:200])
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
        """A package-list refresh or a reboot completing applied changes: preview and store an auxiliary proposal of the
        latest round. Approval and dispatch follow like any other proposal. A per-control restore of an applied fix is
        not offered (administrator, 12 November 2026: as on Windows); the server's own rollbacks stay."""
        from system.contracts import AuxiliaryKind, OperationState
        binding = self.check(connection_session_id, workflow_session_id, basis)
        if AuxiliaryKind(kind) in (AuxiliaryKind.METADATA_REFRESH, AuxiliaryKind.REBOOT):
            return self._request_maintenance(binding, AuxiliaryKind(kind), inputs, operation_id)
        if AuxiliaryKind(kind) is AuxiliaryKind.RECOVERY:
            raise ValueError('A restore of an applied fix is not offered on Ubuntu, as on Windows. A change the server '
                             'could not confirm is restored by the server itself; otherwise use your own backup of '
                             'the server.')
        return OperationState(operation_id, 'refused', code='unsupported',
                              detail='This auxiliary operation is not implemented for Ubuntu.')

    def dispatch_auxiliary(self, connection_session_id, workflow_session_id, proposal_ref, operation_id):
        """Run one approved maintenance proposal once, behind the same gates, then verify with a fresh scan. Restore
        proposals stored before 12 November 2026 are history only: their action is no longer registered."""
        binding = self.check(connection_session_id, workflow_session_id, proposal_ref)
        gate = execution_gate(self)
        if gate:
            raise ValueError(gate[0])
        store = self._store()
        latest = self._latest(store, binding)
        proposal = next((p for p in store.proposals(binding, latest.round_id) if p.proposal_id == proposal_ref.record_id), None)
        if (proposal is None or not proposal.payload['action']['action_id'].startswith('maintenance.')
                or proposal.decision != 'approved'):
            raise ValueError('Only an approved maintenance proposal of the latest round can be dispatched')
        if proposal.receipts:
            return RoundHandle(operation_id, binding, self._ref(latest.round_id), 'completed')  # never twice
        result = self._dispatch_one(store, binding, proposal, operation_id)
        applied = [json.loads(proposal.approved_raw)['request_id']] if result.state == 'completed' else []
        return RoundHandle(operation_id, binding, self._ref(latest.round_id),
                           self._verify(store, binding, latest, applied, result.state))
