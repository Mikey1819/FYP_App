"""Agentic hardening page: one live VM, AI-coordinated rounds, human approval, verified fixes."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from uuid import uuid4

import streamlit as st

from .action_library import LIBRARY
from .agentic import (ANALYSIS, MAX_GOAL_CHARS, ORCHESTRATOR, REMEDIATION, SCANNER, AgenticHardening, explain_finding,
                      verdict_kind)
from .connection_view import render_connection
from .framework import AssessmentRuns
from .import_storage import ImportedEvidenceStore
from .remediation import RemediationStore
from .round_report import round_analysis, round_report, shown
from .ui import VERDICT_COLOR, badge, level_badge, md_escape, myt
from .winrm_channel import ChannelError, LiveScanner
from system.bootstrap import active_backend, CONNECTION_KEY, WORKFLOW_KEY
from system.contracts import AssessmentMode, RecordRef
from system.ui.components import render_controls, render_snapshot_tabs
from backends.windows.adapter import original_services

# Plain session keys (not widget keys), so they survive switching to another page and back.
SESSION = 'agentic_session'
CONFIRM = 'agentic_confirm'
# Widget keys that are reset on purpose when a new round or remediation result arrives.
TAB = 'agentic_tab'
ROUND_VIEW = 'agentic_round_view'
GOAL = 'agentic_goal'
COMMENT = 'agentic_comment'

TABS = ('Fixes', 'Risk ranking', 'Controls', 'Results', 'Agent log')
STEPS = ('Scan', 'Analyse', 'Plan', 'Approve', 'Execute', 'Verify')
STEP_BADGE = {'done': ('green', 'check'), 'current': ('blue', 'arrow_forward'), 'failed': ('red', 'close'),
              'pending': ('gray', None), 'skipped': ('gray', 'remove')}
NEXT_STEP = {'finish': ('green', 'Finished'), 'next_round': ('blue', 'Next round recommended'),
             'remediation_review': ('orange', 'Needs your review'), 'fallback': ('blue', 'Executed without AI'),
             'incomplete': ('orange', 'Agents stopped early')}
PLANNED = ('awaiting_approval', 'no_fix_proposed', 'no_findings')
VERDICT_LABEL = {'verified': 'Verified compliant', 'failed': 'Failed', 'refused': 'Refused',
                 'uncertain': 'Outcome uncertain'}
AGENT_ORDER = {ORCHESTRATOR: 0, SCANNER: 1, ANALYSIS: 2, REMEDIATION: 3}


def _services(database_path, target):
    backend = active_backend(st.session_state)
    if backend:
        return backend.runtime, backend.store, backend.engine
    return original_services(database_path, target, scanner_factory=LiveScanner)


def _decide(store, request_id, *, approve, operator, comment):
    backend = active_backend(st.session_state)
    if backend:
        backend.decide(st.session_state[CONNECTION_KEY], st.session_state[WORKFLOW_KEY],
            RecordRef('windows', backend.session.target_id, request_id), approve, operator, comment, uuid4().hex)
    else:
        store.decide(request_id, approve=approve, operator=operator, comment=comment)


def _execute(hardening, session_id, *, deterministic=False, expected=None):
    backend = active_backend(st.session_state)
    if backend:
        workflow = st.session_state[WORKFLOW_KEY]
        connection = st.session_state[CONNECTION_KEY]
        snapshot = backend.snapshot(connection, workflow)
        if expected is None:
            raise ValueError('An exact displayed approval set must be confirmed before dispatch')
        return backend.execute_approved(connection, workflow, snapshot.current_round_reference,
                                        expected, deterministic, uuid4().hex)
    return hardening.execute_approved(session_id, deterministic=deterministic)


def _round_state(store, rounds, assessment_round):
    """What the page needs about one assessment round, from stored records only."""
    run_id = assessment_round['framework_run_id']
    records = store.for_run(run_id) if run_id else []
    verification = next((r for r in reversed(rounds) if r['kind'] == 'verification_scan'
                         and r.get('remediated_run_id') == run_id), None) if run_id else None
    return dict(records=records, verification=verification,
                undecided=[r for r in records if r['decision'] is None],
                pending=[r for r in records if r['decision'] == 'approved' and r['verdict'] is None])


def _steps(assessment_round, state, analysis):
    steps = dict.fromkeys(STEPS, 'pending')
    if not assessment_round['framework_run_id']:
        steps['Scan'] = 'failed'
        return steps
    steps['Scan'] = 'done'
    if analysis is None:
        steps['Analyse'] = 'failed'
        return steps
    steps['Analyse'] = 'done'
    if assessment_round.get('mode') == 'deterministic':
        steps.update(Plan='skipped', Approve='skipped', Execute='skipped', Verify='skipped')
        return steps
    planned = assessment_round['outcome']['outcome'] in PLANNED
    steps['Plan'] = 'done' if planned else 'failed'
    if not state['records']:
        if planned:
            steps.update(Approve='skipped', Execute='skipped', Verify='skipped')
        return steps
    # An Orchestrator that stopped early may already have stored proposals; they still await a decision.
    steps['Approve'] = 'current' if state['undecided'] else 'done'
    verification = state['verification']
    if verification:
        steps['Execute'] = 'current' if state['pending'] else 'done'  # The agents may stop before every fix ran.
        steps['Verify'] = 'done' if verification['framework_run_id'] else 'failed'
    elif state['pending'] and not state['undecided']:
        steps['Execute'] = 'current'
    elif not state['undecided'] and not any(r['decision'] == 'approved' for r in state['records']):
        steps.update(Execute='skipped', Verify='skipped')  # Everything was rejected.
    return steps


def _show_progress(steps, verification):
    parts = []
    for number, name in enumerate(STEPS, 1):
        color, icon = STEP_BADGE[steps[name]]
        parts.append(badge(f'{number} {name}', color, icon))
    outcome = (verification or {}).get('outcome')
    if outcome and outcome['outcome'] in NEXT_STEP:
        color, label = NEXT_STEP[outcome['outcome']]
        parts.append(badge(label, color, 'flag'))
    st.markdown(' → '.join(parts))


def _default_tab(state):
    if state['undecided'] or state['pending']:
        return 'Fixes'
    return 'Results' if state['verification'] else 'Risk ranking'


def _round_target(runtime, assessment_round):
    """The VM a round scanned, or None when its scan never completed or its run is missing."""
    try:
        run_id = assessment_round['framework_run_id']
        return runtime.get(run_id).target_id.casefold() if run_id else None
    except ValueError:
        return None


def _target_id(target):
    return ('windows:' + target.machine_uuid).casefold()


def _previous_session(store, runtime, target):
    """Newest assessment round of an earlier session on this VM, so a browser refresh does not strand it."""
    backend = active_backend(st.session_state)
    def matches(row):
        if row['kind'] != 'assessment' or _round_target(runtime, row) != _target_id(target):
            return False
        if not backend:
            return True
        s = backend.session
        return backend.ledger.binding_for_backend('windows', s.target_id, s.registration_epoch, row['session_id']) is not None
    return next((r for r in store.recent_rounds(20) if matches(r)), None)


def _reset_view():
    for key in (TAB, ROUND_VIEW, CONFIRM):
        st.session_state.pop(key, None)


def _goal_input():
    return st.text_input('Goal for this round (optional)', key=GOAL, max_chars=MAX_GOAL_CHARS, persist_state='session',
                         placeholder='e.g. Keep RDP usable for remote support this week',
                         help='The Orchestrator reads the goal and may only narrow or reorder its plan. '
                              'You see how it was read before you approve anything.')


def _run_round(hardening, session_id, goal, mode=AssessmentMode.AGENTIC):
    # The session is kept before the round starts, so its records stay reachable whatever happens to the page.
    session_id = session_id or uuid4().hex
    st.session_state[SESSION] = session_id
    with st.spinner('Round running: Orchestrator → Scanner → Analysis → plan. This can take up to 10 minutes.'):
        backend = active_backend(st.session_state)
        if backend:
            handle = backend.start_round(st.session_state[CONNECTION_KEY], st.session_state.get(WORKFLOW_KEY),
                                          goal, mode, uuid4().hex)
            st.session_state[WORKFLOW_KEY] = handle.binding.workflow_session_id
            st.session_state[SESSION] = handle.binding.backend_session_id
        else:
            hardening.run_round(session_id, goal=goal)
    _reset_view()
    st.session_state.pop(GOAL, None)  # A goal is for one round; the next one starts without it.
    st.rerun()


def _ubuntu_states(snapshot):
    executed = {r.proposal_reference for r in snapshot.results}
    applied = {r.proposal_reference for r in snapshot.results if r.execution_state in ('applied', 'reconciled_applied')}
    restoring = {p.title.split('(undo ')[0] for p in snapshot.proposals if p.kind == 'recovery'}
    return executed, applied, restoring


def _ubuntu_fix_header(backend, connection, snapshot):
    """Refresh and pending verification, then the operator name and comment the per-control cards use."""
    error, notice = st.session_state.pop('ubuntu_verify_error', None), st.session_state.pop('ubuntu_verify_notice', None)
    if error:
        st.error(md_escape(error))
    if notice:
        st.success(md_escape(notice))
    workflow = st.session_state.get(WORKFLOW_KEY)
    unverified = backend.unverified_applied(connection, workflow) if workflow else ()

    def verify():
        try:
            handle = backend.verify_applied(connection, workflow, snapshot.current_round_reference, uuid4().hex)
            st.session_state['ubuntu_verify_notice'] = 'Verification scan: ' + handle.state.replace('_', ' ') + '.'
        except (ValueError, OSError) as failure:
            st.session_state['ubuntu_verify_error'] = str(failure)[:300]
    with st.container(horizontal=True):
        # A browser reload starts a new session and ends the connection (credentials live only in this session).
        st.button('Refresh status', key='ubuntu_refresh', icon=':material/refresh:',
                  help='Reload this page from the stored records; the VM connection stays open.')
        if unverified:
            st.button('Run verification scan', key='ubuntu_verify_applied', icon=':material/fact_check:', type='primary',
                      on_click=verify, help='Read-only re-scan for applied changes that have none yet; never re-runs a fix.')
    if unverified:
        st.warning('%d applied change%s still need%s the verification scan, so the card%s cannot show the result yet.'
                   % (len(unverified), '' if len(unverified) == 1 else 's', 's' if len(unverified) == 1 else '',
                      '' if len(unverified) == 1 else 's'))
    if any(p.eligible_commands for p in snapshot.proposals):
        st.text_input('Your name (recorded with each decision)', key='agentic_operator')
        st.text_input('Comment (optional)', key='agentic_comment')


def _ubuntu_decision_buttons(backend, connection, workflow, p):
    operator = st.session_state.get('agentic_operator') or ''
    comment = st.session_state.get('agentic_comment') or ''
    label = p.control_id or p.title
    if 'approve' not in p.eligible_commands:  # e.g. it shares a file with an approved fix not executed yet
        st.warning(md_escape(p.reason))
    left, right = st.columns(2)
    if left.button('Approve ' + label, key='ubuntu_approve_' + p.reference.record_id,
                   disabled=not operator.strip() or 'approve' not in p.eligible_commands):
        backend.decide(connection, workflow, p.reference, True, operator, comment, uuid4().hex)
        st.rerun()
    if right.button('Reject ' + label, key='ubuntu_reject_' + p.reference.record_id, disabled=not operator.strip()):
        backend.decide(connection, workflow, p.reference, False, operator, comment, uuid4().hex)
        st.rerun()


def _ubuntu_card_actions(backend, connection, snapshot, capabilities, card):
    """Inside one control's card: approve/reject its proposals, prepare and run an approved restore."""
    workflow = st.session_state.get(WORKFLOW_KEY)
    executed, applied, restoring = _ubuntu_states(snapshot)
    for p in card['proposals']:
        if p.eligible_commands:
            _ubuntu_decision_buttons(backend, connection, workflow, p)
    _ubuntu_restore_actions(backend, connection, card['proposals'], capabilities, workflow, applied, executed, restoring)


def _ubuntu_fix_actions(backend, connection, snapshot, capabilities):
    """Ubuntu decisions and execution through the backend's typed commands only. With a plan, per-control decisions
    and restores sit inside each control's card; this renders the rest (execution, maintenance)."""
    from system.ui.components import plan_cards
    workflow = st.session_state.get(WORKFLOW_KEY)
    carded = {p.reference for c in plan_cards(snapshot) for p in c['proposals']}
    rest = [p for p in snapshot.proposals if p.reference not in carded]
    undecided = [p for p in rest if p.eligible_commands]
    # The CIS fix set only; approved restores run separately through dispatch_auxiliary.
    approved = [p for p in snapshot.proposals if p.decision == 'approved' and p.approved_request_id
                and p.kind == 'control_remediation']
    executed, applied, restoring = _ubuntu_states(snapshot)
    if undecided:
        if not snapshot.plan:  # without cards the name and comment fields are rendered here
            _ubuntu_fix_header(backend, connection, snapshot)
        for p in undecided:
            _ubuntu_decision_buttons(backend, connection, workflow, p)
    if approved:
        pending = [p for p in approved if p.reference not in executed]
        ids = tuple(p.approved_request_id for p in approved)
        st.caption('Approved set: ' + ', '.join(md_escape(p.control_id + ' (' + p.approved_request_id[:8] + ')')
                                                for p in approved))
        error = st.session_state.pop('ubuntu_execute_error', None)
        if error:
            st.error(md_escape(error))
        confirmed = st.checkbox(f'I confirm executing exactly these {len(pending)} approved change(s) on the VM',
                                key='ubuntu_confirm_execute', disabled=not pending)

        def execute():
            # Runs once per click, before the rerun; the confirmation is cleared so it never carries over.
            st.session_state['ubuntu_confirm_execute'] = False
            try:
                backend.execute_approved(connection, workflow, snapshot.current_round_reference, ids, True, uuid4().hex)
            except ValueError as failure:
                st.session_state['ubuntu_execute_error'] = str(failure)[:300]
        st.button('Execute approved fixes', key='ubuntu_execute', on_click=execute,
                  disabled=not (capabilities.can_remediate and confirmed and pending))
    _ubuntu_restore_actions(backend, connection, rest, capabilities, workflow, applied, executed, restoring)
    _ubuntu_maintenance_actions(backend, connection, snapshot, capabilities, workflow, applied, executed)


def _ubuntu_maintenance_actions(backend, connection, snapshot, capabilities, workflow, applied, executed):
    """Package-list refresh and a reboot completing applied changes: prepare, approve above, confirm, run once."""
    from system.contracts import AuxiliaryKind, MetadataRefreshInput, RebootInput
    open_kinds = {p.kind for p in snapshot.proposals
                  if p.kind in ('metadata_refresh', 'reboot') and p.reference not in executed and p.decision != 'rejected'}
    staged = tuple(p.approved_request_id for p in snapshot.proposals
                   if p.kind == 'control_remediation' and p.reference in applied)

    def prepare(kind):
        try:
            inputs = MetadataRefreshInput('') if kind is AuxiliaryKind.METADATA_REFRESH else RebootInput(staged, 'now')
            backend.request_auxiliary(connection, workflow, kind, None, inputs, uuid4().hex)
        except (ValueError, OSError) as failure:
            st.session_state['ubuntu_execute_error'] = str(failure)[:300]
    with st.container(horizontal=True):
        st.button('Prepare package-list refresh', key='ubuntu_prepare_refresh', on_click=prepare,
                  args=(AuxiliaryKind.METADATA_REFRESH,),
                  disabled=not capabilities.can_remediate or 'metadata_refresh' in open_kinds,
                  help='apt-get update only: installs nothing and changes no configuration.')
        st.button('Prepare reboot to complete applied changes', key='ubuntu_prepare_reboot', on_click=prepare,
                  args=(AuxiliaryKind.REBOOT,), disabled=not capabilities.can_remediate or 'reboot' in open_kinds or not staged,
                  help='Needs applied fixes. The VM restarts 60 s after it runs; reconnect, then Check status.')
    for p in snapshot.proposals:
        if p.kind not in ('metadata_refresh', 'reboot') or p.decision != 'approved' or p.reference in executed:
            continue
        key = p.reference.record_id
        label = 'package-list refresh' if p.kind == 'metadata_refresh' else 'reboot of the VM'
        confirmed = st.checkbox('I confirm running the approved ' + label, key='ubuntu_confirm_maintenance_' + key)

        def run(reference=p.reference, key=key):
            st.session_state['ubuntu_confirm_maintenance_' + key] = False
            try:
                backend.dispatch_auxiliary(connection, workflow, reference, uuid4().hex)
            except (ValueError, OSError) as failure:
                st.session_state['ubuntu_execute_error'] = str(failure)[:300]
        st.button('Run approved ' + label, key='ubuntu_run_maintenance_' + key, on_click=run,
                  disabled=not (capabilities.can_remediate and confirmed))


def _ubuntu_acceptance(backend, connection):
    """Execution acceptance: two live runs of a harmless marker prove the confirm and rollback paths on this VM."""
    error, notice = (st.session_state.pop('ubuntu_acceptance_error', None),
                     st.session_state.pop('ubuntu_acceptance_notice', None))
    with st.expander('Execution acceptance (required before any live fix)', expanded=bool(error or notice)):
        if error:
            st.error(md_escape(error))
        if notice:
            st.success(md_escape(notice))
        deployment = backend.deployment_status(connection)
        if not deployment.ok:
            for reason in deployment.reasons:
                st.warning(md_escape(reason))
            return
        st.caption('Writes only a marker file in the runner state directory on the VM; no system setting changes.')
        runs = backend.acceptance_status(connection)
        for run in runs:
            label = md_escape(run.scenario + ' scenario (' + run.request_id[:8] + '): ' + (run.outcome or run.code))
            if run.outcome is not None:
                st.markdown('- ' + label)
                continue
            if run.scenario == 'confirm' and run.code == 'awaiting_confirmation':
                st.warning(label + '. Disconnect, reconnect to the VM, then confirm within about a minute.')
            elif run.scenario == 'rollback' and run.code == 'awaiting_confirmation':
                st.info(label + '. Do not confirm: the rollback timer restores it shortly; then check status.')
            else:
                st.info(label)

            def act(run=run, confirm=False):
                try:
                    # Settle in the click handler, before the page (and the gate reasons) render.
                    if not confirm:
                        backend.acceptance_status(connection)
                    else:
                        done = backend.confirm_acceptance(connection, run.request_id)
                        st.session_state['ubuntu_acceptance_notice'] = run.scenario + ' scenario: ' + (done.outcome or done.code)
                except (ValueError, OSError) as failure:
                    st.session_state['ubuntu_acceptance_error'] = str(failure)[:300]
            with st.container(horizontal=True):
                st.button('Check status', key='ubuntu_acceptance_status_' + run.request_id, on_click=act)
                if run.scenario == 'confirm' and run.code == 'awaiting_confirmation':
                    st.button('Confirm', key='ubuntu_acceptance_confirm_run_' + run.request_id, type='primary',
                              on_click=act, kwargs={'confirm': True})
        operator = st.text_input('Your name (recorded with the acceptance approval)', key='ubuntu_acceptance_operator')
        open_run = any(run.outcome is None for run in runs)

        def start(scenario):
            try:
                backend.start_acceptance(connection, scenario, operator, uuid4().hex)
                st.session_state['ubuntu_acceptance_notice'] = scenario + ' scenario started.'
            except (ValueError, OSError) as failure:
                st.session_state['ubuntu_acceptance_error'] = str(failure)[:300]
        with st.container(horizontal=True):
            for scenario, label in (('confirm', 'Run confirm scenario'), ('rollback', 'Run rollback scenario')):
                st.button(label, key='ubuntu_acceptance_' + scenario, on_click=start, args=(scenario,),
                          disabled=open_run or not operator.strip())


def _ubuntu_pending_changes(backend, connection):
    """Changes still running or waiting for confirmation on this VM, from any workflow, so a fresh login finds them."""
    error, notice = st.session_state.pop('ubuntu_pending_error', None), st.session_state.pop('ubuntu_pending_notice', None)
    if error:
        st.error(md_escape(error))
    if notice:
        st.success(md_escape(notice))
    for item in backend.pending_supervised(connection):
        def act(item=item, confirm=False):
            try:
                if confirm:
                    handle = backend.confirm_change(connection, item.workflow_session_id, item.round_reference,
                                                    item.request_id, uuid4().hex)
                else:
                    handle = backend.refresh_execution(connection, item.workflow_session_id, item.round_reference,
                                                       uuid4().hex)
                st.session_state[WORKFLOW_KEY] = item.workflow_session_id
                st.session_state['ubuntu_pending_notice'] = (item.control_id + ': ' + handle.state.replace('_', ' ') + '.')
            except (ValueError, OSError) as failure:
                st.session_state['ubuntu_pending_error'] = str(failure)[:300]
        label = md_escape(item.control_id + ' · ' + item.title)
        if item.code == 'awaiting_confirmation':
            st.warning(f'**{label}** was applied and is waiting for confirmation. Disconnect, reconnect to the VM '
                       '(a fresh login proves SSH still works), then confirm before the rollback timer restores it.')
        elif item.outcome == 'running':
            st.info(f'**{label}** is running under systemd supervision ({md_escape(item.code)}). Check its status.')
        else:
            st.warning(f'**{label}**: outcome unknown ({md_escape(item.code)}). Check its status before any other change.')
        with st.container(horizontal=True):
            st.button('Check status', key='ubuntu_status_' + item.request_id, on_click=act)
            if item.code == 'awaiting_confirmation':
                st.button('Confirm change', key='ubuntu_confirm_change_' + item.request_id, type='primary',
                          on_click=act, kwargs={'confirm': True})


def _ubuntu_restore_actions(backend, connection, proposals, capabilities, workflow, applied, executed, restoring):
    """Approved recovery: prepare a restore of an applied fix, approve it, then confirm and run it once."""
    from system.contracts import AuxiliaryKind, RecoveryInput
    for p in proposals:
        if (p.kind == 'control_remediation' and p.reference in applied
                and 'Restore before-state of ' + p.control_id + ' ' not in restoring):
            if st.button('Prepare restore of ' + p.control_id, key='ubuntu_prepare_restore_' + p.reference.record_id,
                         disabled=not capabilities.can_remediate):
                backend.request_auxiliary(connection, workflow, AuxiliaryKind.RECOVERY, p.reference,
                                          RecoveryInput(p.approved_request_id, p.before_state_sha256,
                                                        'restore_before_state'), uuid4().hex)
                st.rerun()
    for p in proposals:
        if p.kind != 'recovery' or p.decision != 'approved' or p.reference in executed:
            continue
        key = p.reference.record_id
        confirmed = st.checkbox('I confirm restoring the recorded before-state of ' + p.control_id + ' on the VM',
                                key='ubuntu_confirm_restore_' + key)

        def run(reference=p.reference, key=key):
            st.session_state['ubuntu_confirm_restore_' + key] = False
            try:
                backend.dispatch_auxiliary(connection, workflow, reference, uuid4().hex)
            except ValueError as failure:
                st.session_state['ubuntu_execute_error'] = str(failure)[:300]
        st.button('Run approved restore of ' + p.control_id, key='ubuntu_run_restore_' + key, on_click=run,
                  disabled=not (capabilities.can_remediate and confirmed))


def _show_start(hardening, store, runtime, target):
    st.markdown('No round in this session yet. A round scans the VM, ranks the findings and proposes fixes. '
                'Nothing changes on the VM until you approve and execute.')
    previous = _previous_session(store, runtime, target)
    if previous:
        state = _round_state(store, store.rounds(previous['session_id']), previous)
        open_items = len(state['undecided']) + len(state['pending'])
        st.caption(f"Earlier session on {md_escape(target.hostname)}: last round {myt(previous['created_at'])}"
                   + (f', {open_items} fix(es) still open.' if open_items else '.'))
    goal = _goal_input()
    with st.container(horizontal=True):
        if st.button('Start agentic round', type='primary', key='agentic_run'):
            _run_round(hardening, None, goal)
        if active_backend(st.session_state) and st.button('Assess without AI', key='agentic_assess_without_ai'):
            _run_round(hardening, None, None, AssessmentMode.DETERMINISTIC)
        if previous and st.button('Resume earlier session', key='agentic_resume'):
            backend = active_backend(st.session_state)
            if backend:
                s = backend.session
                binding = backend.ledger.binding_for_backend('windows', s.target_id, s.registration_epoch, previous['session_id'])
                if binding is None:
                    raise ValueError('Workflow does not belong to this registration epoch')
                backend.check(st.session_state[CONNECTION_KEY], binding.workflow_session_id)
                st.session_state[WORKFLOW_KEY] = binding.workflow_session_id
            st.session_state[SESSION] = previous['session_id']
            _reset_view()
            st.rerun()


def _choose_round(assessments):
    if len(assessments) == 1:
        return assessments[0]
    count = len(assessments)
    labels = {r['round_id']: f"Round {n} · {myt(r['created_at'])}" + (' (latest)' if n == count else '')
              for n, r in enumerate(assessments, 1)}
    chosen = st.selectbox('Round', [r['round_id'] for r in reversed(assessments)], format_func=labels.get,
                          key=ROUND_VIEW, width=320)
    return next(r for r in assessments if r['round_id'] == chosen)


def _action_bar(hardening, session_id, latest, state, rounds, target):
    verification = state['verification']
    stopped = verification and ((verification.get('outcome') or {}).get('outcome') == 'incomplete' or
                                (verification.get('outcome') or {}).get('reason_code') == 'remediation_incomplete')
    # A new round is offered once nothing in the latest one awaits a decision or execution.
    can_run = not state['undecided'] and not state['pending']
    goal = _goal_input() if can_run else None
    with st.container(horizontal=True, vertical_alignment='center'):
        if can_run:
            if st.button('Run next round', type='primary', key='agentic_run', icon=':material/refresh:',
                         help='Rescan the VM, re-rank the findings and propose again'):
                _run_round(hardening, session_id, goal)
            if active_backend(st.session_state) and st.button('Assess without AI', key='agentic_assess_without_ai'):
                _run_round(hardening, session_id, None, AssessmentMode.DETERMINISTIC)
        if state['pending'] and st.session_state.get(CONFIRM) != latest['round_id']:
            if st.button(f"Execute {len(state['pending'])} approved fix(es)…", type='primary',
                         key='agentic_execute_review', icon=':material/play_arrow:'):
                st.session_state[CONFIRM] = latest['round_id']
                st.session_state['agentic_confirm_requests'] = tuple(r['proposal']['request_id'] for r in state['pending'])
                st.rerun()
        if state['pending'] and stopped:
            if st.button('Execute remaining without AI', key='agentic_execute_fallback',
                         help='Same approval, expiry and precondition guards, in rank order; the result is still '
                              'verified by a rescan.'):
                with st.spinner('Executing approved fixes in rank order, then verifying…'):
                    _execute(hardening, session_id, deterministic=True,
                             expected=tuple(r['proposal']['request_id'] for r in state['pending']))
                _reset_view()
                st.rerun()
        if state['undecided']:
            st.markdown(f"{len(state['undecided'])} proposed fix(es) need your decision in **Fixes**.")
        st.download_button('Round report', round_report(hardening, rounds, latest), icon=':material/download:',
                           file_name='cis-round-' + target.hostname + '-' + myt(latest['created_at'], '%Y-%m-%dT%H%M')
                           + '.html', mime='text/html', key='agentic_report',
                           help='Self-contained HTML record of this round. Open it in a browser to print to PDF.')
        if st.button('New session', key='agentic_reset', type='tertiary'):
            del st.session_state[SESSION]
            st.session_state.pop(WORKFLOW_KEY, None)
            _reset_view()
            st.rerun()


def _confirm_execution(hardening, session_id, state, target):
    now = datetime.now(timezone.utc)
    rows = []
    for record in state['pending']:
        p, approval = record['proposal'], record['decision_record']
        expired = datetime.fromisoformat(approval['expires_at']) <= now
        rows.append({'Rank': p['rank'], 'Control': p['control_id'], 'Change': LIBRARY[p['action_id']].title,
                     'Current value': shown(p['expected_before'], 'Non-Compliant'),
                     'Approved by': approval['approved_by'],
                     'Approval valid until': myt(approval['expires_at']) + (' (expired)' if expired else '')})
    with st.container(border=True):
        st.markdown(f'**Confirm: change {len(rows)} setting(s) on {md_escape(target.hostname)}**')
        st.dataframe(rows, hide_index=True)
        st.caption('The Remediation Agent prechecks each value and skips anything that changed since the scan. '
                   'A fresh Scanner rescan verifies the result. Expired approvals are refused. '
                   'Take a VM snapshot first if you want a quick way back.')
        with st.container(horizontal=True):
            if st.button('Confirm and execute', type='primary', key='agentic_execute'):
                st.session_state.pop(CONFIRM, None)
                with st.spinner('Remediation Agent executing, then Scanner verifying. This can take up to 10 minutes.'):
                    _execute(hardening, session_id, expected=st.session_state.pop('agentic_confirm_requests', None))
                _reset_view()
                st.rerun()
            if st.button('Cancel', key='agentic_execute_cancel'):
                st.session_state.pop(CONFIRM, None)
                st.rerun()


def _decision_cell(store, record, operator, comment, editable):
    p = record['proposal']
    if record['verdict']:
        kind = verdict_kind(record['verdict'])
        st.markdown(badge(VERDICT_LABEL[kind], VERDICT_COLOR[kind]))
        if kind != 'verified':
            st.caption(md_escape(record['verdict']))
    elif record['decision'] == 'approved':
        approval = record['decision_record']
        if datetime.fromisoformat(approval['expires_at']) <= datetime.now(timezone.utc):
            st.markdown(badge('Approval expired', 'orange'))
        else:
            st.markdown(badge('Approved', 'blue'))
        st.caption(f"by {md_escape(approval['approved_by'])}, valid until {myt(approval['expires_at'])}")
    elif record['decision'] == 'rejected':
        st.markdown(badge('Rejected'))
        st.caption('by ' + md_escape(record['decision_record']['operator']))
    elif not editable:
        st.markdown(badge('No decision'))
    else:
        with st.container(horizontal=True):
            ready = bool(operator.strip())
            hint = None if ready else 'Enter your name above first'
            if st.button('Approve', key='agentic_approve_' + p['request_id'], disabled=not ready, help=hint):
                _decide(store, p['request_id'], approve=True, operator=operator, comment=comment)
                st.session_state.pop(COMMENT, None)
                st.rerun()
            if st.button('Reject', key='agentic_reject_' + p['request_id'], disabled=not ready, help=hint):
                _decide(store, p['request_id'], approve=False, operator=operator, comment=comment)
                st.session_state.pop(COMMENT, None)
                st.rerun()
    if record['comment']:
        st.caption('Comment: ' + md_escape(record['comment']))


def _show_fixes(store, assessment_round, state, analysis, *, editable):
    outcome = assessment_round['outcome']
    goal = assessment_round.get('goal')
    if goal:
        with st.container(border=True):
            st.markdown(f"**Your goal:** {md_escape(goal['text'])}  \n**Read by the Orchestrator as:** "
                        f"{md_escape(goal['read_as'])}")
            st.caption('Code enforces this reading on the plan. If it is wrong, reject the fixes and run the next '
                       'round with a clearer goal.')
    if assessment_round.get('mode') == 'deterministic':
        st.caption(md_escape(outcome['reason']))
    elif outcome['outcome'] in PLANNED:
        st.caption('Orchestrator summary: ' + md_escape(outcome['reason']))
    if not state['records']:
        st.info('The Orchestrator proposed no fixes in this round.')
    operator = comment = ''
    if editable and state['undecided']:
        with st.container(horizontal=True, vertical_alignment='bottom'):
            operator = st.text_input('Your name (recorded with each decision)', key='agentic_operator',
                                     persist_state='session', width=320)
            ready = bool(operator.strip())
            approve_all = st.button('Approve all undecided', key='agentic_approve_all', disabled=not ready)
            reject_all = st.button('Reject all undecided', key='agentic_reject_all', disabled=not ready)
        comment = st.text_input('Comment (optional, recorded with your next decision)', key=COMMENT, max_chars=500,
                                placeholder='e.g. Approved for the Saturday maintenance window')
        if approve_all or reject_all:
            for record in state['undecided']:
                _decide(store, record['proposal']['request_id'], approve=approve_all, operator=operator, comment=comment)
            st.session_state.pop(COMMENT, None)
            st.rerun()
        st.caption('Each approval is bound to that exact request on this VM and expires after one hour.')
    levels = {f['control_id']: f['level'] for f in (analysis or {}).get('ranked', [])}
    for record in state['records']:
        p = record['proposal']
        action = LIBRARY[p['action_id']]
        with st.container(border=True):
            left, right = st.columns([3, 1.2], vertical_alignment='center')
            level = levels.get(p['control_id'])
            left.markdown(f"**{p['rank']}. {p['control_id']} · {action.title}** "
                          + (level_badge(level) + f" risk {p['risk_score']}" if level else ''))
            left.caption(f"Now {md_escape(shown(p['expected_before'], 'Non-Compliant'))} → {md_escape(repr(p['value']))} · "
                         f"{p['action_id']} · {action.impact}")
            left.caption('Why the Orchestrator chose it: ' + md_escape(p['reason']))
            with right:
                _decision_cell(store, record, operator, comment, editable)
    if outcome.get('skipped'):
        st.markdown('**Not proposed this round**')
        st.dataframe([{'Control': s['control_id'], 'Reason': s['reason']} for s in outcome['skipped']],
                     hide_index=True)


def _finding_detail(finding, round_id):
    f = finding['factors']
    st.markdown(f"**{finding['control_id']} · {finding['title']}** {level_badge(finding['level'])} "
                f"risk {finding['score']}")
    st.caption(f"6×{f['I']} + 5×{f['E']} + 4×{f['P']} + 3×{f['L']} + 2×{f['D']} = {finding['score']}")
    reasons = finding.get('factor_reasons', {})
    st.dataframe([{'Factor': 'I Security impact', 'Value': f['I'], 'Rule': reasons.get('I', '')},
                  {'Factor': 'E Exposure', 'Value': f['E'], 'Rule': finding['exposure_reason']},
                  {'Factor': 'P Privilege impact', 'Value': f['P'], 'Rule': reasons.get('P', '')},
                  {'Factor': 'L Likelihood', 'Value': f['L'], 'Rule': reasons.get('L', '')},
                  {'Factor': 'D Drift', 'Value': f['D'], 'Rule': finding['drift_reason']}], hide_index=True)
    st.caption('Benchmark rationale (paraphrased): ' + md_escape(finding['rationale']))
    key = 'agentic_explain_' + round_id + finding['control_id']
    if st.button('Explain with local AI', key=key + '_btn', icon=':material/chat:'):
        with st.spinner('Asking qwen3:8b…'):
            try:
                st.session_state[key] = explain_finding(finding)
            except Exception as exc:  # Explanation is optional; assessment remains valid.
                st.session_state[key] = 'Explanation unavailable (' + type(exc).__name__ + ').'
    if key in st.session_state:
        st.caption('Model-written explanation (unverified; does not affect the score):')
        st.text(st.session_state[key])


def _show_risk(analysis, round_id, outcome):
    if not analysis:
        st.info('No risk analysis for this round.')
        return
    st.caption('R = 6I + 5E + 4P + 3L + 2D, computed by code (baselines ' + analysis['baseline_version'] + '). '
               'The Analysis Agent can flag findings but cannot change a score.')
    complete = bool(outcome) and outcome['outcome'] == 'analysis_complete'
    if outcome and not complete:
        st.warning(md_escape(outcome['reason']) + ' The ranking below is unaffected.')
    flags = {a['control_id']: a['reason'] for a in outcome['attention']} if complete else {}
    ranked = analysis['ranked']
    if not ranked:
        st.success('No scored non-compliant findings.')
    else:
        st.dataframe([{'Rank': rank, 'Control': f['control_id'], 'Title': f['title'],
                       'Observed': shown(f['observed'], 'Non-Compliant'), 'Required': f['rule'], 'Risk': f['score'],
                       'Level': f['level'], 'Priority band': f['priority'],
                       'Analysis Agent flag': flags.get(f['control_id'], '')} for rank, f in enumerate(ranked, 1)],
                     hide_index=True, column_config={'Rank': st.column_config.NumberColumn(width='small'),
                                                     'Risk': st.column_config.NumberColumn(width='small')})
        by_id = {f['control_id']: f for f in ranked}
        chosen = st.selectbox('Finding details', list(by_id), format_func=lambda c: c + ' · ' + by_id[c]['title'],
                              key='agentic_finding_' + round_id)
        with st.container(border=True):
            _finding_detail(by_id[chosen], round_id)
    if analysis['gaps']:
        st.markdown('**Gaps (not scored, no fix)**')
        triage = {t['control_id']: t['reason'] for t in (outcome or {}).get('gap_triage', [])}
        st.dataframe([{'Control': g['control_id'], 'Status': g['status'], 'Interpretation': g['hint'],
                       'Analysis Agent triage': triage.get(g['control_id'], '—')}
                      for g in analysis['gaps']], hide_index=True)


def _show_assessment(runtime, run_id):
    record = runtime.imports.get(runtime.get(run_id).evidence_sha256)
    rows = [{'Control': r.control.control_id, 'Title': r.control.title, 'Area': r.control.area,
             'Status': r.status.value, 'Observed': shown(r.evidence.value, r.status.value)}
            for r in record.assessment.results]
    counts = {s: sum(r['Status'] == s for r in rows) for s in ('Compliant', 'Non-Compliant', 'Unknown', 'Error')}
    for col, (label, value) in zip(st.columns(4), counts.items()):
        col.metric(label, value, border=True)
    show = st.segmented_control('Show', ('All',) + tuple(counts), default='All', required=True,
                                key='agentic_status_filter', persist_state='session')
    st.dataframe([r for r in rows if show in (None, 'All') or r['Status'] == show], hide_index=True)
    st.caption(f'{len(rows)} controls, CIS Windows Server 2022 Stand-alone v2.0.0 Level 1. '
               'Unknown and Error are never counted as passes.')


def _show_results(hardening, assessment_round, state):
    verification = state['verification']
    if not verification:
        st.info('Nothing has been executed for this round yet.' if state['records']
                else 'Nothing to execute in this round.')
        return
    outcome = verification.get('outcome')
    if outcome:
        show = {'finish': st.success, 'next_round': st.info, 'fallback': st.info}.get(outcome['outcome'], st.warning)
        show(md_escape(outcome['reason']))
    st.markdown('**Verdicts**')
    st.dataframe([{'Control': v['control_id'], 'Action': v['action_id'], 'Verdict': v['verdict']}
                  for v in verification['verdicts']] or [{'Verdict': 'Nothing was executed'}], hide_index=True)
    if verification['framework_run_id']:
        changed = [c for c in hardening.changes(assessment_round['framework_run_id'], verification['framework_run_id'])
                   if c['change'] != 'Unchanged']
        st.markdown('**Configuration changes found by the verification rescan**')
        st.dataframe([{'Control': c['control_id'], 'Title': c['title'], 'Before': repr(c['before']),
                       'After': repr(c['after']), 'Change': c['change']} for c in changed]
                     or [{'Change': 'No changes detected'}], hide_index=True)


def _compact(value, limit=240):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[:limit] + '…'


def _trace_rows(trace):
    rows = []
    for step, event in enumerate(trace['events'], 1):
        data = event['data']
        if event['kind'] == 'tool':
            result = '(see Risk ranking)' if data.get('name') == 'analyse_findings' else _compact(data.get('result'))
            rows.append({'Step': step, 'Event': 'Tool call', 'Tool': data.get('name'),
                         'Arguments': _compact(data.get('arguments')), 'Result or error': result})
        elif event['kind'] == 'tool_rejected':
            rows.append({'Step': step, 'Event': 'Rejected by code', 'Tool': data.get('name'),
                         'Arguments': _compact(data.get('arguments', '')), 'Result or error': data.get('error')})
        elif event['kind'] == 'nudge':
            rows.append({'Step': step, 'Event': 'Reminder', 'Tool': '', 'Arguments': '',
                         'Result or error': 'Asked for exactly one tool call'})
        elif event['kind'] == 'finished':
            rows.append({'Step': step, 'Event': 'Finished', 'Tool': '', 'Arguments': '',
                         'Result or error': data.get('status', '') + ': ' + _compact(data.get('summary', ''))})
    return rows


def _show_agent_log(hardening, phases):
    if all(r.get('mode') == 'deterministic' for _, r in phases):
        st.info('Assessment ran without AI. No agent decisions or proposals were created.')
        return
    for title, agent_round in phases:
        traces = sorted(hardening.traces(agent_round['round_id']), key=lambda t: AGENT_ORDER.get(t['agent_role'], 9))
        if not traces:
            continue
        st.markdown('**' + title + '**')
        summary = []
        for trace in traces:
            finished = next((e['data'] for e in reversed(trace['events']) if e['kind'] == 'finished'), {})
            summary.append({'Agent': trace['agent_role'], 'Status': finished.get('status', 'Interrupted'),
                            'Decision': (finished.get('outcome') or {}).get('outcome', '—'),
                            'Tool calls': finished.get('tool_calls', 0), 'Seconds': finished.get('duration_seconds'),
                            'Engine': trace['provenance']})
        st.dataframe(summary, hide_index=True)
        for trace, row in zip(traces, summary):
            with st.expander(f"{row['Agent']}: {row['Tool calls']} tool calls, {row['Status'].lower()}"):
                st.dataframe(_trace_rows(trace), hide_index=True)
    st.caption('Every tool call was chosen by the agent and checked by code; rejected calls had no effect.')


def render_agentic(database_path: Path):
    st.title('Agentic hardening')
    try:
        target = render_connection(key='agentic')
    except (ValueError, ChannelError) as exc:
        st.error(md_escape(exc))
        target = None
    if target is None:
        st.info('Connect to the VM to start an agentic round.')
        return
    try:
        backend = active_backend(st.session_state)
        if backend:
            connection = st.session_state[CONNECTION_KEY]
            capabilities = backend.capabilities(connection)
            for reason in capabilities.blocked_reasons:
                st.info(md_escape(reason))
            if backend.session.identity.platform == 'ubuntu':
                _ubuntu_pending_changes(backend, connection)
                _ubuntu_acceptance(backend, connection)
                snapshot = backend.snapshot(connection, st.session_state.get(WORKFLOW_KEY))
                _show_progress(dict(zip(STEPS, snapshot.step_states)), None)
                with st.container(horizontal=True):  # round goals are disabled for Ubuntu (due for removal)
                    if st.button('Start agentic round', key='agentic_run', disabled=not capabilities.can_use_model):
                        # Bounded Ubuntu agents through the backend; the orchestrator plans, the administrator approves.
                        _run_round(None, None, None)
                    if st.button('Assess without AI', key='agentic_assess_without_ai', disabled=not capabilities.can_assess):
                        # Read-only deterministic scan through the backend; the helper gate is checked again there.
                        _run_round(None, None, None, AssessmentMode.DETERMINISTIC)
                render_snapshot_tabs(snapshot, fix_actions=lambda: _ubuntu_fix_actions(backend, connection, snapshot,
                                                                                      capabilities),
                                     fix_header=lambda: _ubuntu_fix_header(backend, connection, snapshot),
                                     control_actions=lambda card: _ubuntu_card_actions(backend, connection, snapshot,
                                                                                       capabilities, card))
                return
        runtime, store, hardening = _services(database_path, target)
        session_id = st.session_state.get(SESSION)
        rounds = store.rounds(session_id) if session_id else []
        assessments = [r for r in rounds if r['kind'] == 'assessment']
        scanned = {_round_target(runtime, r) for r in assessments} - {None}
        if scanned and scanned != {_target_id(target)}:
            # A session belongs to one VM: connecting to another one starts afresh instead of mixing records.
            del st.session_state[SESSION]
            _reset_view()
            rounds, assessments = [], []
        if not assessments:
            _show_start(hardening, store, runtime, target)
            return
        latest = assessments[-1]
        viewing = _choose_round(assessments)
        is_latest = viewing['round_id'] == latest['round_id']
        state = _round_state(store, rounds, viewing)
        analysis = round_analysis(hardening, viewing) if viewing['framework_run_id'] else None
        _show_progress(_steps(viewing, state, analysis), state['verification'])
        if viewing['outcome']['outcome'] not in PLANNED:
            st.warning(md_escape(viewing['outcome']['reason']))
        if is_latest:
            _action_bar(hardening, session_id, latest, state, rounds, target)
            if state['pending'] and st.session_state.get(CONFIRM) == latest['round_id']:
                _confirm_execution(hardening, session_id, state, target)
        else:
            st.caption('An earlier round, read-only. Decisions and execution happen in the latest round.')
        if TAB not in st.session_state:
            st.session_state[TAB] = _default_tab(state)
        fixes, risk, controls, results, log = st.tabs(TABS, key=TAB, on_change='rerun')
        with fixes:
            _show_fixes(store, viewing, state, analysis, editable=is_latest)
        with risk:
            _show_risk(analysis, viewing['round_id'], viewing.get('analysis_outcome'))
        with controls:
            if viewing['framework_run_id']:
                if backend:
                    render_controls(backend.snapshot(connection, st.session_state[WORKFLOW_KEY],
                        RecordRef('windows', backend.session.target_id, viewing['round_id'])))
                else:
                    _show_assessment(runtime, viewing['framework_run_id'])
            else:
                st.info('The scan did not complete in this round.')
        with results:
            _show_results(hardening, viewing, state)
        with log:
            _show_agent_log(hardening, [('Assessment phase', viewing)]
                            + ([('Remediation phase', state['verification'])] if state['verification'] else []))
    except ChannelError as exc:
        st.error('VM channel (' + exc.state + '): ' + md_escape(exc.detail))
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Agentic workflow: ' + md_escape(exc))
