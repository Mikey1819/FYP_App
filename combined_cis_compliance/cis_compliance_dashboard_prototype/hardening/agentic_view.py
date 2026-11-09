"""Agentic hardening page: one live VM, AI-coordinated rounds, human approval, verified fixes."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import sqlite3
from uuid import uuid4

import streamlit as st

from . import background
from .action_library import LIBRARY
from .agentic import ANALYSIS, ORCHESTRATOR, REMEDIATION, SCANNER, AgenticHardening, explain_finding, verdict_kind
from .connection_view import job_key, render_connection
from .domain import Status
from .framework import AssessmentRuns
from .import_storage import ImportedEvidenceStore
from .manual_controls import (AUTOMATED, CHOICES, MANUAL_FIX, MAX_REASON, NOT_AUTOMATED, PROGRAM_FIX, WHY, WITHDRAWN,
                              ManualDecisionStore, in_words, setting, steps)
from .remediation import RemediationStore
from .round_report import round_analysis, round_report, shown
from .ui import VERDICT_COLOR, badge, level_badge, md_escape, myt
from .winrm_channel import MAX_CLOCK_OFFSET_SECONDS, ChannelError, LiveScanner
from system.bootstrap import active_backend, CONNECTION_KEY, SERVICE_KEY, WORKFLOW_KEY
from system.contracts import AssessmentMode, RecordRef
from system.ui.components import render_controls, render_snapshot_tabs
from backends.windows.adapter import original_services

# Plain session keys (not widget keys), so they survive switching to another page and back.
SESSION = 'agentic_session'
CONFIRM = 'agentic_confirm'
# Widget keys that are reset on purpose when a new round or remediation result arrives.
TAB = 'agentic_tab'
ROUND_VIEW = 'agentic_round_view'
COMMENT = 'agentic_comment'
JOB_ERROR = 'agentic_job_error'  # Why the last background round or execution stopped, shown once.
# The page waits this long for background work before showing it as running: quick work looks as before.
WAIT_SECONDS = 3
ROUND_LABEL = 'Round: Orchestrator → Scanner → Analysis → plan'
EXECUTE_LABEL = 'Remediation Agent executing the approved fixes, then Scanner verifying'
FALLBACK_LABEL = 'Executing the approved fixes in rank order without AI, then verifying'
UBUNTU_EXECUTE_LABEL = 'Executing the approved fixes, then verifying'
UBUNTU_AGENTS_EXECUTE_LABEL = 'Remediation Agent executing, then Scanner verifying'
CLOCK = 'agentic_clock'                # Windows: the last check of the server clock (plain session key).
CLOCK_NOTICE = 'agentic_clock_notice'  # What the last clock sync did, shown once.
CLOCK_RECHECK = timedelta(minutes=2)   # The box checks again after this; Start and Execute always check afresh.
MANUAL_ASK = 'agentic_manual_exception'  # The not-automated control whose exception reason is being typed.
MANUAL_ERROR = 'agentic_manual_error'

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
    """Read on the page what the execution needs, and return the work itself for the background worker."""
    backend = active_backend(st.session_state)
    if backend:
        workflow = st.session_state[WORKFLOW_KEY]
        connection = st.session_state[CONNECTION_KEY]
        snapshot = backend.snapshot(connection, workflow)
        if expected is None:
            raise ValueError('An exact displayed approval set must be confirmed before dispatch')
        round_ref, operation = snapshot.current_round_reference, uuid4().hex
        return lambda: backend.execute_approved(connection, workflow, round_ref, expected, deterministic, operation)
    return lambda: hardening.execute_approved(session_id, deterministic=deterministic)


# ------------------------------------------------------------------ background work (background.py)
def _start(label, work, after):
    """Run a round or an execution in the background worker, so opening another page cannot stop it half-way."""
    job = background.start(job_key(), label, work, after=after)
    with st.spinner(label + '…'):
        job.wait(WAIT_SECONDS)
    st.rerun()


def _error_text(error):
    if isinstance(error, ChannelError):
        return 'Server channel (' + error.state + '): ' + md_escape(error.detail)
    return 'Agentic workflow: ' + md_escape(error)


def _collect_finished(key):
    """Apply a finished round or execution of this server once: what the page remembers, and why it stopped."""
    job = background.take_finished(key)
    if job is None:
        return
    handled = job.after(job.result, job.error) if job.after else False
    if job.error is not None and not handled:
        st.session_state[JOB_ERROR] = _error_text(job.error)


def _show_running(job):
    with st.container(border=True):
        st.markdown(f':blue-badge[:material/progress_activity: Running] **{md_escape(job.label)}**')
        st.caption(f'Started {myt(job.started_at, "%H:%M:%S")}. It keeps running if you open another page; this page '
                   'shows the result when it has finished. Starting other work and disconnecting wait until then.')
        st.button('Refresh', key='agentic_job_refresh', icon=':material/refresh:')


def _after_round(result, error):
    binding = getattr(result, 'binding', None)  # Through a backend: the round's workflow, kept for this session.
    if binding is not None:
        st.session_state[WORKFLOW_KEY] = binding.workflow_session_id
        st.session_state[SESSION] = binding.backend_session_id
    _reset_view()


def _after_execute(result, error):
    _reset_view()


def _after_ubuntu_execute(result, error):
    if isinstance(error, ValueError):  # Shown in Fixes, as before.
        st.session_state['ubuntu_execute_error'] = str(error)[:300]
        return True
    return False


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
    for key in (TAB, ROUND_VIEW, CONFIRM, 'ubuntu_round_view'):  # A finished round opens on the latest round.
        st.session_state.pop(key, None)


def _run_round(hardening, session_id, mode=AssessmentMode.AGENTIC):
    if hardening is not None and not _clock_still_ok(hardening):  # Windows; Ubuntu scans use this laptop's clock.
        return
    # The session is kept before the round starts, so its records stay reachable whatever happens to the page.
    session_id = session_id or uuid4().hex
    st.session_state[SESSION] = session_id
    backend = active_backend(st.session_state)
    if backend:
        connection, workflow, operation = st.session_state[CONNECTION_KEY], st.session_state.get(WORKFLOW_KEY), uuid4().hex
        work = lambda: backend.start_round(connection, workflow, None, mode, operation)
    else:
        work = lambda: hardening.run_round(session_id)
    _start(ROUND_LABEL, work, _after_round)


def _ubuntu_states(snapshot):
    executed = {r.proposal_reference for r in snapshot.results}
    applied = {r.proposal_reference for r in snapshot.results if r.execution_state in ('applied', 'reconciled_applied')}
    restoring = {p.title.split('(undo ')[0] for p in snapshot.proposals if p.kind == 'recovery'}
    return executed, applied, restoring


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
                  help='Needs applied fixes. The server restarts 60 s after it runs; connect again, then Check status.')
    for p in snapshot.proposals:
        if p.kind not in ('metadata_refresh', 'reboot') or p.decision != 'approved' or p.reference in executed:
            continue
        key = p.reference.record_id
        label = 'package-list refresh' if p.kind == 'metadata_refresh' else 'reboot of the server'
        confirmed = st.checkbox('I confirm running the approved ' + label, key='ubuntu_confirm_maintenance_' + key)

        def run(reference=p.reference, key=key):
            st.session_state['ubuntu_confirm_maintenance_' + key] = False
            try:
                backend.dispatch_auxiliary(connection, workflow, reference, uuid4().hex)
            except (ValueError, OSError) as failure:
                st.session_state['ubuntu_execute_error'] = str(failure)[:300]
        st.button('Run approved ' + label, key='ubuntu_run_maintenance_' + key, on_click=run,
                  disabled=not (capabilities.can_remediate and confirmed))


def _ubuntu_safety_check(operator):
    """Both execution acceptance tests, run by the dashboard: the confirm test (a fresh login confirms it) and the
    rollback test (left unconfirmed until the server's timer restores it). Returns a line for the page."""
    import time
    from .reconnect import fresh_login
    service = st.session_state[SERVICE_KEY]
    with st.status('Safety check: confirm test…', expanded=True) as status:
        backend, connection = active_backend(st.session_state), st.session_state[CONNECTION_KEY]
        st.write('Applying a harmless marker that must be confirmed after a fresh login.')
        run = backend.start_acceptance(connection, 'confirm', operator, uuid4().hex)
        deadline = time.monotonic() + 120
        while run.outcome is None and run.code != 'awaiting_confirmation':
            if time.monotonic() > deadline:
                raise ValueError('The confirm test did not reach its confirmation step within two minutes.')
            time.sleep(2)
            run = next(r for r in backend.acceptance_status(connection) if r.request_id == run.request_id)
        if run.outcome is None:
            st.write('Logging in again over a new SSH connection, which proves the change kept SSH working.')
            connection = fresh_login(st.session_state)
            backend = service.backend_for(connection)
            run = backend.confirm_acceptance(connection, run.request_id)
        if run.outcome != 'confirmed':
            raise ValueError('The confirm test ended ' + str(run.outcome or run.code) + '; it did not pass.')
        status.update(label='Safety check: rollback test…')
        st.write('Confirm test passed. Applying a marker that is left unconfirmed, so the server must restore it.')
        run = backend.start_acceptance(connection, 'rollback', operator, uuid4().hex)
        deadline = time.monotonic() + 300
        while run.outcome is None:
            if time.monotonic() > deadline:
                raise ValueError('The server did not restore the rollback test marker within five minutes.')
            time.sleep(5)
            run = next(r for r in backend.acceptance_status(connection) if r.request_id == run.request_id)
        if run.outcome != 'rolled_back':
            raise ValueError('The rollback test ended ' + str(run.outcome) + '; it did not pass.')
        status.update(label='Safety check passed', state='complete')
    return 'Safety check passed: the confirm test was confirmed after a fresh login and the rollback test was restored by the server.'


def _ubuntu_acceptance(backend, connection):
    """Execution acceptance: two live runs of a harmless marker prove the confirm and rollback paths on this VM.
    Shown only while needed; once both passed for the deployed runner it is gone (administrator request 2026-11-09),
    and a reinstalled runner (a new digest) makes it needed, and shown, again. With the login remembered, one button
    runs both tests."""
    from .reconnect import can_reconnect
    error, notice = (st.session_state.pop('ubuntu_acceptance_error', None),
                     st.session_state.pop('ubuntu_acceptance_notice', None))
    if not error and backend.acceptance_complete(connection):
        if notice:
            st.success(md_escape(notice))  # the result shows once, right after the check passed
        return
    with st.expander('Safety check (execution acceptance): required before any live fix', expanded=True):
        if error:
            st.error(md_escape(error))
        if notice:
            st.success(md_escape(notice))
        deployment = backend.deployment_status(connection)
        if not deployment.ok:
            for reason in deployment.reasons:
                st.warning(md_escape(reason))
            return
        st.caption('Two tests with a harmless marker file in the runner state directory on the server; no system '
                   'setting changes. The confirm test must be kept after a fresh login, the rollback test must be '
                   'restored by the server itself.')
        runs = backend.acceptance_status(connection)
        operator = st.text_input('Your name (recorded with the acceptance approval)', key='ubuntu_acceptance_operator',
                                 value=st.session_state.get('agentic_operator') or '')
        open_run = any(run.outcome is None for run in runs)
        if can_reconnect(st.session_state):
            if st.button('Run safety check', key='ubuntu_safety_check', type='primary', icon=':material/verified_user:',
                         disabled=open_run or not operator.strip(),
                         help='Runs both tests by itself in about two to three minutes, including the fresh login.'):
                try:
                    st.session_state['ubuntu_acceptance_notice'] = _ubuntu_safety_check(operator.strip())
                except (ValueError, OSError) as failure:
                    st.session_state['ubuntu_acceptance_error'] = str(failure)[:300]
                st.rerun()
        for run in runs:
            label = md_escape(run.scenario + ' scenario (' + run.request_id[:8] + '): ' + (run.outcome or run.code))
            if run.outcome is not None:
                st.markdown('- ' + label)
                continue
            if run.scenario == 'confirm' and run.code == 'awaiting_confirmation':
                st.warning(label + '. Disconnect, connect to the server again, then confirm within about a minute.')
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

        def start(scenario):
            try:
                backend.start_acceptance(connection, scenario, operator, uuid4().hex)
                st.session_state['ubuntu_acceptance_notice'] = scenario + ' scenario started.'
            except (ValueError, OSError) as failure:
                st.session_state['ubuntu_acceptance_error'] = str(failure)[:300]
        st.caption('Or run each test by hand:')
        with st.container(horizontal=True):
            for scenario, label in (('confirm', 'Run confirm scenario'), ('rollback', 'Run rollback scenario')):
                st.button(label, key='ubuntu_acceptance_' + scenario, on_click=start, args=(scenario,),
                          disabled=open_run or not operator.strip())


AUTO_FAILED = 'ubuntu_autoconfirm_failed'


@st.fragment(run_every=5)
def _ubuntu_watch_changes():
    """While a change runs or waits for confirmation, check it every five seconds; confirm a waiting one over a fresh
    login made by the dashboard. The whole page redraws once something settles."""
    from .reconnect import can_reconnect, fresh_login
    backend, connection = active_backend(st.session_state), st.session_state.get(CONNECTION_KEY)
    if backend is None or connection is None:
        return
    items = backend.pending_supervised(connection)
    if not items:
        st.rerun(scope='app')
    failed = st.session_state.setdefault(AUTO_FAILED, set())
    for item in items:
        label = md_escape(item.control_id + ' · ' + item.title)
        if item.code == 'awaiting_confirmation' and can_reconnect(st.session_state) and item.request_id not in failed:
            st.info(f'**{label}** was applied. Confirming it over a fresh SSH login…')
            try:
                new = fresh_login(st.session_state)
                handle = st.session_state[SERVICE_KEY].backend_for(new).confirm_change(
                    new, item.workflow_session_id, item.round_reference, item.request_id, uuid4().hex)
                st.session_state[WORKFLOW_KEY] = item.workflow_session_id
                st.session_state['ubuntu_pending_notice'] = (item.control_id + ': confirmed after a fresh login, '
                                                             + handle.state.replace('_', ' ') + '.')
            except (ValueError, OSError) as failure:
                failed.add(item.request_id)
                st.session_state['ubuntu_pending_error'] = (item.control_id + ': not confirmed automatically. '
                                                            + str(failure)[:300])
            st.rerun(scope='app')
        elif item.code == 'awaiting_confirmation':
            st.warning(f'**{label}** was applied and is waiting for confirmation. Disconnect, reconnect to the server '
                       '(a fresh login proves SSH still works), then confirm before the rollback timer restores it.')
        elif item.outcome == 'running':
            st.info(f'**{label}** is running on the server. This page checks it every few seconds.')
            try:
                handle = backend.refresh_execution(connection, item.workflow_session_id, item.round_reference,
                                                   uuid4().hex)
            except (ValueError, OSError):
                continue
            if handle.state != 'running':
                st.session_state[WORKFLOW_KEY] = item.workflow_session_id
                st.rerun(scope='app')
        else:
            st.warning(f'**{label}**: outcome unknown ({md_escape(item.code)}). Check its status before any other change.')


def _ubuntu_pending_changes(backend, connection):
    """Changes still running or waiting for confirmation on this VM, from any workflow, so a fresh login finds them.
    They are watched automatically; the buttons stay for checking or confirming by hand."""
    error, notice = st.session_state.pop('ubuntu_pending_error', None), st.session_state.pop('ubuntu_pending_notice', None)
    if error:
        st.error(md_escape(error))
    if notice:
        st.success(md_escape(notice))
    items = backend.pending_supervised(connection)
    if not items:
        return
    _ubuntu_watch_changes()
    for item in items:
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
        with st.container(horizontal=True):
            st.button('Check status of ' + item.control_id, key='ubuntu_status_' + item.request_id, on_click=act)
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
        confirmed = st.checkbox('I confirm restoring the recorded before-state of ' + p.control_id + ' on the server',
                                key='ubuntu_confirm_restore_' + key)

        def run(reference=p.reference, key=key):
            st.session_state['ubuntu_confirm_restore_' + key] = False
            try:
                backend.dispatch_auxiliary(connection, workflow, reference, uuid4().hex)
            except ValueError as failure:
                st.session_state['ubuntu_execute_error'] = str(failure)[:300]
        st.button('Run approved restore of ' + p.control_id, key='ubuntu_run_restore_' + key, on_click=run,
                  disabled=not (capabilities.can_remediate and confirmed))


# ------------------------------------------------------------------ Windows: the server clock
def _measure_clock(hardening, key):
    backend = active_backend(st.session_state)
    try:
        reading = (backend.clock_offset(st.session_state[CONNECTION_KEY]) if backend
                   else hardening.scanner.clock_offset())
    except ChannelError as exc:
        reading = dict(error=f'{exc.state}: {exc.detail}')
    except ValueError as exc:
        reading = dict(error=str(exc))
    reading.update(key=key, checked_at=datetime.now(timezone.utc))
    st.session_state[CLOCK] = reading
    return reading


def _clock(hardening, *, fresh=False):
    key = job_key()
    reading = st.session_state.get(CLOCK)
    if (fresh or reading is None or reading['key'] != key
            or datetime.now(timezone.utc) - reading['checked_at'] > CLOCK_RECHECK):
        reading = _measure_clock(hardening, key)
    return reading


def _clock_ok(reading):
    return 'offset' in reading and abs(reading['offset']) <= MAX_CLOCK_OFFSET_SECONDS


def _clock_still_ok(hardening):
    """Checked again at the moment Start or Execute is clicked; when the clocks differ, the page shows why instead."""
    if _clock_ok(_clock(hardening, fresh=True)):
        return True
    st.rerun()


def _apart(seconds):
    seconds = round(abs(seconds))
    return f'{seconds // 60} min {seconds % 60} s' if seconds >= 60 else f'{seconds} s'


def _sync_clock(hardening):
    backend = active_backend(st.session_state)
    try:
        if backend:
            result = backend.sync_clock(st.session_state[CONNECTION_KEY], st.session_state.get(WORKFLOW_KEY),
                                        uuid4().hex)
        else:
            result = hardening.scanner.set_clock()
        st.session_state[CLOCK_NOTICE] = ('success', f"Server clock set from {myt(result['before'], '%H:%M:%S')} to "
                                                     f"{myt(result['after'], '%H:%M:%S')}, this laptop's time.")
    except ChannelError as exc:
        st.session_state[CLOCK_NOTICE] = ('error', f'Clock not set ({exc.state}): {exc.detail}')
    except ValueError as exc:
        st.session_state[CLOCK_NOTICE] = ('error', 'Clock not set: ' + str(exc))
    st.session_state.pop(CLOCK, None)  # Measured again on the next run.
    st.rerun()


def _clock_gate(hardening):
    """Windows: the reminder to check the server clock, the check itself, and the one-click fix. True when the clocks
    match, so a round or an execution may start. Scans and fix evidence carry the server's time; evidence more than
    5 minutes off this laptop's clock is refused, which would stop the round half-way."""
    reading = _clock(hardening)
    ok = _clock_ok(reading)
    notice = st.session_state.pop(CLOCK_NOTICE, None)
    with st.container(border=True):
        if notice:
            (st.success if notice[0] == 'success' else st.error)(md_escape(notice[1]))
        if 'error' in reading:
            st.markdown(':orange-badge[:material/schedule: Clock not checked] Could not read the server clock: '
                        + md_escape(reading['error']))
        else:
            times = (f"server {myt(reading['server'], '%H:%M:%S')} · this laptop "
                     f"{myt(reading['laptop'], '%H:%M:%S')}")
            if ok:
                st.markdown(f':green-badge[:material/schedule: Clocks match] {times} '
                            f"({_apart(reading['offset'])} apart).")
            else:
                st.markdown(f":orange-badge[:material/schedule: Clocks differ] {times}: the server is "
                            f"{_apart(reading['offset'])} {'ahead of' if reading['offset'] > 0 else 'behind'} "
                            'this laptop. Sync the server clock before you continue.')
        st.caption(f"Before you continue, check that the clocks match. Scans and fixes carry the server's time, so a "
                   f'wrong server clock stops the round. Starting and executing wait until the clocks are within '
                   f"{MAX_CLOCK_OFFSET_SECONDS} s. Checked at {myt(reading['checked_at'], '%H:%M:%S')}.")
        with st.container(horizontal=True):
            if 'offset' in reading and not ok and st.button(
                    'Sync server clock to this laptop', type='primary', key='agentic_clock_sync', icon=':material/sync:',
                    help="Sets the server's clock to this laptop's time. Changes nothing else; recorded in the ledger."):
                _sync_clock(hardening)
            if st.button('Check again', key='agentic_clock_check', icon=':material/refresh:'):
                _measure_clock(hardening, job_key())
                st.rerun()
    return ok


def _show_start(hardening, store, runtime, target):
    st.markdown('No round in this session yet. A round scans the server, ranks the findings and proposes fixes. '
                'Nothing changes on the server until you approve and execute.')
    previous = _previous_session(store, runtime, target)
    if previous:
        state = _round_state(store, store.rounds(previous['session_id']), previous)
        open_items = len(state['undecided']) + len(state['pending'])
        st.caption(f"Earlier session on {md_escape(target.hostname)}: last round {myt(previous['created_at'])}"
                   + (f', {open_items} fix(es) still open.' if open_items else '.'))
    ok = _clock_gate(hardening)
    with st.container(horizontal=True):
        if st.button('Start agentic round', type='primary', key='agentic_run', disabled=not ok):
            _run_round(hardening, None)
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


def _action_bar(hardening, session_id, latest, state, rounds, target, manual_open=(), manual=None):
    verification = state['verification']
    stopped = verification and ((verification.get('outcome') or {}).get('outcome') == 'incomplete' or
                                (verification.get('outcome') or {}).get('reason_code') == 'remediation_incomplete')
    # A new round is offered once nothing in the latest one awaits a decision or execution.
    can_run = not state['undecided'] and not state['pending']
    ok = _clock_gate(hardening) if can_run or state['pending'] else True
    with st.container(horizontal=True, vertical_alignment='center'):
        if can_run:
            if st.button('Run next round', type='primary', key='agentic_run', icon=':material/refresh:', disabled=not ok,
                         help='Rescan the server, re-rank the findings and propose again'):
                _run_round(hardening, session_id)
        if state['pending'] and st.session_state.get(CONFIRM) != latest['round_id']:
            if st.button(f"Execute {len(state['pending'])} approved fix(es)…", type='primary', disabled=not ok,
                         key='agentic_execute_review', icon=':material/play_arrow:'):
                st.session_state[CONFIRM] = latest['round_id']
                st.session_state['agentic_confirm_requests'] = tuple(r['proposal']['request_id'] for r in state['pending'])
                st.rerun()
        if state['pending'] and stopped:
            if st.button('Execute remaining without AI', key='agentic_execute_fallback', disabled=not ok,
                         help='Same approval, expiry and precondition guards, in rank order; the result is still '
                              'verified by a rescan.') and _clock_still_ok(hardening):
                _start(FALLBACK_LABEL, _execute(hardening, session_id, deterministic=True,
                                                expected=tuple(r['proposal']['request_id'] for r in state['pending'])),
                       _after_execute)
        if state['undecided']:
            st.markdown(f"{len(state['undecided'])} proposed fix(es) need your decision in **Fixes**.")
        if manual_open:
            st.markdown(f"{len(manual_open)} control(s) this program does not fix need your choice in **Fixes**.")
        st.download_button('Round report', round_report(hardening, rounds, latest, manual=manual),
                           icon=':material/download:',
                           file_name='cis-round-' + target.hostname + '-' + myt(latest['created_at'], '%Y-%m-%dT%H%M')
                           + '.html', mime='text/html', key='agentic_report',
                           help='Self-contained HTML record of this round. Open it in a browser to print to PDF.')
        if st.button('New session', key='agentic_reset', type='tertiary'):
            del st.session_state[SESSION]
            st.session_state.pop(WORKFLOW_KEY, None)
            _reset_view()
            st.rerun()
    return ok


def _confirm_execution(hardening, session_id, state, target, clock_ok=True):
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
                   'A fresh Scanner rescan verifies the result. Expired approvals are refused.')
        with st.container(horizontal=True):
            if st.button('Confirm and execute', type='primary', key='agentic_execute', disabled=not clock_ok) \
                    and _clock_still_ok(hardening):
                st.session_state.pop(CONFIRM, None)
                _start(EXECUTE_LABEL, _execute(hardening, session_id,
                                               expected=st.session_state.pop('agentic_confirm_requests', None)),
                       _after_execute)
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
    if assessment_round.get('mode') == 'deterministic':
        st.caption(md_escape(outcome['reason']))
    elif outcome['outcome'] in PLANNED:
        st.caption('Orchestrator summary: ' + md_escape(outcome['reason']))
    if not state['records']:
        st.info('The Orchestrator proposed no fixes in this round.')
    operator = comment = ''
    asked = editable and bool(state['undecided'])
    if asked:
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
        st.caption('Each approval is bound to that exact request on this server and expires after one hour.')
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
    return operator if asked else None


# ------------------------------------------------------------------ Windows: controls this program does not fix
def _manual_store(database_path):
    return ManualDecisionStore(Path(database_path).with_name('manual_decisions.sqlite3'))


def _manual_results(runtime, assessment_round):
    """(server, {control_id: result}) for the not-automated controls this round scanned; (None, {}) without a scan."""
    target_id = _round_target(runtime, assessment_round)
    if target_id is None:
        return None, {}
    record = runtime.imports.get(runtime.get(assessment_round['framework_run_id']).evidence_sha256)
    return target_id, {r.control.control_id: r for r in record.assessment.results
                       if r.control.control_id in NOT_AUTOMATED}


def _manual_open(runtime, decisions, assessment_round):
    """Not-automated controls that are not compliant and have no choice recorded yet."""
    target_id, results = _manual_results(runtime, assessment_round)
    chosen = decisions.latest(target_id) if target_id else {}
    return [c for c, r in results.items() if r.status != Status.COMPLIANT and c not in chosen]


def _manual_cell(decisions, target_id, control, decision, operator, round_id):
    def record(choice, reason=''):
        try:
            decisions.record(target_id, control, choice, operator=operator, reason=reason, round_id=round_id)
        except ValueError as exc:
            st.session_state[MANUAL_ERROR] = str(exc)
        st.session_state.pop(MANUAL_ASK, None)
        st.rerun()

    if decision is not None:
        if st.button('Change choice', key=f'agentic_manual_withdraw_{control}', disabled=not operator, width='stretch',
                     help='Withdraws this choice (recorded too); the control waits for a new one.'):
            record(WITHDRAWN)
        return
    if st.session_state.get(MANUAL_ASK) == control:
        reason = st.text_input('Why accept it?', key=f'agentic_manual_reason_{control}', max_chars=MAX_REASON,
                               placeholder='e.g. Firewall is managed by the network team')
        with st.container(horizontal=True):
            if st.button('Accept', key=f'agentic_manual_accept_{control}', type='primary',
                         disabled=not (operator and reason.strip())):
                record('exception', reason)
            if st.button('Cancel', key=f'agentic_manual_cancel_{control}'):
                st.session_state.pop(MANUAL_ASK, None)
                st.rerun()
        return
    if st.button('I will fix it by hand', key=f'agentic_manual_fix_{control}', type='primary', disabled=not operator,
                 width='stretch', help='Records your choice. The steps are under "How to fix it on the server".'):
        record('manual_fix')
    if st.button('Accept as exception', key=f'agentic_manual_exception_{control}', disabled=not operator,
                 width='stretch', help='Records that it stays as it is, with your reason.'):
        st.session_state[MANUAL_ASK] = control
        st.rerun()
    if not operator:
        st.caption('Type your name first.')


def _show_not_automated(runtime, decisions, assessment_round, analysis, operator, *, editable):
    """The controls this program assesses but never changes: why, how to fix each by hand, and the administrator's
    choice for each (fix it by hand, or accept it as an exception)."""
    target_id, results = _manual_results(runtime, assessment_round)
    if not results:
        return
    chosen = decisions.latest(target_id)
    scores = {f['control_id']: f for f in (analysis or {}).get('ranked', [])}
    st.markdown('**Not fixed by this program**')
    st.caption(md_escape(WHY))
    error = st.session_state.pop(MANUAL_ERROR, None)
    if error:
        st.error(md_escape(error))
    pending = editable and any(r.status != Status.COMPLIANT for r in results.values())
    if pending and operator is None:  # The proposals above did not ask for the name.
        operator = st.text_input('Your name (recorded with each decision)', key='agentic_operator',
                                 persist_state='session', width=320)
    operator = (operator or '').strip()
    for control, result in results.items():
        decision, finding = chosen.get(control), scores.get(control)
        compliant = result.status == Status.COMPLIANT
        with st.container(border=True):
            left, right = st.columns([3, 1.2], vertical_alignment='center')
            badge = (':green-badge[Compliant now]' if compliant else
                     level_badge(finding['level']) + f" risk {finding['score']}" if finding else
                     f':orange-badge[{result.status.value}]')
            left.markdown(f'**{control} · {md_escape(result.control.title)}** {badge}')
            now = in_words(control, result.evidence.value) or shown(result.evidence.value, result.status.value)
            left.caption(f'Now {md_escape(now)} · needs ' + md_escape(setting(control)))
            if decision:
                left.caption(f"{CHOICES[decision['choice']]} · {md_escape(decision['operator'])}, "
                             f"{myt(decision['decided_at'])}" + (f": {md_escape(decision['reason'])}"
                                                                  if decision['reason'] else ''))
            elif not compliant:
                left.caption(':orange[Needs your choice: fix it by hand, or accept it as an exception.]')
            with left.expander('How to fix it on the server'):
                st.markdown('\n'.join(f'{n}. {md_escape(text)}' for n, text in enumerate(steps(control), 1)))
            with right:
                if editable and not compliant:
                    _manual_cell(decisions, target_id, control, decision, operator, assessment_round['round_id'])


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
             'Status': r.status.value, 'Observed': shown(r.evidence.value, r.status.value),
             'Fix': PROGRAM_FIX if r.control.control_id in AUTOMATED else MANUAL_FIX}
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
        return  # render_connection already points to the Servers page.
    try:
        key = job_key()
        _collect_finished(key)
        error = st.session_state.pop(JOB_ERROR, None)
        if error:
            st.error(error)
        job = background.running(key)
        if job is not None:  # Nothing else to choose until it has finished: the page shows it running.
            _show_running(job)
            return
        backend = active_backend(st.session_state)
        if backend:
            connection = st.session_state[CONNECTION_KEY]
            capabilities = backend.capabilities(connection)
            for reason in capabilities.blocked_reasons:
                st.info(md_escape(reason))
            if backend.session.identity.platform == 'ubuntu':
                _ubuntu_pending_changes(backend, connection)
                _ubuntu_acceptance(backend, connection)
                workflow = st.session_state.get(WORKFLOW_KEY)
                snapshot = backend.snapshot(connection, workflow)
                previous = None if workflow else backend.previous_workflow(connection)
                if previous:  # After a reconnect, as on Windows: the last session on this server can be resumed.
                    earlier, at, open_count = previous
                    st.caption(f'Earlier session on {md_escape(backend.session.identity.hostname)}: last round {myt(at)}'
                               + (f', {open_count} fix(es) still open.' if open_count else '.'))
                # As on Windows: a round picker once the session has more than one round; earlier rounds are read-only.
                rounds = backend.assessment_rounds(connection, workflow) if workflow else ()
                chosen = _ubuntu_choose_round(rounds)
                viewed = snapshot if chosen is None else backend.snapshot(connection, workflow, chosen)
                _show_progress(dict(zip(STEPS, viewed.step_states)), None)
                tabs = dict(fixes_panel=lambda: _ubuntu_show_fixes(backend, connection, viewed, capabilities,
                                                                   editable=chosen is None),
                            risk_panel=lambda: _ubuntu_show_risk(backend, connection, workflow, viewed),
                            results_panel=lambda: _ubuntu_show_results(backend, connection, workflow, viewed,
                                                                       chosen is None))
                if chosen is not None:
                    st.caption('An earlier round, read-only. Decisions and execution happen in the latest round.')
                    render_snapshot_tabs(viewed, **tabs)
                    return
                undecided, pending = _ubuntu_open_fixes(snapshot)
                with st.container(horizontal=True, vertical_alignment='center'):
                    # As on Windows, a new round is offered once nothing in this one awaits a decision or execution,
                    # so approvals are never left behind in an older round.
                    held = undecided or pending or (previous and previous[2])  # previous[2]: its open fixes
                    if previous and previous[2]:
                        st.markdown('Resume the earlier session to decide or execute its open fixes first.')
                    if not held and st.button(
                            'Start agentic round' if snapshot.current_round_reference is None else 'Run next round',
                            key='agentic_run', type='primary', disabled=not capabilities.can_use_model,
                            help='Scan the server, rank the findings and propose fixes. Nothing changes until you '
                                 'approve and execute.'):
                        # Bounded Ubuntu agents through the backend; the orchestrator plans, the administrator approves.
                        _run_round(None, None)
                    if previous and st.button('Resume earlier session', key='agentic_resume'):
                        st.session_state[WORKFLOW_KEY] = earlier
                        st.session_state.pop(UBUNTU_CONFIRM, None)
                        st.session_state.pop(UBUNTU_ROUND_VIEW, None)
                        st.rerun()
                    st.button('Refresh status', key='ubuntu_refresh', icon=':material/refresh:',
                              help='Reload this page from the stored records; the server connection stays open.')
                    if undecided:
                        st.markdown(f'{len(undecided)} proposed fix(es) need your decision in **Fixes**.')
                    if workflow:
                        _ubuntu_report_button(backend, connection, workflow, snapshot, rounds)
                    if workflow and st.button('New session', key='agentic_reset', type='tertiary',
                                              help='Leave this session; its records stay and it can be resumed.'):
                        st.session_state.pop(WORKFLOW_KEY, None)
                        st.session_state.pop(UBUNTU_CONFIRM, None)
                        st.session_state.pop(UBUNTU_ROUND_VIEW, None)
                        st.rerun()
                _ubuntu_execute_bar(backend, connection, snapshot, capabilities)
                render_snapshot_tabs(snapshot, **tabs)
                return
        runtime, store, hardening = _services(database_path, target)
        decisions = _manual_store(database_path)
        session_id = st.session_state.get(SESSION)
        rounds = store.rounds(session_id) if session_id else []
        assessments = [r for r in rounds if r['kind'] == 'assessment']
        scanned = {_round_target(runtime, r) for r in assessments} - {None}
        if scanned and scanned != {_target_id(target)}:
            # A session belongs to one server: connecting to another one starts afresh instead of mixing records.
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
            manual_target = _round_target(runtime, latest)
            clock_ok = _action_bar(hardening, session_id, latest, state, rounds, target,
                                   _manual_open(runtime, decisions, latest),
                                   decisions.latest(manual_target) if manual_target else {})
            if state['pending'] and st.session_state.get(CONFIRM) == latest['round_id']:
                _confirm_execution(hardening, session_id, state, target, clock_ok)
        else:
            st.caption('An earlier round, read-only. Decisions and execution happen in the latest round.')
        if TAB not in st.session_state:
            st.session_state[TAB] = _default_tab(state)
        fixes, risk, controls, results, log = st.tabs(TABS, key=TAB, on_change='rerun')
        with fixes:
            operator = _show_fixes(store, viewing, state, analysis, editable=is_latest)
            _show_not_automated(runtime, decisions, viewing, analysis, operator, editable=is_latest)
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
        st.error('Server channel (' + exc.state + '): ' + md_escape(exc.detail))
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Agentic workflow: ' + md_escape(exc))


# ------------------------------------------------------------------ Ubuntu: the same Fixes layout as Windows
# The Fixes tab and the execution confirmation follow the Windows page above (_show_fixes, _decision_cell,
# _confirm_execution) element for element. What only Ubuntu has (verification scan, restore, maintenance) sits in its
# own boxes. Every decision and execution still goes through the backend's typed commands.
UBUNTU_DONE = {'Fixed, re-scan: Compliant': ('Verified compliant', 'green'), 'Running': ('Running', 'blue'),
               'Applied, re-scan pending': ('Applied, re-scan pending', 'blue'), 'Not applied': ('Refused', 'gray'),
               'Outcome unknown': ('Outcome uncertain', 'orange'), 'Restored to the before-state': ('Restored', 'gray'),
               'Skipped by the Remediation Agent': ('Skipped', 'gray')}
UBUNTU_CONFIRM = 'ubuntu_confirm_execution'


def _ubuntu_open_fixes(snapshot):
    """Fixes of the shown round still awaiting a decision, and approved ones not yet executed whose approval is still
    valid (an expired approval can never run, so it does not hold the next round back)."""
    executed = {r.proposal_reference for r in snapshot.results}
    now = datetime.now(timezone.utc)
    fixes = [p for p in snapshot.proposals if p.kind == 'control_remediation' and p.reference not in executed]
    undecided = [p for p in fixes if p.decision is None and p.eligible_commands]
    pending = [p for p in fixes if p.decision == 'approved' and p.approved_request_id
               and not (p.expiry and datetime.fromisoformat(p.expiry) <= now)]
    return undecided, pending


def _ubuntu_now_line(p):
    """The Windows row's "Now X → Y" line: the preview's readable lines, then the action and its version."""
    lines = [line.strip() for line in p.exact_preview.splitlines() if line.strip()]
    return ' · '.join(lines[:3] + [p.action_id + ' ' + p.version])


def _ubuntu_decide(backend, connection, p, approve, operator, comment):
    try:
        backend.decide(connection, st.session_state.get(WORKFLOW_KEY), p.reference, approve, operator, comment,
                       uuid4().hex)
    except ValueError as failure:
        st.session_state['ubuntu_decision_error'] = (p.control_id or p.title) + ': ' + str(failure)[:300]


def _ubuntu_decision_cell(backend, connection, card, p, operator, comment):
    state = card['state']
    if state in UBUNTU_DONE or state.startswith('Applied, re-scan: '):
        label, color = UBUNTU_DONE.get(state, ('Failed', 'red'))
        st.markdown(badge(label, color))
        result = card['results'].get(p.reference.record_id)
        if result is not None and label != 'Verified compliant':
            st.caption(md_escape(result.detail))
    elif p.decision == 'approved':
        expired = p.expiry and datetime.fromisoformat(p.expiry) <= datetime.now(timezone.utc)
        st.markdown(badge('Approval expired', 'orange') if expired else badge('Approved', 'blue'))
        st.caption((f'by {md_escape(p.approved_by)}, ' if p.approved_by else '')
                   + (f'valid until {myt(p.expiry)}' if p.expiry else ''))
    elif p.decision == 'rejected':
        st.markdown(badge('Rejected'))
        if p.rejected_by:
            st.caption('by ' + md_escape(p.rejected_by))
    elif not p.eligible_commands:
        st.markdown(badge('No decision'))
    else:
        if 'approve' not in p.eligible_commands:  # It shares a file with an approved fix that has not run yet.
            st.caption(md_escape(p.reason))
        with st.container(horizontal=True):
            ready = bool(operator.strip())
            hint = None if ready else 'Enter your name above first'
            if st.button('Approve', key='ubuntu_approve_' + p.reference.record_id, help=hint,
                         disabled=not ready or 'approve' not in p.eligible_commands):
                _ubuntu_decide(backend, connection, p, True, operator, comment)
                st.session_state.pop('agentic_comment', None)
                st.rerun()
            if st.button('Reject', key='ubuntu_reject_' + p.reference.record_id, disabled=not ready, help=hint):
                _ubuntu_decide(backend, connection, p, False, operator, comment)
                st.session_state.pop('agentic_comment', None)
                st.rerun()
    for author, text in p.comments:
        st.caption('Comment: ' + md_escape(text) + ' (' + md_escape(author) + ')')


def _ubuntu_verification_box(backend, connection, snapshot):
    """Ubuntu only: applied changes that still need their read-only verification scan."""
    workflow = st.session_state.get(WORKFLOW_KEY)
    unverified = backend.unverified_applied(connection, workflow) if workflow else ()
    if not unverified:
        return

    def verify():
        try:
            handle = backend.verify_applied(connection, workflow, snapshot.current_round_reference, uuid4().hex)
            st.session_state['ubuntu_verify_notice'] = 'Verification scan: ' + handle.state.replace('_', ' ') + '.'
        except (ValueError, OSError) as failure:
            st.session_state['ubuntu_verify_error'] = str(failure)[:300]
    with st.container(border=True):
        st.markdown('%d applied change%s still need%s the verification scan, so the result cannot show yet.'
                    % (len(unverified), '' if len(unverified) == 1 else 's', 's' if len(unverified) == 1 else ''))
        st.button('Run verification scan', key='ubuntu_verify_applied', icon=':material/fact_check:', type='primary',
                  on_click=verify, help='Read-only re-scan for applied changes that have none yet; never re-runs a fix.')


def _ubuntu_review_line(review):
    """The Orchestrator's next-step decision after the remediation phase, or (`fallback`) that the remaining fixes
    then ran without AI, as the Windows page shows its outcome."""
    text = md_escape(review['reason']) if review['next_step'] == 'fallback' \
        else 'Orchestrator review: ' + md_escape(review['reason'])
    (st.success if review['next_step'] == 'finish' else st.info)(text)


def _ubuntu_show_fixes(backend, connection, snapshot, capabilities, editable=True):
    """As the Windows Fixes tab. An earlier round (`editable` false) is read-only: no verification, restore or
    maintenance actions, and its proposals carry no decision commands."""
    from system.ui.components import NO_PLAN, plan_cards, plan_summary
    for key, show in (('ubuntu_decision_error', st.error), ('ubuntu_verify_error', st.error),
                      ('ubuntu_execute_error', st.error), ('ubuntu_verify_notice', st.success)):
        message = st.session_state.pop(key, None)
        if message:
            show(md_escape(message))
    if editable:
        _ubuntu_verification_box(backend, connection, snapshot)
    workflow = st.session_state.get(WORKFLOW_KEY)
    review = backend.remediation_review(connection, workflow) \
        if editable and workflow and hasattr(backend, 'remediation_review') else None
    if review:  # The Orchestrator's next-step decision after the Remediation Agent ran (code-written sentence).
        _ubuntu_review_line(review)
    executed, applied, restoring = _ubuntu_states(snapshot)
    cards = plan_cards(snapshot)
    fixes = [c for c in cards if any(p.kind == 'control_remediation' for p in c['proposals'])]
    if snapshot.plan:
        st.caption('Orchestrator summary: ' + md_escape(plan_summary(snapshot)) + '.')
    if not fixes:
        st.info('The Orchestrator proposed no fixes in this round.')
    undecided = [p for c in fixes for p in c['proposals'] if p.kind == 'control_remediation' and p.eligible_commands]
    operator = comment = ''
    if any(p.eligible_commands for p in snapshot.proposals):  # A fix, a restore or a maintenance step awaits you.
        with st.container(horizontal=True, vertical_alignment='bottom'):
            operator = st.text_input('Your name (recorded with each decision)', key='agentic_operator',
                                     persist_state='session', width=320)
            ready = bool(operator.strip())
            approve_all = st.button('Approve all undecided', key='ubuntu_approve_all', disabled=not (ready and undecided))
            reject_all = st.button('Reject all undecided', key='ubuntu_reject_all', disabled=not (ready and undecided))
        comment = st.text_input('Comment (optional, recorded with your next decision)', key='agentic_comment',
                                max_chars=500, placeholder='e.g. Approved for the Saturday maintenance window')
        if approve_all or reject_all:
            for p in undecided:
                if approve_all and 'approve' not in p.eligible_commands:
                    continue
                _ubuntu_decide(backend, connection, p, approve_all, operator, comment)
            st.session_state.pop('agentic_comment', None)
            st.rerun()
        st.caption('Each approval is bound to that exact request on this server and expires after one hour.')
    findings = {f.control_id: f for f in snapshot.findings}
    for number, card in enumerate(fixes, 1):
        p = [q for q in card['proposals'] if q.kind == 'control_remediation'][-1]  # The latest plan for the control.
        finding = findings.get(card['control_id'])
        with st.container(border=True):
            left, right = st.columns([3, 1.2], vertical_alignment='center')
            left.markdown(f"**{number}. {md_escape(card['control_id'])} · {md_escape(p.title)}** "
                          + (level_badge(finding.level) + f' risk {finding.score}' if finding else ''))
            left.caption('Now: ' + md_escape(_ubuntu_now_line(p)) + ' · ' + md_escape(p.recovery))
            left.caption('Why the Orchestrator chose it: ' + md_escape(card['reason'])
                         + (' · Analysis flag: ' + md_escape(card['flag']) if card['flag'] else ''))
            with right:
                _ubuntu_decision_cell(backend, connection, card, p, operator, comment)
            restores = [q for q in card['proposals'] if q.kind == 'recovery']
            if editable and (p.reference in applied or restores):
                with left:
                    _ubuntu_restore_actions(backend, connection, card['proposals'], capabilities, workflow, applied,
                                            executed, restoring)
                    for q in restores:
                        if q.eligible_commands:
                            st.caption('Restore of ' + md_escape(card['control_id']) + ' awaits your decision:')
                            _ubuntu_decision_cell(backend, connection, dict(card, state='Awaiting your decision'), q,
                                                  operator, comment)
    skipped = [c for c in cards if c not in fixes]
    if skipped:
        st.markdown('**Not proposed this round**')
        st.dataframe([{'Control': c['control_id'], 'Reason': (
            'Fix proposed, but the read-only check on the server refused it (a prerequisite is missing, for example '
            'an SSH allow rule before the firewall is enabled)' if c['state'] == NO_PLAN
            else c['decision'] + ': ' + c['reason'])} for c in skipped], hide_index=True)
    if snapshot.current_round_reference is None or not editable:
        return  # Maintenance belongs to the latest round's applied fixes: nothing before the first round.
    with st.container(border=True):
        st.markdown('**Maintenance**')
        carded = {q.reference for c in cards for q in c['proposals']}
        for q in snapshot.proposals:  # Package-list refresh and reboot proposals, which belong to no control.
            if q.reference not in carded and q.eligible_commands:
                st.caption(md_escape(q.title) + ' awaits your decision.')
                _ubuntu_decision_cell(backend, connection, {'state': 'Awaiting your decision', 'results': {}}, q,
                                      operator, comment)
        _ubuntu_maintenance_actions(backend, connection, snapshot, capabilities, workflow, applied, executed)


UBUNTU_ROUND_VIEW = 'ubuntu_round_view'
UBUNTU_FACTORS = (('I', 'I Security impact'), ('E', 'E Exposure'), ('P', 'P Privilege impact'), ('L', 'L Likelihood'),
                  ('D', 'D Drift'))


def _ubuntu_choose_round(rounds):
    """As the Windows round picker: newest first; returns the chosen earlier round's reference, or None for the
    latest round (or when the workflow has a single round)."""
    if len(rounds) < 2:
        return None
    count = len(rounds)
    labels = {f'Round {n} · {myt(at)}' + (' (latest)' if n == count else ''): ref
              for n, (ref, at) in enumerate(rounds, 1)}  # unique: each label starts with its round number
    chosen = labels[st.selectbox('Round', list(reversed(labels)), key=UBUNTU_ROUND_VIEW, width=320)]
    return None if chosen == rounds[-1][0] else chosen


def _ubuntu_report_button(backend, connection, workflow, snapshot, rounds):
    """As the Windows "Round report": a self-contained HTML record of the latest round, built from stored records."""
    from system.ui.round_report import ubuntu_round_report
    if snapshot.current_round_reference is None:
        return
    html = ubuntu_round_report(snapshot, rounds, backend.remediation_review(connection, workflow),
                               backend.verification_changes(connection, workflow, snapshot.current_round_reference))
    started = next((at for ref, at in rounds if ref == snapshot.current_round_reference), None)
    st.download_button('Round report', html, icon=':material/download:', mime='text/html', key='ubuntu_report',
                       file_name='cis-round-' + backend.session.identity.hostname + '-'
                       + (myt(started, '%Y-%m-%dT%H%M') if started else 'round') + '.html',
                       help='Self-contained HTML record of this round. Open it in a browser to print to PDF.')


def _ubuntu_finding_detail(backend, connection, workflow, snapshot, finding):
    """As the Windows finding detail: the score's factors with the rule behind each, the benchmark rationale, then
    the optional explanation by the local model (FR17: unverified, changes nothing)."""
    control = next((c for c in snapshot.controls if c.control_id == finding.control_id), None)
    st.markdown(f"**{md_escape(finding.control_id)} · {md_escape(control.title if control else '')}** "
                f'{level_badge(finding.level)} risk {finding.score}')
    st.caption(f'6×{finding.I} + 5×{finding.E} + 4×{finding.P} + 3×{finding.L} + 2×{finding.D} = {finding.score}')
    rules = {r[0]: r for r in finding.derivation_reasons if len(r) > 1 and r[1] == '=' and r[0] in 'IEPLD'}
    rationale = [r for r in finding.derivation_reasons if r not in rules.values()]
    st.dataframe([{'Factor': label, 'Value': getattr(finding, name), 'Rule': rules.get(name, '')}
                  for name, label in UBUNTU_FACTORS], hide_index=True)
    if rationale:
        st.caption('Benchmark rationale (paraphrased): ' + md_escape(' '.join(rationale)))
    round_id = snapshot.current_round_reference.record_id
    key = 'ubuntu_explain_' + round_id + '_' + finding.control_id
    if st.button('Explain with local AI', key=key + '_btn', icon=':material/chat:'):
        with st.spinner('Asking qwen3:8b…'):
            try:
                st.session_state[key] = backend.explain_finding(connection, workflow, finding.control_id,
                    round_ref=snapshot.current_round_reference) or 'The model returned no explanation.'
            except Exception as exc:  # Explanation is optional; the assessment remains valid.
                st.session_state[key] = 'Explanation unavailable (' + type(exc).__name__ + ').'
    if key in st.session_state:
        st.caption('Model-written explanation (unverified; does not affect the score):')
        st.text(st.session_state[key])


def _ubuntu_show_risk(backend, connection, workflow, snapshot):
    """As the Windows Risk ranking tab: the ranking, the chosen finding's details (with Explain), then the gaps."""
    if snapshot.summary is None:
        st.info('No risk analysis for this round.')
        return
    if snapshot.findings:
        st.caption('R = 6I + 5E + 4P + 3L + 2D, computed by code (' + snapshot.findings[0].risk_policy_version + '). '
                   'The Analysis Agent can flag findings but cannot change a score.')
        controls = {c.control_id: c for c in snapshot.controls}
        flags = {row.control_id: row.flag for row in snapshot.plan if row.flag}
        st.dataframe([{'Rank': f.rank, 'Control': f.control_id, 'Title': controls[f.control_id].title,
                       'Sub-checks': controls[f.control_id].observed, 'Risk': f.score, 'Level': f.level,
                       'Analysis Agent flag': flags.get(f.control_id, '')} for f in snapshot.findings],
                     hide_index=True, column_config={'Rank': st.column_config.NumberColumn(width='small'),
                                                     'Risk': st.column_config.NumberColumn(width='small')})
        by_id = {f.control_id: f for f in snapshot.findings}
        chosen = st.selectbox('Finding details', list(by_id),
                              format_func=lambda c: c + ' · ' + controls[c].title,
                              key='ubuntu_finding_' + snapshot.current_round_reference.record_id)
        with st.container(border=True):
            _ubuntu_finding_detail(backend, connection, workflow, snapshot, by_id[chosen])
    elif snapshot.summary.non_compliant:
        st.info('No scored findings are available for this assessment.')
    else:
        st.success('No scored non-compliant findings.')
    gaps = [c for c in snapshot.controls if c.status.value in ('Unknown', 'Error')]
    if gaps:
        st.markdown('**Gaps (not scored, no fix)**')
        st.dataframe([{'Control': c.control_id, 'Status': c.status.value, 'Sub-checks': c.observed} for c in gaps],
                     hide_index=True)


def _ubuntu_show_results(backend, connection, workflow, snapshot, editable):
    """As the Windows Results tab: the Orchestrator's review, the execution results, then the configuration changes
    the verification scan found."""
    from system.ui.components import render_results_table
    review = backend.remediation_review(connection, workflow) if editable and workflow else None
    if review:
        _ubuntu_review_line(review)
    render_results_table(snapshot)
    changes = backend.verification_changes(connection, workflow, snapshot.current_round_reference) \
        if workflow and snapshot.current_round_reference else None
    if changes is not None:
        st.markdown('**Configuration changes found by the verification rescan**')
        st.dataframe([{'Control': c['control_id'], 'Title': c['title'], 'Before': c['before'], 'After': c['after'],
                       'Change': c['change'], 'Sub-checks': c['subchecks']} for c in changes]
                     or [{'Change': 'No changes detected'}], hide_index=True)


def _ubuntu_execute_bar(backend, connection, snapshot, capabilities):
    """Above the tabs, as on Windows: Execute N approved fix(es)…, then a confirmation listing exactly those changes."""
    executed = {r.proposal_reference for r in snapshot.results}
    pending = [p for p in snapshot.proposals if p.kind == 'control_remediation' and p.decision == 'approved'
               and p.approved_request_id and p.reference not in executed]
    if not pending:
        st.session_state.pop(UBUNTU_CONFIRM, None)
        return
    # The backend takes the round's whole approved set (fixes already run are skipped, never repeated).
    approved = tuple(p.approved_request_id for p in snapshot.proposals
                     if p.kind == 'control_remediation' and p.decision == 'approved' and p.approved_request_id)
    if st.session_state.get(UBUNTU_CONFIRM) != snapshot.current_round_reference.record_id:
        workflow = st.session_state.get(WORKFLOW_KEY)
        review = backend.remediation_review(connection, workflow) if workflow else None
        # As on Windows: once the agents stopped early (the review decided nothing, or found fixes not attempted),
        # the approved fixes still waiting can run without AI, in plan order, with the same approvals and checks.
        stopped = bool(review) and (review['next_step'] is None or review['reason_code'] == 'remediation_incomplete')
        hint = None if capabilities.can_remediate else 'Execution is not enabled on this server yet.'
        with st.container(horizontal=True):
            if st.button(f'Execute {len(pending)} approved fix(es)…', type='primary', key='ubuntu_execute_review',
                         icon=':material/play_arrow:', disabled=not capabilities.can_remediate, help=hint):
                st.session_state[UBUNTU_CONFIRM] = snapshot.current_round_reference.record_id
                st.session_state['ubuntu_confirm_requests'] = approved
                st.rerun()
            if stopped and st.button('Execute remaining without AI', key='ubuntu_execute_fallback',
                                     disabled=not capabilities.can_remediate,
                                     help=hint or 'Same approval, expiry and server checks, in plan order; the result '
                                                  'is still verified by a fresh scan.'):
                round_ref, operation = snapshot.current_round_reference, uuid4().hex
                _start(FALLBACK_LABEL,
                       lambda: backend.execute_approved(connection, workflow, round_ref, approved, True, operation),
                       _after_ubuntu_execute)
        return
    findings = {f.control_id: f for f in snapshot.findings}
    now = datetime.now(timezone.utc)
    with st.container(border=True):
        st.markdown(f'**Confirm: change {len(pending)} setting(s) on {md_escape(backend.session.identity.hostname)}**')
        st.dataframe([{'Rank': findings[p.control_id].rank if p.control_id in findings else '—',
                       'Control': p.control_id, 'Change': p.title, 'Current value': _ubuntu_now_line(p),
                       'Approved by': p.approved_by or '—',
                       'Approval valid until': myt(p.expiry) + (' (expired)' if datetime.fromisoformat(p.expiry) <= now
                                                                else '') if p.expiry else '—'}
                      for p in pending], hide_index=True)
        # An agentic round's fixes run in the remediation phase: the Remediation Agent prechecks, skips what is not
        # ready and executes in its order; the Scanner verifies and the Orchestrator decides the next step. Only when
        # the model is unavailable do they run in plan order; there is no separate button for that (administrator
        # request 2026-11-09). The same server checks guard both.
        agentic = bool(snapshot.plan) and capabilities.can_use_model
        st.caption(('The Remediation Agent re-checks each fix read-only and skips anything that changed since the '
                    'plan; the server checks it again before writing. ' if agentic else
                    'The server re-checks each value and refuses anything that changed since the plan. ')
                   + 'A fresh scan verifies the result. Expired approvals are refused. SSH and firewall changes must '
                   'be confirmed after reconnecting, or the server undoes them by itself.')
        with st.container(horizontal=True):
            if st.button('Confirm and execute', type='primary', key='ubuntu_execute'):
                st.session_state.pop(UBUNTU_CONFIRM, None)
                ids = st.session_state.pop('ubuntu_confirm_requests', ())
                workflow, round_ref, operation = (st.session_state.get(WORKFLOW_KEY), snapshot.current_round_reference,
                                                  uuid4().hex)
                # In the background worker, so opening another page cannot stop it half-way.
                _start(UBUNTU_AGENTS_EXECUTE_LABEL if agentic else UBUNTU_EXECUTE_LABEL,
                       lambda: backend.execute_approved(connection, workflow, round_ref, ids, not agentic, operation),
                       _after_ubuntu_execute)
            if st.button('Cancel', key='ubuntu_execute_cancel'):
                st.session_state.pop(UBUNTU_CONFIRM, None)
                st.rerun()
