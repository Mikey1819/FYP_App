"""Agentic hardening page: one live VM, AI-coordinated rounds, human approval, verified fixes."""
from pathlib import Path
import sqlite3

import streamlit as st

from .action_library import LIBRARY
from .agentic import ANALYSIS, ORCHESTRATOR, SCANNER, AgenticHardening, explain_finding
from .framework import AssessmentOrchestrator
from .import_storage import ImportedEvidenceStore
from .remediation import RemediationStore
from .scan_view import render_connection
from .winrm_channel import ChannelError, LiveScanner

SESSION = 'agentic_session'
LEVEL_ICON = {'Critical': '🟥', 'High': '🟧', 'Moderate': '🟨', 'Low': '🟩'}


def shown(value, status):
    """Display value; an absent policy that fails (decision D5) reads as Not configured."""
    if value is None:
        return 'Not configured' if status == 'Non-Compliant' else '—'
    return repr(value)


def _services(database_path, target):
    imports = ImportedEvidenceStore(database_path)
    runtime = AssessmentOrchestrator(imports)
    store = RemediationStore(database_path.with_name(database_path.stem + '_agentic.sqlite3'), imports)
    return runtime, store, AgenticHardening(runtime, store, LiveScanner(runtime, target))


def _analysis(hardening, round_id):
    for trace in hardening.traces(round_id):
        if trace['agent_role'] == ANALYSIS:
            return next(e['data']['result'] for e in trace['events'] if e['kind'] == 'tool')
    return None


def _show_timeline(hardening, assessment_round):
    traces = hardening.traces(assessment_round['round_id'])
    order = {ORCHESTRATOR: 0, SCANNER: 1, ANALYSIS: 2}
    rows = []
    for trace in sorted(traces, key=lambda t: order.get(t['agent_role'], 9)):
        finished = next((e['data'] for e in reversed(trace['events']) if e['kind'] == 'finished'), {})
        outcome = (finished.get('outcome') or {}).get('outcome', 'No structured decision')
        rows.append({'Agent': trace['agent_role'], 'Engine': trace['provenance'], 'Status': finished.get('status', 'Interrupted'),
                     'Outcome': outcome, 'Tool calls': finished.get('tool_calls', 0),
                     'Seconds': finished.get('duration_seconds')})
    st.dataframe(rows, hide_index=True)
    with st.expander('Agent decisions, tool calls and rejected calls'):
        st.caption('Every tool call below was chosen by the agent and validated by code. Rejected calls had no effect. '
                   'Model-written reasons are unverified text.')
        for trace in traces:
            st.markdown('**' + trace['agent_role'] + '** · ' + trace['provenance'])
            for event in trace['events']:
                if event['kind'] in ('tool', 'tool_rejected', 'finished'):
                    data = dict(event['data'])
                    if event['kind'] == 'tool' and data.get('name') == 'analyse_findings':
                        data['result'] = '(shown in the risk ranking above)'
                    st.json({'event': event['kind'], **data}, expanded=False)


def _show_assessment(runtime, run_id):
    record = runtime.imports.get(runtime.get(run_id).evidence_sha256)
    rows = [{'Control': r.control.control_id, 'Title': r.control.title, 'Area': r.control.area,
             'Status': r.status.value, 'Observed': shown(r.evidence.value, r.status.value)}
            for r in record.assessment.results]
    counts = {s: sum(r['Status'] == s for r in rows) for s in ('Compliant', 'Non-Compliant', 'Unknown', 'Error')}
    cols = st.columns(4)
    for col, (label, value) in zip(cols, counts.items()):
        col.metric(label, value)
    with st.expander('All ' + str(len(rows)) + ' assessed controls (CIS Server 2022 Stand-alone v2.0.0)'):
        st.dataframe(rows, hide_index=True)


def _show_risk(analysis, round_id):
    st.caption('Deterministic risk engine: R = 6I + 5E + 4P + 3L + 2D. Baselines: ' + analysis['baseline_version'] + '. '
               'The AI never computes or changes these numbers.')
    if not analysis['ranked']:
        st.success('No scored non-compliant findings.')
    for finding in analysis['ranked']:
        f = finding['factors']
        with st.container(border=True):
            left, right = st.columns([3, 1])
            left.markdown(f"**{finding['control_id']} · {finding['title']}**  \n"
                          f"Observed `{shown(finding['observed'], 'Non-Compliant')}` · required {finding['rule']}")
            right.markdown(f"{LEVEL_ICON[finding['level']]} **{finding['score']}** {finding['level']}  \nPriority {finding['priority']}")
            st.caption(f"I={f['I']} E={f['E']} P={f['P']} L={f['L']} D={f['D']} → "
                       f"6×{f['I']} + 5×{f['E']} + 4×{f['P']} + 3×{f['L']} + 2×{f['D']} = {finding['score']}")
            with st.expander('How this score was derived'):
                reasons = finding.get('factor_reasons', {})
                st.dataframe([{'Factor': 'I Security Impact', 'Value': f['I'], 'Rule': reasons.get('I', '')},
                              {'Factor': 'E Exposure', 'Value': f['E'], 'Rule': finding['exposure_reason']},
                              {'Factor': 'P Privilege Impact', 'Value': f['P'], 'Rule': reasons.get('P', '')},
                              {'Factor': 'L Likelihood', 'Value': f['L'], 'Rule': reasons.get('L', '')},
                              {'Factor': 'D Drift', 'Value': f['D'], 'Rule': finding['drift_reason']}], hide_index=True)
                st.caption('Benchmark rationale (paraphrased): ' + finding['rationale'])
            key = 'agentic_explain_' + round_id + finding['control_id']
            if st.button('Explain with local AI', key=key + '_btn'):
                with st.spinner('Asking local qwen3:8b for a plain-language explanation…'):
                    try:
                        st.session_state[key] = explain_finding(finding)
                    except Exception as exc:  # Explanation is optional; assessment remains valid.
                        st.session_state[key] = 'Explanation unavailable (' + type(exc).__name__ + ').'
            if key in st.session_state:
                st.caption('AI-generated explanation (unverified; does not affect the score):')
                st.text(st.session_state[key])
    if analysis['gaps']:
        st.markdown('**Gaps (not scored, no fix)**')
        st.dataframe([{'Control': g['control_id'], 'Status': g['status'], 'Interpretation': g['hint']}
                      for g in analysis['gaps']], hide_index=True)


def _show_proposals(store, run_id, round_id):
    records = store.for_run(run_id)
    if not records:
        st.info('The Orchestrator proposed no fixes in this round.')
        return
    operator = st.text_input('Administrator name for decisions', key='agentic_operator_' + round_id)
    for record in records:
        p = record['proposal']
        action = LIBRARY[p['action_id']]
        with st.container(border=True):
            st.markdown(f"**#{p['rank']} · {p['control_id']} → {action.title}**  (`{p['action_id']}`, risk {p['risk_score']})")
            st.caption('Change: ' + shown(p['expected_before'], 'Non-Compliant') + ' → ' + repr(p['value']) + '. Impact: ' + action.impact)
            st.caption('Orchestrator’s reason (a fixed reason code it chose, checked against the analysis):')
            st.text(p['reason'])
            if record['verdict']:
                st.write('Result: **' + record['verdict'] + '**')
            elif record['decision']:
                st.write('Decision: **' + record['decision'] + '**'
                         + (' — awaiting execution' if record['decision'] == 'approved' else ''))
            else:
                approve, reject = st.columns(2)
                pid = p['request_id']
                if approve.button('Approve', key='agentic_approve_' + pid, disabled=not operator.strip()):
                    store.decide(pid, approve=True, operator=operator)
                    st.rerun()
                if reject.button('Reject', key='agentic_reject_' + pid, disabled=not operator.strip()):
                    store.decide(pid, approve=False, operator=operator)
                    st.rerun()


def render_agentic(database_path: Path):
    st.title('Agentic hardening')
    st.caption('Scanner Agent → Analysis Agent → AI Orchestrator proposes fixes → you approve → '
               'Remediation Agent executes → Scanner verifies. Target: the registered standalone Server 2022 VM.')
    with st.expander('1. Connect to the VM', expanded=SESSION not in st.session_state):
        left, right = st.columns(2)
        hostname = left.text_input('VM computer name', key='agentic_host')
        machine_uuid = right.text_input('VM machine UUID', key='agentic_uuid')
        try:
            target = render_connection(hostname, machine_uuid, key='agentic_live')
        except (ValueError, ChannelError) as exc:
            st.error(str(exc))
            target = None
    if target is None:
        st.info('Connect to the VM to start an agentic round.')
        return
    try:
        runtime, store, hardening = _services(database_path, target)
        session_id = st.session_state.get(SESSION)
        rounds = store.rounds(session_id) if session_id else []
        assessments = [r for r in rounds if r['kind'] == 'assessment']
        latest = assessments[-1] if assessments else None
        # A new round is offered once nothing in the latest one awaits a decision or execution.
        open_items = [r for r in store.for_run(latest['framework_run_id'] or '') if r['decision'] is None
                      or (r['decision'] == 'approved' and r['verdict'] is None)] if latest else []
        label = 'Start agentic round' if latest is None else 'Run next round (rescan, re-rank, re-propose)'
        if not open_items:
            if st.button(label, type='primary', key='agentic_run'):
                with st.spinner('AI Orchestrator coordinating the Scanner and Analysis agents (up to 5 minutes)…'):
                    result = hardening.run_round(session_id)
                st.session_state[SESSION] = result['session_id']
                st.rerun()
        if session_id and st.button('Start a new session', key='agentic_reset'):
            del st.session_state[SESSION]
            st.rerun()
        if latest is None:
            return
        st.subheader('2. Round outcome')
        outcome = latest['outcome']
        (st.success if outcome['outcome'] == 'awaiting_approval' else st.info)(outcome['reason'])
        if outcome.get('skipped'):
            st.caption('Deferred by the Orchestrator (reason codes it chose, checked against the analysis):')
            st.dataframe([{'Control': s['control_id'], 'Reason': s['reason']} for s in outcome['skipped']],
                         hide_index=True)
        _show_timeline(hardening, latest)
        if not latest['framework_run_id']:
            return
        st.subheader('3. Assessment')
        _show_assessment(runtime, latest['framework_run_id'])
        analysis = _analysis(hardening, latest['round_id'])
        if analysis:
            st.subheader('4. Risk ranking (Analysis Agent)')
            _show_risk(analysis, latest['round_id'])
        st.subheader('5. Proposed fixes — your decision')
        _show_proposals(store, latest['framework_run_id'], latest['round_id'])
        pending = [r for r in store.for_run(latest['framework_run_id']) if r['decision'] == 'approved' and r['verdict'] is None]
        if pending and st.button(f'Execute {len(pending)} approved fix(es) in the VM', type='primary', key='agentic_execute'):
            with st.spinner('Remediation Agent executing approved actions; Scanner verifying…'):
                hardening.execute_approved(session_id)
            st.rerun()
        verification = next((r for r in reversed(rounds) if r['kind'] == 'verification_scan'
                             and r.get('remediated_run_id') == latest['framework_run_id']), None)
        if verification:
            st.subheader('6. Verification')
            st.dataframe([{'Control': v['control_id'], 'Action': v['action_id'], 'Verdict': v['verdict']}
                          for v in verification['verdicts']], hide_index=True)
            if verification['framework_run_id']:
                changed = [c for c in hardening.changes(latest['framework_run_id'], verification['framework_run_id'])
                           if c['change'] != 'Unchanged']
                st.caption('Configuration changes since this round’s scan (fresh full rescan by the Scanner):')
                st.dataframe(changed or [{'change': 'No changes detected'}], hide_index=True)
    except ChannelError as exc:
        st.error('VM channel (' + exc.state + '): ' + exc.detail)
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Agentic workflow: ' + str(exc))
