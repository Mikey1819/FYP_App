"""Visible multi-agent tasks and public handoffs, separate from fixed evaluation."""
import json
import streamlit as st

from .agent_team import AgentTeam, ORCHESTRATOR
from .scan_view import collection_channel


def render_agent_team(lifecycle, run_id, *, current_id=None, can_start=True):
    st.subheader('AI agent team')
    st.caption('Four separate agent conversations use local qwen3:8b. Each has its own task and permitted tools. '
               'Scanner reviews imported evidence; Analysis interprets findings; Remediation prepares a supported '
               'proposal; the AI Orchestrator delegates from their results. Scanner recollection runs over WinRM when the live connection is active; '
               'approved execution still uses the VM file exchange.')
    if st.button('Run multi-agent hardening review', key='vm_agent_team', disabled=not can_start):
        with st.spinner('The AI orchestrator is delegating to specialists (maximum five minutes)…'):
            AgentTeam(lifecycle, run_id, expected_previous_id=current_id,
                      collection_exchange=collection_channel(lifecycle.runtime)).run()
        st.rerun()
    # Recover this run's latest team from durable metadata, not a cached success flag.
    with lifecycle.bridge._connection() as db:
        rows = db.execute('SELECT payload FROM investigation_runs ORDER BY rowid DESC').fetchall()
    root = next((payload for (raw,) in rows if (payload := json.loads(raw)).get('framework_run_id') == run_id
                 and payload.get('agent_role') == ORCHESTRATOR), None)
    if root is None:
        return
    traces = AgentTeam.traces(lifecycle.bridge, run_id, root['team_id'])
    table = []
    for trace in traces:
        finished = next((e['data'] for e in reversed(trace['events']) if e['kind'] == 'finished'), None)
        outcome = (finished or {}).get('outcome') or {}
        table.append({'Agent': trace['agent_role'], 'Task state': finished['status'] if finished else 'Incomplete / interrupted',
                      'Outcome': outcome.get('outcome', 'No structured decision'),
                      'Tool calls': (finished or {}).get('tool_calls', 0)})
    st.dataframe(table, hide_index=True)
    root_trace = next(t for t in traces if t['agent_role'] == ORCHESTRATOR)
    finished = next((e['data'] for e in reversed(root_trace['events']) if e['kind'] == 'finished'), None)
    if finished and finished.get('outcome'):
        st.info(finished['outcome']['reason'])
        queued = finished['outcome'].get('collection_request')
        if queued and queued.get('state') == 'assessment_ready':
            st.success('Scanner collected fresh evidence over WinRM: new assessment ' + queued['framework_run_id'] + '.')
            if st.button('Open the Scanner’s new assessment', key='vm_open_recollected'):
                for key in list(st.session_state):
                    if key.startswith(('vm_cycle_', 'vm_context_')):
                        del st.session_state[key]
                st.session_state['vm_cycle_digest'] = queued['evidence_sha256']
                st.session_state['vm_cycle_framework_run'] = queued['framework_run_id']
                st.rerun()
        elif queued and queued.get('channel') == 'winrm':
            st.warning('Scanner tried to recollect over WinRM but failed (' + queued['state'] + '): '
                       + queued.get('error', '') + ' No assessment was created.')
        elif queued:
            if not st.session_state.get('vm_cycle_scan_id'):
                st.session_state['vm_cycle_scan_id'] = queued['request_id']
            st.info('Scanner queued fresh evidence collection. Use Check scan response below after the VM worker responds.')
    st.caption('A proposal awaits your separate approval. Specialist no-action outcomes do not authorize changes. '
               'Non-password findings still require review; no numeric risk score is generated.')
    with st.expander('Agent decisions and handoffs'):
        st.warning('Model-authored reasons and commentary are unverified and may contain incorrect claims. '
                   'Use recorded workflow state and collected measurements as the authority; a proposal is not execution.')
        for trace in traces:
            st.write(trace['agent_role'])
            st.caption('Task ' + trace['run_id'] + ' | ' + trace['provenance'])
            for event in trace['events']:
                if event['kind'] in ('tool', 'tool_rejected', 'finished'):
                    st.json({'event': event['kind'], **event['data']}, expanded=False)
