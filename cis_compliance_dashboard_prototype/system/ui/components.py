"""Common presentation helpers used inside the existing pages, for either backend."""
import streamlit as st
from hardening.ui import md_escape
from hardening.ui import myt, FULL

TABS = ('Fixes', 'Risk ranking', 'Controls', 'Results', 'Agent log')


def render_history_rows(backend, rows):
    if not rows:
        st.info('No assessments yet for this verified target. Open **Agentic hardening** to assess it.')
        return
    st.subheader('Assessment history')
    st.dataframe([{'Assessed (MYT)': myt(r.time, FULL), 'Run': r.run_reference.record_id[:8],
        'Evidence': r.evidence_mode, 'Controls': r.counts.selected, 'Compliant': r.counts.compliant,
        'Non-Compliant': r.counts.non_compliant, 'Unknown': r.counts.unknown, 'Error': r.counts.error,
        'Coverage': f'{r.counts.coverage_percent:.0f}%',
        'Compliance of evaluated': '—' if r.counts.compliance_percent is None else f'{r.counts.compliance_percent:.0f}%'}
        for r in reversed(rows)], hide_index=True)
    if len(rows) >= 2:
        st.subheader('Compare two assessments')
        refs = [r.run_reference for r in rows]
        labels = {r.run_reference: f'{myt(r.time, FULL)} · {r.run_reference.record_id[:8]}' for r in rows}
        left, right = st.columns(2)
        before = left.selectbox('Earlier', refs, index=len(refs)-2, format_func=labels.get, key='history_before_shared')
        after = right.selectbox('Later', refs, index=len(refs)-1, format_func=labels.get, key='history_after_shared')
        if before == after:
            st.info('Choose two different assessments.')
        else:
            result = backend.compare(before, after)
            if not result.comparable:
                st.warning(md_escape(result.reason))
            else:
                st.dataframe([{'Control': control, 'Before': previous, 'After': current}
                              for control, previous, current in result.changes] or [{'Change': 'No differences'}], hide_index=True)


def render_controls(snapshot):
    if snapshot.summary is None:
        st.info('No assessment has been collected for this target.')
        return
    s = snapshot.summary
    for column, (label, count) in zip(st.columns(4), (
            ('Compliant', s.compliant), ('Non-Compliant', s.non_compliant), ('Unknown', s.unknown), ('Error', s.error))):
        column.metric(label, count, border=True)
    st.caption(f'{s.selected} selected controls · coverage {s.coverage_percent:.0f}% · '
               + ('compliance unavailable' if s.compliance_percent is None else f'compliance {s.compliance_percent:.0f}%')
               + '. Unknown and Error are never counted as passes. Evidence: '
               + md_escape(snapshot.target.evidence_mode) + '.')
    if snapshot.controls:
        st.dataframe([{'Control': row.control_id, 'Title': row.title, 'Area': row.area,
            'Profile': row.profile, 'Status': row.status.value, 'Applicability': row.applicability,
            'Observed': row.observed, 'Required': row.expected, 'Source': row.source} for row in snapshot.controls], hide_index=True)


def render_snapshot_tabs(snapshot, *, tabs=None, fix_actions=None):
    """Common panels, also used while a verified backend requires setup. `fix_actions` renders the page's own
    decision/execution controls inside Fixes; the panels themselves never call a backend."""
    fixes, risk, controls, results, log = tabs or st.tabs(TABS)
    with fixes:
        if not snapshot.proposals:
            st.info('No fixes have been proposed for this round.')
        else:
            for row in snapshot.proposals:
                st.markdown('**' + md_escape(row.title) + '** · ' + md_escape(row.control_id or '') + ' · '
                            + md_escape(row.decision or 'awaiting decision'))
                st.text(row.exact_preview)
                st.caption(md_escape(row.reason) + ' Recovery: ' + md_escape(row.recovery))
        if fix_actions is not None:
            fix_actions()
    with risk:
        if snapshot.findings:
            st.dataframe([{'Rank': f.rank, 'Control': f.control_id, 'Risk': f.score, 'Level': f.level,
                           'I': f.I, 'E': f.E, 'P': f.P, 'L': f.L, 'D': f.D,
                           'Derivation': '\n'.join(f.derivation_reasons)} for f in snapshot.findings], hide_index=True)
        else:
            st.info('No scored findings are available for this assessment.')
    with controls:
        render_controls(snapshot)
    with results:
        if snapshot.results:
            st.dataframe([{'Proposal': r.proposal_reference.record_id, 'Execution': r.execution_state,
                'Verification': r.verification_status.value if r.verification_status else 'Not verified',
                'Recovery': r.recovery_state, 'Detail': r.detail} for r in snapshot.results], hide_index=True)
        else:
            st.info('No execution results for this target.')
    with log:
        if snapshot.events:
            st.dataframe([{'Role': e.role, 'Event': e.event_kind, 'Tool': e.tool_name,
                'Result': e.result_summary, 'Provenance': e.provenance} for e in snapshot.events], hide_index=True)
        else:
            st.info('No agent decisions recorded.')
