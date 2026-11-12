"""Common presentation helpers used inside the existing pages, for either backend."""
import streamlit as st
from hardening.ui import md_escape
from hardening.ui import myt, FULL

TABS = ('Fixes', 'Risk ranking', 'Controls', 'Results', 'Agent log')


def render_history_rows(backend, rows):
    """The Windows History page's sections for an Ubuntu server: assessment history, detected drift, compare."""
    if not rows:
        st.info('No assessments yet. Open **Agentic hardening** and start a round.')
        return
    st.subheader('Assessment history')
    st.dataframe([{'Assessed (MYT)': myt(r.time, FULL), 'Run': r.run_reference.record_id[:8],
        'Evidence': r.evidence_mode, 'Controls': r.counts.selected, 'Compliant': r.counts.compliant,
        'Non-compliant': r.counts.non_compliant, 'Unknown': r.counts.unknown, 'Error': r.counts.error,
        'Compliance of evaluated': '—' if r.counts.compliance_percent is None else f'{r.counts.compliance_percent:.0f}%'}
        for r in reversed(rows)], hide_index=True)
    st.caption('Compliance is among evaluated controls (Compliant + Non-compliant); Unknown/Error are shown '
               'separately and never counted as passes.')
    if hasattr(backend, 'drift'):
        st.subheader('Detected configuration drift')
        records = backend.drift()
        if not records:
            st.info('No drift detected between consecutive assessments.')
        else:
            regressions = sum(r['change'] == 'Regression' for r in records)
            if regressions:
                st.warning(f'{regressions} regression(s): a control that was compliant became non-compliant.')
            st.dataframe([{'Detected (MYT)': myt(r['detected_at'], FULL), 'Control': r['control_id'],
                           'Title': r['title'], 'Before': r['before'], 'After': r['after'], 'Change': r['change'],
                           'Runs': r['runs']} for r in reversed(records)], hide_index=True)
    if len(rows) >= 2:
        st.subheader('Compare two assessments')
        refs = [r.run_reference for r in rows]
        labels = {r.run_reference: f'{myt(r.time, FULL)} MYT · {r.run_reference.record_id[:8]}' for r in rows}
        left, right = st.columns(2)
        before = left.selectbox('Earlier', refs, index=len(refs)-2, format_func=labels.get, key='history_before_shared')
        after = right.selectbox('Later', refs, index=len(refs)-1, format_func=labels.get, key='history_after_shared')
        if before == after:
            st.info('Choose two different assessments.')
        elif hasattr(backend, 'compare_rows'):
            try:
                compared = backend.compare_rows(before, after)
            except ValueError as exc:
                st.warning(md_escape(exc))
                return
            show_all = st.checkbox('Show unchanged controls', key='history_all_shared')
            shown = compared if show_all else [r for r in compared if r['change'] != 'Unchanged']
            st.dataframe([{'Control': r['control_id'], 'Title': r['title'], 'Before': r['before'], 'After': r['after'],
                           'Change': r['change']} for r in shown] or [{'Change': 'No differences'}], hide_index=True)
        else:
            result = backend.compare(before, after)
            if not result.comparable:
                st.warning(md_escape(result.reason))
            else:
                st.dataframe([{'Control': control, 'Before': previous, 'After': current}
                              for control, previous, current in result.changes] or [{'Change': 'No differences'}],
                             hide_index=True)


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
        with_fix = any(row.fix for row in snapshot.controls)
        st.dataframe([{'Control': row.control_id, 'Title': row.title, 'Area': row.area,
            'Profile': row.profile, 'Status': row.status.value, 'Applicability': row.applicability,
            'Observed': row.observed, 'Required': row.expected, **({'Fix': row.fix} if with_fix else {}),
            'Source': row.source} for row in snapshot.controls], hide_index=True)


APPLIED = ('applied', 'reconciled_applied')
NOT_APPLIED = ('refused', 'rolled_back', 'reconciled_not_applied')
SKIPPED = 'Skipped by the Remediation Agent'
EXPLANATION_LABEL = 'Model-written explanation (unverified; does not affect the score):'
ICONS = {'Awaiting your decision': ':material/build:', 'Fix proposed': ':material/build:', SKIPPED: ':material/skip_next:',
         'Approved, ready to execute': ':material/thumb_up:', 'Rejected': ':material/block:',
         'Running': ':material/hourglass_top:', 'Applied, re-scan pending': ':material/hourglass_top:',
         'Fixed, re-scan: Compliant': ':material/check_circle:', 'Not applied': ':material/cancel:',
         'Outcome unknown': ':material/help:', 'Restored to the before-state': ':material/undo:',
         'No fix plan: the read-only preview failed': ':material/report:'}
NO_PLAN = 'No fix plan: the read-only preview failed'
NO_PLAN_NOTE = ('The planner proposed this fix, but the read-only preview on the target was refused, so there is '
                'nothing to approve. The target checks the current state before any plan is stored: a prerequisite '
                'may be missing, or the change would affect more than this control. It is offered again in a later '
                'round once the target allows it.')


def _card_state(row, fix, recovery, results):
    if any(results.get(r.reference.record_id) and results[r.reference.record_id].execution_state in APPLIED
           for r in recovery):
        return 'Restored to the before-state'
    if fix is None:
        # A planned fix gets its stored plan right after the plan step, unless the read-only preview failed
        # (live 05:08-07:19: 1.2.2.1, 2.1.2 and 6.3.3.x always said only "Fix proposed").
        return NO_PLAN if row.decision == 'Fix proposed' else row.decision  # Deferred, Deferred (by the app), No plan
    result = results.get(fix.reference.record_id)
    if result is None:
        return {'approved': 'Approved, ready to execute', 'rejected': 'Rejected'}.get(fix.decision,
                                                                                    'Awaiting your decision')
    if result.execution_state in APPLIED:
        status = result.verification_status
        if status is None:
            return 'Applied, re-scan pending'
        return 'Fixed, re-scan: Compliant' if status.value == 'Compliant' else 'Applied, re-scan: ' + status.value
    if result.execution_state == 'running':
        return 'Running'
    if result.execution_state == 'skipped':  # Closed unexecuted by the Remediation Agent (precheck or a stop).
        return SKIPPED
    return 'Not applied' if result.execution_state in NOT_APPLIED else 'Outcome unknown'


def plan_cards(snapshot):
    """One card per Non-Compliant control of the round's plan: decision, reason, its proposals and their outcome."""
    results = {r.proposal_reference.record_id: r for r in snapshot.results}
    risk = {f.control_id: f for f in getattr(snapshot, 'findings', ())}
    cards = []
    for row in getattr(snapshot, 'plan', ()):
        own = [p for p in snapshot.proposals if p.control_id == row.control_id
               and p.kind in ('control_remediation', 'recovery')]
        fixes = [p for p in own if p.kind == 'control_remediation']
        recovery = [p for p in own if p.kind == 'recovery']
        state = _card_state(row, fixes[-1] if fixes else None, recovery, results)
        finding = risk.get(row.control_id)
        cards.append({'control_id': row.control_id, 'title': row.title, 'state': state, 'decision': row.decision,
                      'risk': 'risk %d (%s)' % (finding.score, finding.level) if finding else '',
                      '_order': (0, -finding.score, finding.rank) if finding else (1, 0, 0),
                      'note': NO_PLAN_NOTE if state == NO_PLAN else '',
                      'reason': row.reason, 'flag': row.flag, 'proposals': own,
                      'results': {p.reference.record_id: results[p.reference.record_id]
                                  for p in own if p.reference.record_id in results},
                      'icon': ICONS.get(state, ':material/warning:' if state.startswith('Applied')
                                        else ':material/pause_circle:')})
    # Highest deterministic risk first (administrator request 2026-11-08); ties keep the risk ranking, and controls
    # without a score (risk withheld or not ranked) follow in plan order.
    cards.sort(key=lambda c: c.pop('_order'))
    return cards


def plan_summary(snapshot):
    cards = plan_cards(snapshot)
    proposed = sum(c['decision'] == 'Fix proposed' for c in cards)
    approved = sum(p.decision == 'approved' for c in cards for p in c['proposals'] if p.kind == 'control_remediation')
    fixed = sum(c['state'] == 'Fixed, re-scan: Compliant' for c in cards)
    unplanned = sum(c['state'] == NO_PLAN for c in cards)
    return '%d Non-Compliant controls · %d %s proposed · %d approved · %d fixed (re-scan Compliant)%s' % (
        len(cards), proposed, 'fix' if proposed == 1 else 'fixes', approved, fixed,
        ' · %d without a fix plan' % unplanned if unplanned else '')


def _render_cards(snapshot, control_actions):
    st.markdown('**' + md_escape(plan_summary(snapshot)) + '**')
    st.caption("One card per Non-Compliant control from this round's scan, highest deterministic risk first. The AI "
               'Agent Orchestrator chooses what to propose; every fix needs your approval. After a fix runs, its card '
               'shows the fresh re-scan.')
    for card in plan_cards(snapshot):
        label = '**%s** · %s%s — %s' % (md_escape(card['control_id']), md_escape(card['title']),
                                         ' · ' + md_escape(card['risk']) if card['risk'] else '', md_escape(card['state']))
        with st.expander(label, icon=card['icon'], key='fix_card_' + card['control_id']):
            st.markdown('**Planner decision:** ' + md_escape(card['decision']) + '  \n**Reason:** '
                        + md_escape(card['reason']) + ('  \n**Analysis flag:** ' + md_escape(card['flag'])
                                                      if card['flag'] else ''))
            if card['note']:
                st.warning(md_escape(card['note']))
            for p in card['proposals']:
                st.markdown(('**Proposed fix:** ' if p.kind == 'control_remediation' else '**Restore:** ')
                            + md_escape(p.title) + ' · ' + md_escape(p.version) + ' · '
                            + md_escape(p.decision or 'awaiting decision'))
                st.code(p.exact_preview, language=None)
                st.caption('Recovery: ' + md_escape(p.recovery))
                outcome = card['results'].get(p.reference.record_id)
                if outcome is not None:
                    st.caption('Outcome: ' + md_escape(outcome.detail))
            if control_actions is not None:
                control_actions(card)


def render_results_table(snapshot):
    """One row per execution result of the round (also used by the Ubuntu page's Results layout)."""
    if snapshot.results:
        st.dataframe([{'Proposal': r.proposal_reference.record_id, 'Execution': r.execution_state,
            'Verification': r.verification_status.value if r.verification_status else 'Not verified',
            'Recovery': r.recovery_state, 'Detail': r.detail} for r in snapshot.results], hide_index=True)
    else:
        st.info('No execution results for this target.')


def render_snapshot_tabs(snapshot, *, tabs=None, fix_actions=None, fix_header=None, control_actions=None,
                         fixes_panel=None, risk_panel=None, results_panel=None, log_panel=None, controls_panel=None):
    """Common panels, also used while a verified backend requires setup. `fix_actions` renders the page's own
    decision/execution controls inside Fixes; with a plan (Ubuntu), `fix_header` renders above the per-control
    cards and `control_actions(card)` inside each card. `fixes_panel`, `risk_panel`, `results_panel` and `log_panel`
    replace a tab with the page's own layout (Ubuntu: the Windows page's layout). The panels themselves never call a
    backend."""
    fixes, risk, controls, results, log = tabs or st.tabs(TABS)
    with fixes:
        if fixes_panel is not None:  # The page's own Fixes layout (Ubuntu: the same layout as the Windows page).
            fixes_panel()
        elif getattr(snapshot, 'plan', ()):
            if fix_header is not None:
                fix_header()
            _render_cards(snapshot, control_actions)
            carded = {p.reference for c in plan_cards(snapshot) for p in c['proposals']}
            for row in snapshot.proposals:  # maintenance and other proposals that belong to no control card
                if row.reference not in carded:
                    st.markdown('**' + md_escape(row.title) + '** · ' + md_escape(row.decision or 'awaiting decision'))
                    st.text(row.exact_preview)
                    st.caption(md_escape(row.reason) + ' Recovery: ' + md_escape(row.recovery))
        elif not snapshot.proposals:
            st.info('No fixes have been proposed for this round.')
        else:
            for row in snapshot.proposals:
                st.markdown('**' + md_escape(row.title) + '** · ' + md_escape(row.control_id or '') + ' · '
                            + md_escape(row.decision or 'awaiting decision'))
                st.text(row.exact_preview)
                st.caption(md_escape(row.reason) + ' Recovery: ' + md_escape(row.recovery))
        if fix_actions is not None and fixes_panel is None:
            fix_actions()
    with risk:
        if risk_panel is not None:
            risk_panel()
        elif snapshot.findings:
            st.dataframe([{'Rank': f.rank, 'Control': f.control_id, 'Risk': f.score, 'Level': f.level,
                           'I': f.I, 'E': f.E, 'P': f.P, 'L': f.L, 'D': f.D,
                           'Derivation': '\n'.join(f.derivation_reasons)} for f in snapshot.findings], hide_index=True)
        else:
            st.info('No scored findings are available for this assessment.')
    with controls:
        if controls_panel is not None:  # Ubuntu: the newest scan of the round, as on the Windows page.
            controls_panel()
        else:
            render_controls(snapshot)
    with results:
        if results_panel is not None:
            results_panel()
        else:
            render_results_table(snapshot)
    with log:
        if log_panel is not None:
            log_panel()
        elif snapshot.events:
            st.dataframe([{'Role': e.role, 'Event': e.event_kind, 'Tool': e.tool_name,
                'Result': e.result_summary, 'Provenance': e.provenance} for e in snapshot.events], hide_index=True)
        else:
            st.info('No agent decisions recorded.')
