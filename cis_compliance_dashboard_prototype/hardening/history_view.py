"""Assessment history and configuration drift page (report Figure 4.16, UC07)."""
from pathlib import Path
import sqlite3

import streamlit as st

from .framework import AssessmentRuns
from .history import HistoryService
from .import_storage import ImportedEvidenceStore
from .remediation import RemediationStore
from .ui import FULL, md_escape, myt
from system.history import active_history

def _label(run):
    return f"{myt(run['created_at'], FULL)} MYT · {run['run_id'][:8]}"


def _value(value):
    """An absent setting is a policy that is not configured (decision D5), shown as such rather than as None."""
    return 'not configured' if value is None else repr(value)


def render_history(database_path: Path):
    st.title('History and configuration drift')
    st.caption('Every assessment is an immutable snapshot. Drift compares each assessment with the previous one of '
               'the same VM and records every change once. Changes are compared only when the benchmark source, '
               'profile, rule and collection method are identical.')
    try:
        backend, shared_rows = active_history(st.session_state, limit=1000)
        if backend and backend.session.identity.platform != 'windows':
            from system.ui.components import render_history_rows
            st.caption(md_escape(backend.session.identity.hostname) + ' · verified Ubuntu target')
            render_history_rows(backend, shared_rows)
            return
        imports = ImportedEvidenceStore(database_path)
        runtime = AssessmentRuns(imports)
        store = RemediationStore(database_path.with_name(database_path.stem + '_agentic.sqlite3'), imports)
        history = HistoryService(runtime, store)
        targets = history.targets()
        if backend:
            targets = {t: name for t, name in targets.items() if t == backend.session.target_id}
        if not targets:
            st.info('No assessments yet. Run an agentic round or a scan first.')
            return
        target = st.selectbox('VM', list(targets), format_func=lambda t: f'{targets[t]} ({t.removeprefix("windows:")})',
                              key='history_target')
        runs = history.runs(target)
        if backend:
            allowed = {r.run_reference.record_id for r in shared_rows}
            runs = [r for r in runs if r['run_id'] in allowed]
            if not runs:
                st.info('No assessments yet for this verified target and registration epoch.')
                return
        # Rounds record drift as they scan; this fills in runs recorded before the page existed. Idempotent, and done
        # once per browser session, because comparing every run on every page view grows with the history.
        checked = st.session_state.setdefault('history_drift_checked', set())
        for run in runs:
            if run['run_id'] not in checked:
                history.record_drift(run['run_id'])
                checked.add(run['run_id'])

        st.subheader('Assessment history')
        st.dataframe([{'Assessed (MYT)': myt(r['created_at'], FULL), 'Run': r['run_id'][:8],
                       'Evidence': {'Live': 'Live (WinRM)', 'Imported': 'Imported file'}[r['evidence']],
                       'Controls': r['controls'], 'Compliant': r['compliant'], 'Non-compliant': r['non_compliant'],
                       'Unknown': r['unknown'], 'Error': r['error'],
                       'Compliance of evaluated': '—' if r['compliance_percent'] is None
                       else f"{r['compliance_percent']:.0f}%"} for r in reversed(runs)], hide_index=True)
        st.caption('Compliance is among evaluated controls (Compliant + Non-compliant); Unknown/Error are shown '
                   'separately and never counted as passes.')

        st.subheader('Detected configuration drift')
        records = history.drift_records(target)
        if backend:
            records = [r for r in records if r['previous_run_id'] in allowed and r['current_run_id'] in allowed]
        if not records:
            st.info('No drift detected between consecutive assessments.')
        else:
            regressions = sum(r['change'] == 'Regression' for r in records)
            if regressions:
                st.warning(f'{regressions} regression(s): a control that was compliant became non-compliant.')
            st.dataframe([{'Detected (MYT)': myt(r['detected_at'], FULL),
                           'Control': r['control_id'], 'Title': r['title'], 'Before': _value(r['before']),
                           'After': _value(r['after']), 'Change': r['change'],
                           'Runs': r['previous_run_id'][:8] + ' → ' + r['current_run_id'][:8]} for r in records],
                         hide_index=True)

        if len(runs) >= 2:
            st.subheader('Compare two assessments')
            left, right = st.columns(2)
            ids = [r['run_id'] for r in runs]
            labels = {r['run_id']: _label(r) for r in runs}
            before = left.selectbox('Earlier', ids, index=len(ids) - 2, format_func=labels.get, key='history_before')
            after = right.selectbox('Later', ids, index=len(ids) - 1, format_func=labels.get, key='history_after')
            if before == after:
                st.info('Choose two different assessments.')
            else:
                rows = history.compare(before, after)
                show_all = st.checkbox('Show unchanged controls', key='history_all')
                shown = rows if show_all else [r for r in rows if r['change'] != 'Unchanged']
                st.dataframe([{'Control': r['control_id'], 'Title': r['title'],
                               'Before': _value(r['before']), 'After': _value(r['after']), 'Change': r['change']}
                              for r in shown] or [{'Change': 'No differences'}], hide_index=True)
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('History: ' + md_escape(exc))
