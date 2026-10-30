"""Assessment history and configuration drift page (report Figure 4.16, UC07)."""
from pathlib import Path
import sqlite3

import streamlit as st

from .framework import AssessmentOrchestrator
from .history import HistoryService
from .import_storage import ImportedEvidenceStore
from .remediation import RemediationStore

def _label(run):
    return f"{run['created_at'][:19].replace('T', ' ')} UTC · {run['run_id'][:8]}"


def render_history(database_path: Path):
    st.title('History and configuration drift')
    st.caption('Every assessment is an immutable snapshot. Drift compares each assessment with the previous one of '
               'the same VM and records every change once. Changes are compared only when the benchmark source, '
               'profile, rule and collection method are identical.')
    try:
        imports = ImportedEvidenceStore(database_path)
        runtime = AssessmentOrchestrator(imports)
        store = RemediationStore(database_path.with_name(database_path.stem + '_agentic.sqlite3'), imports)
        history = HistoryService(runtime, store)
        targets = history.targets()
        if not targets:
            st.info('No assessments yet. Run an agentic round or a scan first.')
            return
        target = st.selectbox('VM', list(targets), format_func=lambda t: f'{targets[t]} ({t.removeprefix("windows:")})',
                              key='history_target')
        runs = history.runs(target)
        for run in runs:  # Idempotent: fills in drift for any run recorded before this page existed.
            history.record_drift(run['run_id'])

        st.subheader('Assessment history')
        st.dataframe([{'Assessed (UTC)': r['created_at'][:19].replace('T', ' '), 'Run': r['run_id'][:8],
                       'Evidence': {'Live': 'Live (WinRM)', 'Imported': 'Imported file'}[r['evidence']],
                       'Controls': r['controls'], 'Compliant': r['compliant'], 'Non-compliant': r['non_compliant'],
                       'Unknown': r['unknown'], 'Error': r['error'],
                       'Compliance of evaluated': '—' if r['compliance_percent'] is None
                       else f"{r['compliance_percent']:.0f}%"} for r in reversed(runs)], hide_index=True)
        st.caption('Compliance is among evaluated controls (Compliant + Non-compliant); Unknown/Error are shown '
                   'separately and never counted as passes. Older runs may cover fewer controls (5, 12, 16 or 32).')

        st.subheader('Detected configuration drift')
        records = history.drift_records(target)
        if not records:
            st.info('No drift detected between consecutive assessments.')
        else:
            regressions = sum(r['change'] == 'Regression' for r in records)
            if regressions:
                st.warning(f'{regressions} regression(s): a control that was compliant became non-compliant.')
            st.dataframe([{'Detected (UTC)': r['detected_at'][:19].replace('T', ' '),
                           'Control': r['control_id'], 'Title': r['title'], 'Before': repr(r['before']),
                           'After': repr(r['after']), 'Change': r['change'],
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
                               'Before': repr(r['before']), 'After': repr(r['after']), 'Change': r['change']}
                              for r in shown] or [{'Change': 'No differences'}], hide_index=True)
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('History: ' + str(exc))
