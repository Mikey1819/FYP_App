"""Overview page (report Figure 4.11): posture, risk distribution, top risks and recent activity."""
from collections import Counter
from pathlib import Path
import sqlite3

import altair as alt
import pandas as pd
import streamlit as st

from .action_library import actions_for
from .agentic import verdict_kind
from .domain import summarise
from .framework import AssessmentRuns
from .history import HistoryService
from .import_storage import ImportedEvidenceStore
from .remediation import RemediationStore
from .risk import analyse
from .ui import md_escape, myt
from system.bootstrap import CONNECTION_KEY
from system.history import active_history
from .server_picker import choose_server

LEVELS = ('Critical', 'High', 'Moderate', 'Low')
# Ordinal warm ramp for the cartoon theme, darker = more severe. Bars carry a black outline, so the palest
# level stays visible on the cream page.
SEVERITY_RAMP = {'light': ('#9D0208', '#D62828', '#F77F00', '#FCBF49'),
                 'dark': ('#D62828', '#F77F00', '#FCBF49', '#FFE08A')}
OUTLINE = '#1C1C1C'
# Secondary text ink per theme: labels never wear the series colour.
TEXT_INK = {'light': '#52514e', 'dark': '#c3c2b7'}
METER_INK = '#1C1C1C'  # Meter fill: the theme's black line colour.
STATUS = {'awaiting_approval': 'Awaiting approval', 'no_fix_proposed': 'No fix proposed',
          'no_findings': 'No findings', 'collection_failed': 'Scan failed', 'scan_not_handed_off': 'Scan not validated',
          'incomplete': 'Stopped early', 'finish': 'Finished', 'next_round': 'Next round recommended',
          'remediation_review': 'Needs review', 'fallback': 'Executed without AI', 'settle_scan': 'Settled',
          'completed': 'Hardening complete', 'not_complete': 'Not complete yet'}
COMPLETED = 'workspace_completed'  # The message after Complete hardening (Agentic hardening), shown once here.
AREAS = ('Account Policies', 'Local Security Options', 'Windows Defender Firewall', 'Advanced Audit Policy',
         'Remote Desktop Services')


def _theme():
    try:
        return 'dark' if st.context.theme.type == 'dark' else 'light'
    except AttributeError:  # Older Streamlit without theme context.
        return 'light'


def risk_distribution_chart(ranked):
    counts = Counter(f.level for f in ranked)
    data = pd.DataFrame({'Level': LEVELS, 'Findings': [counts.get(level, 0) for level in LEVELS]})
    scale = alt.Scale(domain=list(LEVELS), range=list(SEVERITY_RAMP[_theme()]))
    base = alt.Chart(data).encode(
        y=alt.Y('Level:N', sort=list(LEVELS), title=None, axis=alt.Axis(labelFontSize=13, ticks=False, domain=False)),
        x=alt.X('Findings:Q', title='Non-compliant findings', axis=alt.Axis(tickMinStep=1, grid=True)),
        tooltip=[alt.Tooltip('Level:N'), alt.Tooltip('Findings:Q')])
    bars = base.mark_bar(cornerRadiusEnd=6, size=22, stroke=OUTLINE, strokeWidth=1.5).encode(
        color=alt.Color('Level:N', scale=scale, legend=None))
    # Count labels in text ink beside each bar: identity never rests on colour alone.
    labels = base.mark_text(align='left', dx=6, fontSize=13, color=TEXT_INK[_theme()]).encode(text='Findings:Q')
    return (bars + labels).properties(height=170)


# The area table's columns, shared by the Windows and Ubuntu Overview.
AREA_COLUMNS = {
    'Compliance': st.column_config.ProgressColumn('Compliance', min_value=0, max_value=100, format='%d%%',
                                                  color=METER_INK, width='small', help='Compliant among evaluated controls'),
    'Compliant': st.column_config.NumberColumn('✓', width='small', help='Compliant'),
    'Non-compliant': st.column_config.NumberColumn('✗', width='small', help='Non-compliant'),
    'Unknown / Error': st.column_config.NumberColumn('?', width='small', help='Unknown or Error'),
    'Controls': st.column_config.NumberColumn('Total', width='small')}


def area_table(results):
    rows = []
    for area in AREAS:
        in_area = [r for r in results if r.control.area == area]
        if not in_area:
            continue
        s = summarise(tuple(in_area))
        rows.append({'Security area': area, 'Compliance': round(s.compliance_percent or 0),
                     'Compliant': s.compliant, 'Non-compliant': s.non_compliant,
                     'Unknown / Error': s.unknown + s.errors, 'Controls': s.selected})
    return rows


def _round_target(runtime, r):
    """A failed scan has no run; a verification round belongs to the VM of the run it remediated."""
    run_id = r['framework_run_id'] if r['kind'] == 'assessment' else r.get('remediated_run_id')
    return runtime.get(run_id).target_id if run_id else None


def latest_assessment_run(store, runtime, target):
    """The scan of this server's newest assessment round: the only round whose fixes can still be decided."""
    latest = next((r for r in store.recent_rounds(200) if r['kind'] == 'assessment' and r['framework_run_id']
                   and _round_target(runtime, r) == target), None)
    return latest['framework_run_id'] if latest else None


def awaiting_you(store, runtime, target):
    """Undecided fixes the administrator can still act on: those of this server's newest assessment round.
    Proposals of older rounds belong to scans that a later round replaced; the Agentic page never offers them, so
    counting them would overstate the work waiting."""
    run_id = latest_assessment_run(store, runtime, target)
    return sum(p['decision'] is None for p in store.for_run(run_id)) if run_id else 0


def activity_row(r, store, latest_run_id=None):
    """One line per stored round, in the terms an administrator would log it."""
    outcome = r.get('outcome') or {}
    status = STATUS.get(outcome.get('outcome'), (outcome.get('outcome') or '—').replace('_', ' '))
    if r['kind'] == 'assessment':
        proposed, deferred = len(outcome.get('proposals') or []), len(outcome.get('skipped') or [])
        result = (f'{proposed} fix(es) proposed, {deferred} deferred' if r['framework_run_id']
                  else 'Scan did not complete')
        activity = 'Assessment round'
        if outcome.get('outcome') == 'awaiting_approval':  # The stored state is as of the round; decisions came later.
            undecided = sum(p['decision'] is None for p in store.for_run(r['framework_run_id']))
            if not undecided:
                status = 'All decided'
            elif latest_run_id is None or r['framework_run_id'] == latest_run_id:
                status = f'{undecided} awaiting approval'
            else:  # Its fixes can no longer be decided: a later round rescanned and proposed again.
                status = 'Replaced by a later round'
    else:
        kinds = Counter(verdict_kind(v['verdict']) for v in r['verdicts'] if v['control_id'])
        result = ', '.join(f'{n} {kind}' for kind, n in kinds.items()) or 'Nothing executed'
        activity = 'Remediation and verification'
        if r['kind'] == 'settle_scan':  # The read-only rescan that settled an uncertain fix (Agentic hardening).
            activity, result = 'Rescan to settle an uncertain fix', ', '.join(v['control_id'] for v in r['verdicts'])
        elif r['kind'] == 'final_scan':  # The scan before completing a hardening session.
            activity, result = 'Final scan before completing', outcome.get('reason', '')
    return {'Time': myt(r['created_at']), 'Activity': activity, 'Result': result, 'Status': status}


NEW_SERVER = 'overview_new_server'  # Set by pairing when the server is new to this laptop; shown until its first scan.


def _new_server_note(platform, machine_identity):
    """The first-pairing message (both systems), in place of "No assessments yet". True if it was shown. Also for a
    saved server re-paired with a new SSH host key (13 November 2026): the ledger then records it as a new
    registration with no scan yet, so it reads as a new server, saying why."""
    new = st.session_state.get(NEW_SERVER)
    if not new or new['key'].casefold() != (platform + ':' + machine_identity).casefold():
        return _new_key_note(platform, machine_identity)
    st.success(f"**New server paired: {md_escape(new['hostname'])}** ({md_escape(new['system'])}). This is the first "
               'time it has been paired with this program, so nothing has been scanned yet. Open **Agentic hardening** '
               'and start the first round to see its compliance.', icon=':material/new_releases:')
    return True


def no_scan_note(platform, machine_identity, hostname=None):
    """What every page shows while a server has no assessment (administrator, 13 November 2026: never "No assessments
    yet"): the first-pairing message, the re-paired-with-a-new-key message, or otherwise the same new-server message
    without claiming a first pairing."""
    if machine_identity and _new_server_note(platform, machine_identity):
        return
    system = 'Ubuntu 22.04 LTS' if platform == 'ubuntu' else 'Windows Server 2022'
    name = f'New server paired: {md_escape(hostname)}' if hostname else 'New server paired'
    st.success(f'**{name}** ({system}). Nothing has been scanned on it yet. Open **Agentic hardening** and start the '
               'first round to see its compliance.', icon=':material/new_releases:')


def _new_key_note(platform, machine_identity):
    """The new-server message for a server whose current registration came from a re-pair with a new host key."""
    from system.bootstrap import SERVICE_KEY
    ledger = getattr(st.session_state.get(SERVICE_KEY), 'ledger', None)
    try:
        record = ledger.registration(platform, machine_identity) if ledger is not None else None
    except Exception:  # an older ledger, or none: say nothing special
        record = None
    if not record or not record.get('key_changed_at'):
        return False
    system = 'Ubuntu 22.04 LTS' if platform == 'ubuntu' else 'Windows Server 2022'
    st.success(f"**New server paired: {md_escape(record['hostname'])}** ({system}). It was re-paired with a new SSH "
               'host key, so it is recorded as a new registration and nothing has been scanned under it yet. Open '
               '**Agentic hardening** and start the first round to see its compliance.', icon=':material/new_releases:')
    return True


def _scanned(platform, machine_identity):
    """The server has a scan now: the first-pairing message has done its job."""
    new = st.session_state.get(NEW_SERVER)
    if new and new['key'].casefold() == (platform + ':' + machine_identity).casefold():
        st.session_state.pop(NEW_SERVER, None)


def render_overview(database_path: Path, servers_path: Path | None = None):
    st.title('Overview')
    completed = st.session_state.pop(COMPLETED, None)
    if completed:
        st.success(completed, icon=':material/verified:')
    try:
        choice = choose_server('overview_server', servers_path)
        if choice is not None and choice.platform == 'ubuntu':
            if choice.reader is not None:
                _render_ubuntu(choice.reader, choice.connection_id, connected=choice.connected)
            return
        backend, shared_rows = (active_history(st.session_state) if choice is None or choice.connected
                                else (None, ()))
        if backend and backend.session.identity.platform != 'windows':  # Connected Ubuntu, not in the dropdown.
            _render_ubuntu(backend, st.session_state[CONNECTION_KEY])
            return
        imports = ImportedEvidenceStore(database_path)
        runtime = AssessmentRuns(imports)
        store = RemediationStore(database_path.with_name(database_path.stem + '_agentic.sqlite3'), imports)
        history = HistoryService(runtime, store)
        targets = history.targets()
        if choice is not None:
            targets = {t: name for t, name in targets.items() if t == 'windows:' + choice.machine_identity}
        elif backend:
            targets = {t: name for t, name in targets.items() if t == backend.session.target_id}
        here = (('windows', choice.machine_identity) if choice is not None else
                ('windows', backend.session.identity.machine_identity) if backend else None)
        name = choice.hostname if choice is not None else (backend.session.identity.hostname if backend else None)
        if not targets:
            no_scan_note(*(here or ('windows', '')), name)
            return
        target = (next(iter(targets)) if choice is not None or len(targets) == 1 else
                  st.selectbox('Server', list(targets), format_func=lambda t: f'{targets[t]} ({t.removeprefix("windows:")})',
                               key='overview_target'))
        runs = history.runs(target)
        if backend:
            allowed = {r.run_reference.record_id for r in shared_rows}
            runs = [r for r in runs if r['run_id'] in allowed]
            if not runs:
                no_scan_note(*(here or ('windows', '')), name)
                return
        if here:
            _scanned(*here)
        if backend:  # connected: the register of this server and registration, as on Ubuntu (14 November 2026)
            _register(backend, st.session_state[CONNECTION_KEY])
        latest = runs[-1]
        record = imports.get(runtime.get(latest['run_id']).evidence_sha256)
        results = record.assessment.results
        ranked = analyse(record, history.previous_records(latest['run_id']))
        st.caption(f"{targets[target]} · latest assessment {myt(latest['created_at'])} · "
                   f"{latest['controls']} controls · CIS Windows Server 2022 Stand-alone v2.0.0, Level 1")

        previous = runs[-2] if len(runs) > 1 else None
        compliance = latest['compliance_percent']
        delta = (None if previous is None or compliance is None or previous['compliance_percent'] is None
                 else f"{compliance - previous['compliance_percent']:+.0f} pts vs previous")
        proposals = [p for p in store.all_proposals() if p['proposal']['framework_run_id'] in
                     {r['run_id'] for r in runs}]
        waiting = awaiting_you(store, runtime, target)
        verified = sum(p['verdict'] == 'Verified compliant' for p in proposals)  # All rounds: this is history.
        tiles = st.columns(5)
        tiles[0].metric('Compliance (evaluated)', '—' if compliance is None else f'{compliance:.0f}%', delta)
        tiles[1].metric('Non-compliant', latest['non_compliant'])
        tiles[2].metric('Unknown / Error', latest['unknown'] + latest['error'])
        top = ranked[0] if ranked else None
        tiles[3].metric('Highest risk', '—' if top is None else top.score, None if top is None else top.level,
                        delta_color='off')
        tiles[4].metric('Fixes awaiting you', waiting, f'{verified} verified so far', delta_color='off',
                        help='Undecided fixes in the latest round, the ones you can still approve or reject.')
        regressions = [d for d in history.drift_records(target)
                       if d['current_run_id'] == latest['run_id'] and d['change'] == 'Regression']
        if regressions:
            st.warning(f"{len(regressions)} control(s) regressed since the previous assessment: "
                       + ', '.join(d['control_id'] for d in regressions) + '. See History and drift.',
                       icon=':material/trending_down:')

        left, right = st.columns([1, 1.5])
        with left:
            st.subheader('Risk distribution')
            if ranked:
                st.altair_chart(risk_distribution_chart(ranked), width='stretch')
                st.caption('Darker = more severe. Scores from the deterministic risk engine (R = 6I+5E+4P+3L+2D).')
            else:
                st.success('No scored non-compliant findings.')
        with right:
            st.subheader('Compliance by security area')
            st.dataframe(area_table(results), hide_index=True, column_config=AREA_COLUMNS)

        st.subheader('Top risks')
        if ranked:
            st.dataframe([{'Priority': f.priority, 'Control': f.control_id, 'Title': f.title, 'Risk': f.score,
                           'Level': f.level,
                           'Fix': (actions_for(f.control_id)[0].title if actions_for(f.control_id)
                                   else 'Manual: not automated')} for f in ranked[:5]],
                         hide_index=True)
        else:
            st.caption('Nothing to prioritise.')

        st.subheader('Activity')
        rounds = [r for r in store.recent_rounds(20) if _round_target(runtime, r) in (None, target)][:8]
        if rounds:
            latest_run = latest_assessment_run(store, runtime, target)
            st.dataframe([activity_row(r, store, latest_run) for r in rounds], hide_index=True)
        else:
            st.caption('No agentic rounds yet for this server.')
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Overview: ' + md_escape(exc))


def _ubuntu_area_table(areas):
    """Compliance by security area, as the Windows table: areas in benchmark order, counts per status."""
    rows = []
    for area in dict.fromkeys(area for area, _ in areas):
        statuses = [status.value for a, status in areas if a == area]
        compliant, failing = statuses.count('Compliant'), statuses.count('Non-Compliant')
        evaluated = compliant + failing
        rows.append({'Security area': area, 'Compliance': round(100 * compliant / evaluated) if evaluated else 0,
                     'Compliant': compliant, 'Non-compliant': failing,
                     'Unknown / Error': len(statuses) - evaluated, 'Controls': len(statuses)})
    return rows


def _register(backend, connection):
    """The live validation register (both systems; Windows since 14 November 2026): which controls were proven on
    this server. Shown on Overview once the server has an assessment; read-only, from the stored records."""
    from .agentic_view import live_register
    if hasattr(backend, 'live_validation'):
        live_register(backend, connection)


def _render_ubuntu(backend, connection, *, connected=True):
    """The Windows Overview's sections for an Ubuntu 22.04 server, from the Ubuntu backend's read model."""
    data = backend.overview(connection) if hasattr(backend, 'overview') else None
    here = ('ubuntu', getattr(backend.session.identity, 'machine_identity', '') or '')
    if data is None:
        no_scan_note(*here, getattr(backend.session.identity, 'hostname', None))
        return
    _scanned(*here)
    s, previous, ranked = data['summary'], data['previous'], data['findings']
    _register(backend, connection)  # moved here from Agentic hardening (2026-11-13); needs an assessment
    st.caption(f"{md_escape(backend.session.identity.hostname)} · latest assessment {myt(s.collected_at)} · "
               f"{s.selected} controls · CIS Ubuntu Linux 22.04 LTS v2.0.0, Level 1 Server"
               + ('' if connected else ' · read-only, not connected'))
    compliance = s.compliance_percent
    delta = (None if previous is None or compliance is None or previous.compliance_percent is None
             else f"{compliance - previous.compliance_percent:+.0f} pts vs previous")
    tiles = st.columns(5)
    tiles[0].metric('Compliance (evaluated)', '—' if compliance is None else f'{compliance:.0f}%', delta)
    tiles[1].metric('Non-compliant', s.non_compliant)
    tiles[2].metric('Unknown / Error', s.unknown + s.error)
    top = ranked[0] if ranked else None
    tiles[3].metric('Highest risk', '—' if top is None else top.score, None if top is None else top.level,
                    delta_color='off')
    tiles[4].metric('Fixes awaiting you', data['awaiting'], f"{data['verified']} verified so far", delta_color='off',
                    help='Undecided fixes in the latest round, the ones you can still approve or reject.')
    if data['regressions']:
        st.warning(f"{len(data['regressions'])} control(s) regressed since the previous assessment: "
                   + ', '.join(data['regressions']) + '. See History and drift.', icon=':material/trending_down:')
    left, right = st.columns([1, 1.5])
    with left:
        st.subheader('Risk distribution')
        if ranked:
            st.altair_chart(risk_distribution_chart(ranked), width='stretch')
            st.caption('Darker = more severe. Scores from the deterministic risk engine (R = 6I+5E+4P+3L+2D).')
        else:
            st.success('No scored non-compliant findings.')
    with right:
        st.subheader('Compliance by security area')
        st.dataframe(_ubuntu_area_table(data['areas']), hide_index=True, column_config=AREA_COLUMNS)
    st.subheader('Top risks')
    if ranked:
        st.dataframe([{'Priority': f.rank, 'Control': f.control_id, 'Title': data['titles'].get(f.control_id, ''),
                       'Risk': f.score, 'Level': f.level,
                       'Fix': data['fixes'].get(f.control_id, 'Manual review (no registered fix)')} for f in ranked[:5]],
                     hide_index=True)
    else:
        st.caption('Nothing to prioritise.')
    st.subheader('Activity')
    if data['activity']:
        st.dataframe([dict(row, Time=myt(row['Time'])) for row in data['activity']], hide_index=True)
    else:
        st.caption('No agentic rounds yet for this server.')
