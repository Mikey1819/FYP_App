"""What the agents are doing right now, for the Agentic hardening page while a round or an execution runs.

Read-only, from the investigation log the agents already write (one run per agent, with its events): which agent is
working, which have finished, and the last step the working one completed. Code-written words only; the model's own
text is never shown. Drawn as a row of agent cards in the dashboard's style, the working one animated.
"""
import json
from urllib.parse import quote

from .agentic import ANALYSIS, ORCHESTRATOR, REMEDIATION, SCANNER

# Line icons in the dashboard's cartoon style: black outline, yellow highlight (drawn here; no image files). The
# page's HTML filter removes inline SVG, so each one is drawn as its card's background image, in the style block.
_SVG = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="34" height="34" fill="none" stroke="#1C1C1C" stroke-width="1.8" '
        'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{}</svg>')
ICONS = {
    # The Orchestrator plans and coordinates: a clipboard with its checklist.
    ORCHESTRATOR: _SVG.format('<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" '
                              'fill="#FFFFFF"/><rect x="8" y="2" width="8" height="4" rx="1" fill="#FFC72C"/>'
                              '<path d="M7.5 11.5l1.2 1.2 2-2M7.5 16.5l1.2 1.2 2-2M13 12h4M13 17h4"/>'),
    # The Scanner reads the server: a server with a magnifying glass.
    SCANNER: _SVG.format('<rect x="2.5" y="3" width="15" height="7" rx="1.5" fill="#FFFFFF"/>'
                         '<rect x="2.5" y="12" width="15" height="7" rx="1.5" fill="#FFFFFF"/>'
                         '<path d="M6 6.5h.01M6 15.5h.01"/><circle cx="16.5" cy="16" r="4" fill="#FFC72C"/>'
                         '<path d="M19.5 19l2.5 2.5"/>'),
    # The Analysis Agent reads the risk ranking: a bar chart, its highest bar highlighted.
    ANALYSIS: _SVG.format('<path d="M3 3v18h18"/><rect x="6.5" y="12" width="3" height="6" fill="#FFFFFF"/>'
                          '<rect x="11.5" y="5" width="3" height="13" fill="#FFC72C"/>'
                          '<rect x="16.5" y="9" width="3" height="9" fill="#FFFFFF"/>'),
    # The Remediation Agent applies the approved fixes: a wrench.
    REMEDIATION: _SVG.format('<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 '
                             '7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" '
                             'fill="#FFC72C"/>'),
}
SHORT = {ORCHESTRATOR: 'Orchestrator', SCANNER: 'Scanner', ANALYSIS: 'Analysis', REMEDIATION: 'Remediation'}
# The last step an agent completed, in the administrator's words (its tool names).
STEPS = {
    'delegate_scanner': 'sent the Scanner Agent to collect evidence',
    'delegate_analysis': 'handed the scan to the Analysis Agent',
    'submit_plan': 'submitted its plan of fixes',
    'delegate_remediation': 'handed the approved fixes to the Remediation Agent',
    'delegate_verification': 'sent the Scanner Agent to verify the fixes',
    'submit_review': 'decided the next step',
    'scan_target': "collected the server's settings (read-only)",
    'read_coverage': 'checked that every control has a result',
    'inspect_observation': 'looked at one observation',
    'rescan': 'collected again after an error',
    'handoff_analysis': 'handed the scan over',
    'handoff_verification': 'handed the verification scan over',
    'report_failure': 'reported a collection failure',
    'score_findings': 'read the risk ranking',
    'inspect_finding': 'investigated a finding',
    'check_history': "checked a finding's history",
    'submit_analysis': 'handed in its analysis',
    'list_approved': 'read the approved fixes',
    'precheck': 'prechecked the approved fixes (read-only)',
    'skip_fix': 'skipped a fix that was not ready',
    'execute_fixes': 'applied approved fixes',
    'stop_execution': 'stopped after a failed fix',
    'report_results': 'reported the results',
}


def phase_roles(label):
    """The agents a running job involves, in the order they work, from its label (agentic_view.py)."""
    text = label.lower()
    if 'without ai' in text:
        return (REMEDIATION, SCANNER)  # Run by code in rank order, then verified.
    if 'remediation agent' in text:
        return (ORCHESTRATOR, REMEDIATION, SCANNER)
    if 'round' in text:
        return (ORCHESTRATOR, SCANNER, ANALYSIS)
    return (SCANNER,)  # A read-only scan: a rescan to settle, or the final scan before completing.


def progress(store, since):
    """dict(active=role or None, done={roles}, words=str) for the agent runs started since `since` (a datetime)."""
    stamp = since.isoformat()
    with store._connection() as db:
        runs = db.execute('SELECT run_id, payload FROM investigation_runs WHERE created_at >= ? ORDER BY rowid',
                          (stamp,)).fetchall()
        rows = []
        for run_id, payload in runs:
            events = db.execute('SELECT kind, payload FROM investigation_events WHERE run_id=? ORDER BY sequence',
                                (run_id,)).fetchall()
            rows.append((json.loads(payload).get('agent_role'), events))
    unfinished = [(role, events) for role, events in rows if not any(kind == 'finished' for kind, _ in events)]
    active, events = unfinished[-1] if unfinished else (None, [])
    done = {role for role, events in rows if any(kind == 'finished' for kind, _ in events)} - {active}
    tools = [json.loads(payload).get('name') for kind, payload in events if kind == 'tool']
    if active is None:
        words = 'finishing up'
    elif tools:
        words = 'working · last step: ' + STEPS.get(tools[-1], (tools[-1] or 'a step').replace('_', ' '))
    else:
        words = 'working on its first step'  # A step is logged once done; the first may be a long scan.
    return dict(active=active, done=done, words=words)


CSS = """<style>
.fyp-stage { display: flex; align-items: center; flex-wrap: wrap; row-gap: .6rem; margin: .4rem 0 .8rem; }
.fyp-agent { width: 116px; text-align: center; padding: .55rem .35rem .45rem; background: #FFFFFF; color: #1C1C1C;
  border: 2px solid #1C1C1C; border-radius: 1rem; box-shadow: 3px 3px 0 #1C1C1C; opacity: .5; font-weight: 600;
  font-size: .82rem; line-height: 1.25; }
.fyp-icon { display: block; width: 34px; height: 34px; margin: 0 auto .15rem; background: center / 34px no-repeat; }
.fyp-state { display: block; font-size: .7rem; font-weight: 400; }
.fyp-agent.fyp-done { opacity: 1; background: #E8F6EA; }
.fyp-agent.fyp-active { opacity: 1; background: #FFF4C7; animation: fyp-glow 1.2s ease-in-out infinite; }
.fyp-agent.fyp-active .fyp-icon { animation: fyp-hop .55s ease-in-out infinite alternate; }
.fyp-track { position: relative; flex: 1 1 28px; min-width: 28px; max-width: 90px; height: 4px; margin: 0 .35rem;
  background: repeating-linear-gradient(90deg, #1C1C1C 0 6px, transparent 6px 12px); }
.fyp-track.fyp-live::after, .fyp-track.fyp-back::after { content: ''; position: absolute; top: -6px; width: 14px;
  height: 14px; border-radius: 50%; background: #FFC72C; border: 2px solid #1C1C1C; }
.fyp-track.fyp-live::after { animation: fyp-pass 1.1s linear infinite; }
.fyp-track.fyp-back::after { animation: fyp-pass 1.1s linear infinite reverse; }
@keyframes fyp-hop { from { transform: translateY(0) rotate(-4deg); } to { transform: translateY(-7px) rotate(4deg); } }
@keyframes fyp-glow { 0%, 100% { box-shadow: 3px 3px 0 #1C1C1C; }
  50% { box-shadow: 3px 3px 0 #1C1C1C, 0 0 0 6px rgba(255, 199, 44, .55); } }
@keyframes fyp-pass { from { left: 0; } to { left: calc(100% - 14px); } }
@media (prefers-reduced-motion: reduce) {
  .fyp-agent.fyp-active, .fyp-agent.fyp-active .fyp-icon, .fyp-track::after { animation: none !important; } }
</style>"""


def _icon_class(role):
    return 'fyp-i-' + SHORT[role].lower()


ICON_CSS = '<style>' + ''.join(
    f'.{_icon_class(role)} {{ background-image: url("data:image/svg+xml,{quote(svg)}"); }}' for role, svg in ICONS.items()
) + '</style>'


def stage_html(roles, state):
    """The agent cards with the lines between them. `state` None (no live record, for example Ubuntu): every agent
    shows as taking part and every line carries work."""
    active = state['active'] if state else None
    done = state['done'] if state else set()
    cards = []
    for n, role in enumerate(roles):
        if n:
            # Work travels towards the agent now working; results travel back to the Orchestrator once it works again.
            towards = role == active and active != ORCHESTRATOR
            back = active == ORCHESTRATOR and role in done
            cards.append('<div class="fyp-track%s"></div>' % (
                ' fyp-live' if towards or state is None else ' fyp-back' if back else ''))
        kind, words = (('fyp-active', 'working…') if role == active or state is None else
                       ('fyp-done', 'done ✓') if role in done else ('', 'waiting'))
        cards.append(f'<div class="fyp-agent {kind}"><span class="fyp-icon {_icon_class(role)}"></span>{SHORT[role]}'
                     f'<span class="fyp-state">{words}</span></div>')
    return CSS + ICON_CSS + '<div class="fyp-stage">' + ''.join(cards) + '</div>'
