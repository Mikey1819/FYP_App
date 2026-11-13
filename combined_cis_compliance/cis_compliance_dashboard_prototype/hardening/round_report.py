"""Downloadable report of one agentic round: a self-contained HTML page that prints cleanly to PDF.

Only stored, code-checked records are included: the assessment, the deterministic ranking, the reason codes the
agents chose (as sentences written by code), administrator decisions and verdicts. Optional AI explanations are
unverified text and are left out.
"""
from datetime import datetime, timezone
from html import escape

from .action_library import LIBRARY
from .manual_controls import CHOICES, NOT_AUTOMATED, WHY, setting
from .agentic import ANALYSIS, ORCHESTRATOR, REMEDIATION, SCANNER
from .ui import FULL, myt

BENCHMARK = 'CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0'
EVIDENCE = {'Live': 'Live (WinRM, collected by the Scanner Agent)', 'Imported': 'Imported file'}
AGENT_ORDER = {ORCHESTRATOR: 0, SCANNER: 1, ANALYSIS: 2, REMEDIATION: 3}


def shown(value, status):
    """Display value; an absent policy that fails (decision D5) reads as Not configured."""
    if value is None:
        return 'Not configured' if status == 'Non-Compliant' else '—'
    return repr(value)


def round_analysis(hardening, assessment_round):
    if assessment_round.get('analysis'):
        return assessment_round['analysis']
    for trace in hardening.traces(assessment_round['round_id']):  # Rounds stored before the Analysis Agent loop.
        if trace['agent_role'] == ANALYSIS:
            return next(e['data']['result'] for e in trace['events'] if e['kind'] == 'tool')
    return None


def _table(headers, rows, empty='None.'):
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    head = ''.join(f'<th>{escape(h)}</th>' for h in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{escape(str(cell))}</td>' for cell in row) + '</tr>' for row in rows)
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def _agents(hardening, agent_round):
    rows = []
    for trace in sorted(hardening.traces(agent_round['round_id']), key=lambda t: AGENT_ORDER.get(t['agent_role'], 9)):
        finished = next((e['data'] for e in reversed(trace['events']) if e['kind'] == 'finished'), {})
        rows.append((trace['agent_role'], trace['provenance'], finished.get('status', 'Interrupted'),
                     (finished.get('outcome') or {}).get('outcome', 'No structured decision'),
                     finished.get('tool_calls', 0), sum(e['kind'] == 'tool_rejected' for e in trace['events']),
                     finished.get('duration_seconds', '—')))
    return _table(('Agent', 'Engine', 'Status', 'Outcome', 'Tool calls', 'Rejected calls', 'Seconds'), rows,
                  'No agent traces were stored for this round.')


def _decision(record):
    if record['decision'] is None:
        return 'Awaiting decision', '—'
    made = record['decision_record'] or {}
    who = made.get('approved_by') or made.get('operator', '—')
    when = made.get('approved_at') or made.get('at')
    return record['decision'].capitalize(), f'{who}, {myt(when, FULL)} MYT' if when else who


PHASE_LIMIT_SECONDS = 600  # NFR06: each phase (assessment, or remediation with verification) within 10 minutes.


def duration_text(seconds):
    seconds = round(seconds)
    return f'{seconds // 60} min {seconds % 60:02d} s' if seconds >= 60 else f'{seconds} s'


def phase_time(hardening, phase_round):
    """(total seconds or None, {agent: seconds}) for one phase. The total is from the phase's recorded start to its
    stored end; a round from before starts were recorded uses the Orchestrator's own run time, which covers the
    agents it delegated. A phase without either (for example executed without AI before starts were recorded) has
    no total."""
    agents = {}
    for trace in hardening.traces(phase_round['round_id']):
        finished = next((e['data'] for e in reversed(trace['events']) if e['kind'] == 'finished'), {})
        if finished.get('duration_seconds') is not None:  # A Scanner may run twice in one phase.
            agents[trace['agent_role']] = agents.get(trace['agent_role'], 0) + finished['duration_seconds']
    total = None
    if phase_round.get('started_at'):
        total = (datetime.fromisoformat(phase_round['created_at'])
                 - datetime.fromisoformat(phase_round['started_at'])).total_seconds()
    elif ORCHESTRATOR in agents:
        total = agents[ORCHESTRATOR]
    return total, agents


def phase_line(hardening, phase_round, name):
    """'Assessment took 4 min 53 s (Scanner 37 s · ...), within the 10-minute limit per phase.' or None."""
    total, agents = phase_time(hardening, phase_round)
    if total is None:
        return None
    own = agents.get(ORCHESTRATOR, 0) - sum(s for role, s in agents.items() if role != ORCHESTRATOR)
    parts = [f'{role.replace(" Agent", "")} {duration_text(s)}' for role, s in agents.items() if role != ORCHESTRATOR]
    if own > 1:
        parts.append(f'Orchestrator {"planning" if name == "Assessment" else "review"} {duration_text(own)}')
    limit = ('within the 10-minute limit per phase' if total <= PHASE_LIMIT_SECONDS
             else 'over the 10-minute limit per phase')
    return f'{name} took {duration_text(total)}' + (f' ({" · ".join(parts)})' if parts else '') + f', {limit}.'


def register_section(rows, number):
    """The live-validation register of this server (tools/live_validation_register.register rows), the same section
    in both systems' round reports (Windows since 14 November 2026)."""
    from tools.live_validation_register import NOTE, summary
    table = _table(('Control', 'Status', 'Proven or last attempt (MYT, UTC+8)', 'Approver', 'Request', 'Round'),
                   [(r['control_id'], r['status'],
                     myt(r['evidence']['time'], FULL) if r['evidence'] else '—',
                     (r['evidence'] or {}).get('approver') or '—',
                     (r['evidence'] or {}).get('request_id') or '—',
                     (r['evidence'] or {}).get('round_id') or '—') for r in rows])
    return (f'<h2>{number}. Live validation register</h2><p>{escape(summary(rows))} on this server.</p>'
            f'<p class="muted">{escape(NOTE)} Derived from the stored approvals, outcomes and verification scans; '
            'nothing is typed in.</p>' + table)


def round_report(hardening, rounds, assessment_round, *, now=None, manual=None, completion=None, register=None):
    """HTML for one assessment round and, once run, its remediation and verification. `manual`: the administrator's
    latest choice per control this program does not fix (manual_controls.py). `completion`: the session's completion
    record, which adds the completion section (the completion report). `register`: this server's live-validation
    register rows, printed as the last section, as in the Ubuntu report."""
    now = now or datetime.now(timezone.utc)
    run_id = assessment_round['framework_run_id']
    outcome = assessment_round['outcome']
    parts = []
    record = hardening.runtime.imports.get(hardening.runtime.get(run_id).evidence_sha256) if run_id else None
    if record is not None:
        results = record.assessment.results
        mode = results[0].evidence.mode.value
        counts = {s: sum(r.status.value == s for r in results) for s in ('Compliant', 'Non-Compliant', 'Unknown', 'Error')}
        evaluated = counts['Compliant'] + counts['Non-Compliant']
        title = f'{escape(record.assessment.hostname)} · {len(results)} controls'
        facts = [('Target', f'{record.assessment.hostname} ({record.assessment.target_id})'),
                 ('Benchmark', BENCHMARK), ('Evidence', EVIDENCE.get(mode, mode)),
                 ('Collected (MYT, UTC+8)', myt(record.assessment.collected_at, FULL)),
                 ('Evidence SHA-256', record.assessment.source_sha256)]
        cards = ''.join(f'<div class="card"><b>{n}</b><span>{escape(s)}</span></div>' for s, n in counts.items())
        if evaluated:
            cards += f'<div class="card"><b>{100 * counts["Compliant"] / evaluated:.0f}%</b><span>Compliance of evaluated</span></div>'
    else:
        title, facts, cards, results = 'No assessment', [], '', ()
    facts += [('Round', f"{assessment_round['round_id']} (started {myt(assessment_round['created_at'], FULL)} MYT)"),
              ('Report generated (MYT, UTC+8)', myt(now, FULL))]
    parts.append('<dl>' + ''.join(f'<dt>{escape(k)}</dt><dd>{escape(str(v))}</dd>' for k, v in facts) + '</dl>')
    parts.append(f'<div class="cards">{cards}</div>')
    parts.append(f'<h2>1. Round outcome</h2><p>{escape(outcome["reason"])}</p>')
    if outcome.get('skipped'):
        parts.append('<h3>Deferred by the Orchestrator</h3>'
                     + _table(('Control', 'Reason'), [(s['control_id'], s['reason']) for s in outcome['skipped']]))

    analysis = round_analysis(hardening, assessment_round)
    if analysis:
        parts.append('<h2>2. Risk ranking</h2><p class="muted">Deterministic risk engine: R = 6I + 5E + 4P + 3L + 2D '
                     f'(baselines {escape(analysis["baseline_version"])}). The AI never computes or changes these '
                     'numbers.</p>')
        decided = assessment_round.get('analysis_outcome') or {}
        if decided.get('outcome') == 'analysis_complete' and decided['attention']:
            parts.append('<h3>Analysis Agent: look at these first</h3>'
                         + _table(('Control', 'Why'), [(a['control_id'], a['reason']) for a in decided['attention']]))
        elif decided and decided.get('outcome') != 'analysis_complete':
            parts.append(f'<p class="muted">{escape(decided["reason"])}</p>')
        parts.append(_table(('Rank', 'Control', 'Title', 'Observed', 'Required', 'I', 'E', 'P', 'L', 'D', 'Score', 'Level'),
                            [(n, f['control_id'], f['title'], shown(f['observed'], 'Non-Compliant'), f['rule'],
                              *(f['factors'][k] for k in 'IEPLD'), f['score'], f['level'])
                             for n, f in enumerate(analysis['ranked'], 1)], 'No scored non-compliant findings.'))
        if analysis['gaps']:
            triage = {t['control_id']: t['reason'] for t in decided.get('gap_triage', [])}
            parts.append('<h3>Gaps (not scored, no fix)</h3>' + _table(
                ('Control', 'Status', 'Interpretation', 'Analysis Agent triage'),
                [(g['control_id'], g['status'], g['hint'], triage.get(g['control_id'], '—')) for g in analysis['gaps']]))

    proposals = hardening.store.for_run(run_id) if run_id else []
    rows = []
    for item in proposals:
        p = item['proposal']
        decision, by = _decision(item)
        rows.append((p['rank'], p['control_id'], LIBRARY[p['action_id']].title,
                     f"{shown(p['expected_before'], 'Non-Compliant')} → {p['value']!r}", p['risk_score'], p['reason'],
                     decision, by, item['comment'] or '—', item['verdict'] or '—'))
    parts.append('<h2>3. Proposed fixes and administrator decisions</h2>'
                 + _table(('Rank', 'Control', 'Library action', 'Change', 'Risk', 'Orchestrator reason', 'Decision',
                           'By', 'Comment', 'Result'), rows, 'The Orchestrator proposed no fixes in this round.'))
    not_automated = [r for r in results if r.control.control_id in NOT_AUTOMATED]
    if not_automated:
        manual = manual or {}
        parts.append('<h3>Not fixed by this program</h3><p class="muted">' + escape(WHY) + '</p>' + _table(
            ('Control', 'Title', 'Status this round', 'Needs', 'Administrator choice', 'By', 'When (MYT)', 'Reason'),
            [(r.control.control_id, r.control.title, r.status.value, setting(r.control.control_id),
              *((CHOICES[d['choice']], d['operator'], myt(d['decided_at'], FULL), d['reason'] or '—')
                if (d := manual.get(r.control.control_id)) else ('No choice recorded', '—', '—', '—')))
             for r in not_automated]))

    verification = next((r for r in reversed(rounds) if r['kind'] == 'verification_scan'
                         and r.get('remediated_run_id') == run_id), None) if run_id else None
    parts.append('<h2>4. Remediation and verification</h2>')
    if verification is None:
        parts.append('<p class="muted">Not run yet.</p>')
    else:
        if verification.get('outcome'):
            parts.append(f'<p>{escape(verification["outcome"]["reason"])}</p>')
        parts.append(_table(('Control', 'Action', 'Verdict'),
                            [(v['control_id'] or '—', v['action_id'] or '—', v['verdict']) for v in verification['verdicts']],
                            'Nothing was executed.'))
        if verification['framework_run_id']:
            changed = [c for c in hardening.changes(run_id, verification['framework_run_id']) if c['change'] != 'Unchanged']
            parts.append('<h3>Configuration changes found by the verification rescan</h3>' + _table(
                ('Control', 'Title', 'Before', 'After', 'Change'),
                [(c['control_id'], c['title'], shown(c['before'], c['status_before']), shown(c['after'], c['status_after']),
                  c['change']) for c in changed], 'No changes detected.'))

    times = [line for line in (phase_line(hardening, assessment_round, 'Assessment'),
                               verification and phase_line(hardening, verification, 'Execution and verification'))
             if line]
    parts.append('<h2>5. Agent activity</h2><p class="muted">Every tool call was chosen by an agent and validated by '
                 'code; rejected calls had no effect.</p>' + ''.join(f'<p>{escape(t)}</p>' for t in times)
                 + _agents(hardening, assessment_round))
    if verification is not None:
        parts.append('<h3>Remediation phase</h3>' + _agents(hardening, verification))

    parts.append('<h2>6. All assessed controls</h2>' + _table(
        ('Control', 'Title', 'Area', 'Status', 'Observed'),
        [(r.control.control_id, r.control.title, r.control.area, r.status.value, shown(r.evidence.value, r.status.value))
         for r in results], 'No assessment was collected in this round.'))
    if completion:
        exceptions = completion['exceptions']
        parts.append('<h2>7. Completion</h2><p>The hardening session was completed after a final read-only scan in which '
                     'every control was compliant or accepted as an exception. The session is closed; a later check '
                     'starts a new session.</p>' + _table(
                         ('Completed by', 'When (MYT)', 'Final scan', 'Compliant', 'Accepted as exceptions'),
                         [(completion['operator'], myt(completion['completed_at'], FULL), completion['final_run_id'],
                           f"{completion['compliant']} of {completion['total']}", str(len(exceptions)))]))
        if exceptions:
            parts.append('<h3>Accepted exceptions</h3>' + _table(
                ('Control', 'Title', 'Status in the final scan', 'Reason', 'Accepted by'),
                [(e['control_id'], e['title'], e['status'], e['reason'], e['operator']) for e in exceptions]))
    if register is not None:
        parts.append(register_section(register, 8 if completion else 7))
    return _PAGE.format(title=title, body='\n'.join(parts), benchmark=escape(BENCHMARK))


_PAGE = '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CIS Hardening Round Report</title>
<style>
:root {{ --ink: #1f2328; --muted: #59636e; --line: #d1d9e0; --soft: #f6f8fa; }}
body {{ font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--ink); background: #fff;
        max-width: 1100px; margin: 0 auto; padding: 24px 16px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }} h2 {{ font-size: 17px; margin: 28px 0 8px; border-bottom: 1px solid var(--line);
        padding-bottom: 4px; }} h3 {{ font-size: 14px; margin: 16px 0 6px; }}
.muted {{ color: var(--muted); }}
dl {{ display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px; margin: 12px 0; }}
dt {{ color: var(--muted); }} dd {{ margin: 0; overflow-wrap: anywhere; }}
.cards {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }}
.card {{ border: 1px solid var(--line); border-radius: 6px; padding: 8px 14px; min-width: 110px; }}
.card b {{ display: block; font-size: 20px; }} .card span {{ color: var(--muted); font-size: 12px; }}
table {{ border-collapse: collapse; width: 100%; margin: 6px 0; font-size: 12.5px; }}
th, td {{ border: 1px solid var(--line); padding: 4px 6px; text-align: left; vertical-align: top; }}
th {{ background: var(--soft); }}
@media print {{ body {{ padding: 0; }} h2 {{ break-after: avoid; }} tr {{ break-inside: avoid; }} }}
</style></head><body>
<h1>CIS hardening round report</h1>
<p class="muted">{title} · {benchmark}</p>
{body}
<p class="muted" style="margin-top:32px">Generated by the Agentic AI Framework for Windows Systems Hardening and CIS
Compliance Assessment. Reasons are fixed codes chosen by the agents and checked against the analysis; the sentences
are written by code. Scores come from the deterministic risk engine.</p>
</body></html>
'''
