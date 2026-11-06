"""Downloadable report of one agentic round: a self-contained HTML page that prints cleanly to PDF.

Only stored, code-checked records are included: the assessment, the deterministic ranking, the reason codes the
agents chose (as sentences written by code), administrator decisions and verdicts. Optional AI explanations are
unverified text and are left out.
"""
from datetime import datetime, timezone
from html import escape

from .action_library import LIBRARY
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


def round_report(hardening, rounds, assessment_round, *, now=None):
    """HTML for one assessment round and, once run, its remediation and verification."""
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

    parts.append('<h2>5. Agent activity</h2><p class="muted">Every tool call was chosen by an agent and validated by '
                 'code; rejected calls had no effect.</p>' + _agents(hardening, assessment_round))
    if verification is not None:
        parts.append('<h3>Remediation phase</h3>' + _agents(hardening, verification))

    parts.append('<h2>6. All assessed controls</h2>' + _table(
        ('Control', 'Title', 'Area', 'Status', 'Observed'),
        [(r.control.control_id, r.control.title, r.control.area, r.status.value, shown(r.evidence.value, r.status.value))
         for r in results], 'No assessment was collected in this round.'))
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
