"""Downloadable report of one Ubuntu round, with the same sections and page as the Windows round report
(`hardening/round_report.py`): a self-contained HTML page that prints cleanly to PDF.

Built from a `WorkspaceSnapshot` and the backend's read-only records only: the assessment, the deterministic
ranking, the Orchestrator's plan (sentences written by code), administrator decisions, results, the verification
scan's changes and the agents' recorded runs. Optional AI explanations are unverified text and are left out.
"""
from datetime import datetime, timezone
from html import escape

from hardening.round_report import _PAGE, _table, register_section
from hardening.ui import FULL, myt

from .components import plan_cards, plan_summary


def _agents(events):
    """One row per recorded agent run, in the order the runs started: what the Windows report lists per trace."""
    runs = {}
    for e in events:
        run = runs.setdefault(e.run, {'role': e.role, 'engine': e.provenance, 'status': 'Interrupted',
                                      'outcome': 'No structured decision', 'calls': 0, 'rejected': 0, 'seconds': []})
        if getattr(e, 'model_seconds', None) is not None:  # module 2: each step's model response time
            run['seconds'].append(f'{e.model_seconds:.1f}' + (' (retried)' if getattr(e, 'model_retried', False) else ''))
        if e.event_kind == 'tool':
            run['calls'] += 1
        elif e.event_kind == 'tool_rejected':
            run['calls'] += 1
            run['rejected'] += 1
        elif e.event_kind == 'finished':
            run['status'] = e.result_summary.split(':', 1)[0]
            run['outcome'] = e.reason_code or 'No structured decision'
    rows = [(r['role'], r['engine'], r['status'], r['outcome'], r['calls'], r['rejected'],
             ', '.join(r['seconds']) or '—') for r in runs.values()]
    return _table(('Agent', 'Engine', 'Status', 'Outcome', 'Tool calls', 'Rejected calls', 'Model seconds per step'), rows,
                  'No agent runs were stored for this round.')


def _register(rows):
    """Section 7: the live-validation register of this server, the same section as in the Windows report."""
    return register_section(rows, 7)


def _completion(record):
    """The completion of the hardening session (module 1): who, when, the final scan and each accepted exception."""
    exceptions = record['exceptions']
    return ('<h2>Hardening completed</h2><dl>' + ''.join(
        f'<dt>{escape(k)}</dt><dd>{escape(str(v))}</dd>' for k, v in (
            ('Completed by', record['operator']), ('Completed (MYT, UTC+8)', myt(record['completed_at'], FULL)),
            ('Final scan', record['final_run_id']),
            ('Result', f"{record['compliant']} of {record['total']} controls compliant, {len(exceptions)} accepted as "
                       'exception(s)'))) + '</dl>'
            + '<p class="muted">The final read-only scan found every other control compliant. An exception is the '
              "administrator's decision with its reason; it never counts as compliant.</p>"
            + _table(('Control', 'Title', 'Status in the final scan', 'Reason', 'Accepted by'),
                     [(e['control_id'], e['title'], e['status'], e['reason'], e['operator']) for e in exceptions],
                     'No exceptions: every control was compliant.'))


def ubuntu_round_report(snapshot, rounds, review, changes, *, now=None, register=None, completion=None):
    """HTML for one Ubuntu assessment round and, once run, its remediation and verification. `rounds` are the
    workflow's (round reference, started at) pairs, `review` the Orchestrator's next-step decision (or None) and
    `changes` the verification scan's changed controls (None before a verification scan). `register`, when given, is
    the server's live-validation register (module 3), printed as section 7; `completion`, the session's completion
    record (module 1), printed first."""
    now = now or datetime.now(timezone.utc)
    s, parts = snapshot.summary, []
    round_id = snapshot.current_round_reference.record_id if snapshot.current_round_reference else '—'
    started = next((at for ref, at in rounds if ref.record_id == round_id), None)
    benchmark = s.catalogue_id if s else 'CIS Ubuntu Linux 22.04 LTS v2.0.0'
    if s is not None:
        counts = {'Compliant': s.compliant, 'Non-Compliant': s.non_compliant, 'Unknown': s.unknown, 'Error': s.error}
        evaluated = s.compliant + s.non_compliant
        title = f'{escape(snapshot.target.hostname)} · {s.selected} controls'
        facts = [('Target', f'{snapshot.target.hostname} ({snapshot.target.reference.target_id})'),
                 ('Benchmark', benchmark), ('Evidence', f'{snapshot.target.evidence_mode} ({snapshot.target.transport})'),
                 ('Collected (MYT, UTC+8)', myt(s.collected_at, FULL)), ('Assessment', s.reference.record_id)]
        cards = ''.join(f'<div class="card"><b>{n}</b><span>{escape(k)}</span></div>' for k, n in counts.items())
        if evaluated:
            cards += f'<div class="card"><b>{100 * s.compliant / evaluated:.0f}%</b><span>Compliance of evaluated</span></div>'
    else:
        title, facts, cards = 'No assessment', [], ''
    facts += [('Round', f'{round_id} (started {myt(started, FULL)} MYT)' if started else round_id),
              ('Report generated (MYT, UTC+8)', myt(now, FULL))]
    parts.append('<dl>' + ''.join(f'<dt>{escape(k)}</dt><dd>{escape(str(v))}</dd>' for k, v in facts) + '</dl>')
    parts.append(f'<div class="cards">{cards}</div>')
    if completion is not None:
        parts.append(_completion(completion))

    if snapshot.plan:
        outcome = plan_summary(snapshot)
    elif s is not None and not s.non_compliant:
        outcome = 'No Non-Compliant control: nothing to plan in this round.'
    else:
        outcome = 'No plan was made in this round.'
    parts.append(f'<h2>1. Round outcome</h2><p>{escape(outcome)}</p>')
    deferred = [(row.control_id, row.decision + ': ' + row.reason) for row in snapshot.plan if row.decision != 'Fix proposed']
    if deferred:
        parts.append('<h3>Deferred by the Orchestrator</h3>' + _table(('Control', 'Reason'), deferred))

    titles = {c.control_id: c.title for c in snapshot.controls}
    parts.append('<h2>2. Risk ranking</h2><p class="muted">Deterministic risk engine: R = 6I + 5E + 4P + 3L + 2D '
                 + (f'({escape(snapshot.findings[0].risk_policy_version)}). ' if snapshot.findings else '')
                 + 'The AI never computes or changes these numbers.</p>')
    flags = [(row.control_id, row.flag) for row in snapshot.plan if row.flag]
    if flags:
        parts.append('<h3>Analysis Agent: look at these first</h3>' + _table(('Control', 'Why'), flags))
    parts.append(_table(('Rank', 'Control', 'Title', 'I', 'E', 'P', 'L', 'D', 'Score', 'Level'),
                        [(f.rank, f.control_id, titles.get(f.control_id, ''), f.I, f.E, f.P, f.L, f.D, f.score, f.level)
                         for f in snapshot.findings], 'No scored non-compliant findings.'))
    gaps = [(c.control_id, c.status.value, c.observed) for c in snapshot.controls if c.status.value in ('Unknown', 'Error')]
    if gaps:
        parts.append('<h3>Gaps (not scored, no fix)</h3>' + _table(('Control', 'Status', 'Sub-checks'), gaps))

    cards_by_id = {c['control_id']: c for c in plan_cards(snapshot)}
    ranks = {f.control_id: f.rank for f in snapshot.findings}
    scores = {f.control_id: f.score for f in snapshot.findings}
    rows = []
    for p in snapshot.proposals:
        if p.kind != 'control_remediation':
            continue
        card = cards_by_id.get(p.control_id, {})
        decision = (p.decision or 'awaiting decision').capitalize()
        rows.append((ranks.get(p.control_id, '—'), p.control_id, p.title, scores.get(p.control_id, '—'),
                     card.get('reason', '—'), decision, p.approved_by or p.rejected_by or '—',
                     '; '.join(f'{text} ({who})' for who, text in p.comments) or '—', card.get('state', '—')))
    parts.append('<h2>3. Proposed fixes and administrator decisions</h2>'
                 + _table(('Rank', 'Control', 'Fix', 'Risk', 'Orchestrator reason', 'Decision', 'By', 'Comment', 'Result'),
                          rows, 'The Orchestrator proposed no fixes in this round.'))

    parts.append('<h2>4. Remediation and verification</h2>')
    executed = {r.proposal_reference for r in snapshot.results}
    verdicts = [(p.control_id or '—', p.title, cards_by_id.get(p.control_id, {}).get('state', '—'))
                for p in snapshot.proposals if p.kind == 'control_remediation' and p.reference in executed]
    if review is None and not verdicts:
        parts.append('<p class="muted">Not run yet.</p>')
    else:
        if review is not None:
            parts.append(f'<p>{escape(review["reason"])}</p>')
        parts.append(_table(('Control', 'Fix', 'Verdict'), verdicts, 'Nothing was executed.'))
    if changes is not None:
        parts.append('<h3>Configuration changes found by the verification rescan</h3>' + _table(
            ('Control', 'Title', 'Before', 'After', 'Change', 'Sub-checks'),
            [(c['control_id'], c['title'], c['before'], c['after'], c['change'], c['subchecks']) for c in changes],
            'No changes detected.'))

    parts.append('<h2>5. Agent activity</h2><p class="muted">Every tool call was chosen by an agent and validated by '
                 'code; rejected calls had no effect.</p>' + _agents(snapshot.events))

    parts.append('<h2>6. All assessed controls</h2>' + _table(
        ('Control', 'Title', 'Area', 'Status', 'Sub-checks'),
        [(c.control_id, c.title, c.area, c.status.value, c.observed) for c in snapshot.controls],
        'No assessment was collected in this round.'))
    if register is not None:
        parts.append(_register(register))
    return _PAGE.format(title=title, body='\n'.join(parts), benchmark=escape(benchmark))
