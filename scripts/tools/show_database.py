"""Read-only viewer for the dashboard's SQLite databases: what is stored, in readable form.

    python scripts/tools/show_database.py                      overview: files, tables, latest scans and rounds
    python scripts/tools/show_database.py scans [--limit N]    stored scans with their compliance summary
    python scripts/tools/show_database.py scan ID              one scan, control by control (digest or run ID prefix)
    python scripts/tools/show_database.py rounds [--limit N]   agentic rounds with outcome and proposals
    python scripts/tools/show_database.py round ID [--log]     one round: plan, decisions, verdicts (--log: agent steps)
    python scripts/tools/show_database.py proposals [--limit N]
    python scripts/tools/show_database.py drift [--limit N]
    python scripts/tools/show_database.py table NAME [--limit N]   raw rows of any table, JSON decoded

Every file is opened with SQLite's read-only mode, so this tool cannot create, change or delete anything.
`--database` takes the imported-evidence file; the framework and agentic files sit next to it with the same
names the dashboard uses. Times are shown in Malaysia time (MYT); storage stays UTC.
"""
import argparse
import base64
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'cis_compliance_dashboard_prototype'))
from hardening.databases import imports_database
from hardening.ui import FULL, myt

STATUSES = ('Compliant', 'Non-Compliant', 'Unknown', 'Error')


def paths(imports):
    """The three files, named exactly as the dashboard names them (framework.py, agentic_view.py)."""
    imports = Path(imports)
    return {'imports': imports, 'framework': imports.with_name(imports.stem + '_framework.sqlite3'),
            'agentic': imports.with_name(imports.stem + '_agentic.sqlite3')}


def connect(path):
    """Read-only connection, or None when the file does not exist (mode=ro never creates one)."""
    if not Path(path).exists():
        return None
    return sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)


def decode(value):
    """Stored payloads are JSON text or JSON bytes; anything else is shown as it is."""
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8-sig')
        except UnicodeDecodeError:
            return f'<{len(value)} bytes>'
    if isinstance(value, str) and value[:1] in '{[':
        try:
            return json.loads(value)
        except ValueError:
            pass
    return value


def shown(value):
    """An absent value is a policy that is not configured (decision D5), not the word None."""
    return 'not configured' if value is None else value


def when(value):
    try:
        return myt(value, FULL)
    except (TypeError, ValueError):
        return str(value)


def table(headers, rows, empty='(none)'):
    rows = [['' if c is None else str(c) for c in row] for row in rows]
    if not rows:
        print('  ' + empty)
        return
    widths = [min(max(len(h), *(len(r[i]) for r in rows)), 60) for i, h in enumerate(headers)]
    line = lambda cells: '  ' + '  '.join(c[:w].ljust(w) for c, w in zip(cells, widths))
    print(line(headers))
    print(line(['-' * w for w in widths]))
    for row in rows:
        print(line(row))


def heading(text):
    print('\n' + text + '\n' + '=' * len(text))


def counts(snapshot):
    tally = {s: sum(r['status'] == s for r in snapshot) for s in STATUSES}
    evaluated = tally['Compliant'] + tally['Non-Compliant']
    percent = f"{100 * tally['Compliant'] / evaluated:.0f}%" if evaluated else '-'
    return tally, percent


class Viewer:
    def __init__(self, imports):
        self.paths = paths(imports)
        self.db = {name: connect(path) for name, path in self.paths.items()}

    def close(self):
        for db in self.db.values():
            if db is not None:
                db.close()

    def rows(self, name, sql, params=()):
        db = self.db[name]
        if db is None:
            return []
        try:
            return db.execute(sql, params).fetchall()
        except sqlite3.OperationalError:  # Table not created yet (e.g. no round has run).
            return []

    def run_ids(self):
        """Scan digest -> framework run ID."""
        return {d: r for r, d in self.rows('framework', 'SELECT run_id, digest FROM framework_runs')}

    # ------------------------------------------------------------------ overview
    def overview(self):
        heading('Database files')
        for name, path in self.paths.items():
            db = self.db[name]
            print(f'\n{name}: {path}' + ('' if db else '  (not found)'))
            if db:
                tables = [t for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' "
                                                   "AND name NOT LIKE 'sqlite_%' ORDER BY name")]
                table(('table', 'rows'), [(t, db.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0])
                                          for t in tables])
        self.scans(5)
        self.rounds(5)

    # ------------------------------------------------------------------ scans
    def scans(self, limit):
        heading(f'Latest {limit} scans (newest first)')
        runs = self.run_ids()
        out = []
        for digest, host, collected, snapshot in self.rows(
                'imports', 'SELECT digest, hostname, collected_at, snapshot FROM imported_assessments '
                'ORDER BY collected_at DESC LIMIT ?', (limit,)):
            results = decode(snapshot)
            tally, percent = counts(results)
            mode = results[0]['evidence']['mode'] if results else '-'
            out.append((when(collected), host, digest[:12], (runs.get(digest) or '-')[:12], mode, len(results),
                        tally['Compliant'], tally['Non-Compliant'], tally['Unknown'], tally['Error'], percent))
        table(('collected (MYT)', 'host', 'digest', 'run ID', 'mode', 'controls', 'pass', 'fail', 'unknown',
               'error', 'compliance'), out)

    def scan(self, prefix):
        runs = self.run_ids()
        select = 'SELECT digest, hostname, target_id, collected_at, snapshot FROM imported_assessments '
        found = self.rows('imports', select + 'WHERE digest LIKE ?', (prefix + '%',))
        if not found:  # Not a digest: try it as a framework run ID.
            digests = [d for d, r in runs.items() if r.startswith(prefix)]
            found = self.rows('imports', select + 'WHERE digest = ?', (digests[0],)) if len(digests) == 1 else []
        if len(found) != 1:
            sys.exit(f'{len(found) or "No"} scans match {prefix!r}; give a longer digest or run ID prefix.')
        digest, host, target, collected, snapshot = found[0]
        results = decode(snapshot)
        tally, percent = counts(results)
        heading(f'Scan {digest[:12]}')
        print(f'  host {host}, target {target}\n  collected {when(collected)} MYT, run ID {runs.get(digest, "-")}')
        print(f'  SHA-256 {digest}')
        print('  ' + ', '.join(f'{s} {n}' for s, n in tally.items()) + f', compliance {percent}\n')
        table(('control', 'title', 'area', 'status', 'observed', 'required'),
              [(r['control']['control_id'], r['control']['title'], r['control']['area'], r['status'],
                shown(r['evidence']['value']) if r['evidence']['error'] is None
                else 'error: ' + str(r['evidence']['error']),
                f"{r['control']['rule']['operator']} {r['control']['rule']['expected']}") for r in results])

    # ------------------------------------------------------------------ rounds
    def all_rounds(self):
        return [dict(round_id=i, created_at=c, **decode(p)) for i, c, p in self.rows(
            'agentic', 'SELECT id, created_at, payload FROM agentic_rounds ORDER BY rowid DESC')]

    def rounds(self, limit):
        heading(f'Latest {limit} agentic rounds (newest first)')
        out = []
        for r in self.all_rounds()[:limit]:
            outcome = r.get('outcome') or {}
            detail = (f"{len(outcome.get('proposals') or [])} proposed" if r['kind'] == 'assessment'
                      else f"{len(r.get('verdicts') or [])} verdict(s)")
            out.append((when(r['created_at']), r['round_id'][:12], r['kind'], outcome.get('outcome', '-'), detail))
        table(('created (MYT)', 'round ID', 'kind', 'outcome', 'detail'), out)

    def proposal_rows(self, sql_where='', params=()):
        out = []
        for pid, run_id, payload in self.rows('agentic', 'SELECT id, run_id, payload FROM rem_proposals '
                                              + sql_where + ' ORDER BY rowid DESC', params):
            p = decode(payload)
            decision = self.rows('agentic', 'SELECT decision, payload FROM rem_decisions WHERE id=?', (pid,))
            verdict = self.rows('agentic', 'SELECT verdict FROM rem_receipts WHERE id=?', (pid,))
            by = ''
            if decision:
                record = decode(decision[0][1])
                by = record.get('approved_by') or record.get('operator') or ''
            out.append(dict(created=when(p['created_at']), id=pid[:12], run=run_id[:12], rank=p['rank'],
                            control=p['control_id'], action=p['action_id'],
                            change=f"{shown(p['expected_before'])} -> {p['value']}", risk=p.get('risk_score'),
                            decision=(decision[0][0] + (f' by {by}' if by else '')) if decision else 'undecided',
                            verdict=verdict[0][0] if verdict else '-', reason=p['reason']))
        return out

    def round(self, prefix, show_log):
        matches = [r for r in self.all_rounds() if r['round_id'].startswith(prefix)]
        if len(matches) != 1:
            sys.exit(f'{len(matches) or "No"} rounds match {prefix!r}; give a longer round ID prefix.')
        r = matches[0]
        outcome = r.get('outcome') or {}
        heading(f"Round {r['round_id']} ({r['kind']})")
        print(f"  created {when(r['created_at'])} MYT, session {r['session_id']}")
        run = r.get('framework_run_id') or r.get('remediated_run_id')
        print(f"  scan run {run or '-'}" + (' (remediated)' if r['kind'] != 'assessment' else ''))
        print(f"  outcome: {outcome.get('outcome', '-')}")
        print(f"  {outcome.get('reason', '')}")
        if r['kind'] == 'assessment':
            heading('Plan: proposed fixes')
            ids = outcome.get('proposals') or []
            rows = [p for p in self.proposal_rows('WHERE run_id=?', (r['framework_run_id'] or '',))
                    if any(i.startswith(p['id']) for i in ids)]
            table(('rank', 'control', 'action', 'change', 'risk', 'decision', 'verdict', 'reason'),
                  [(p['rank'], p['control'], p['action'], p['change'], p['risk'], p['decision'], p['verdict'],
                    p['reason']) for p in sorted(rows, key=lambda p: p['rank'])])
            heading('Plan: deferred')
            table(('control', 'reason code', 'reason'), [(s['control_id'], s['reason_code'], s.get('reason', ''))
                                                          for s in outcome.get('skipped') or []])
            attention = ((r.get('analysis_outcome') or {}).get('attention')) or []
            if attention:
                heading('Analysis Agent: flagged for attention')
                table(('control', 'reason'), [(a['control_id'], a.get('reason', '')) for a in attention])
        else:
            heading('Verdicts')
            table(('control', 'action', 'verdict'), [(v.get('control_id'), v.get('action_id'), v['verdict'])
                                                     for v in r.get('verdicts') or []])
        self.agent_runs(r['round_id'], show_log)

    def agent_runs(self, round_id, show_log):
        heading('Agent runs in this round')
        runs = self.rows('agentic', "SELECT run_id, created_at, payload FROM investigation_runs "
                         "WHERE json_extract(payload, '$.team_id') = ? ORDER BY rowid", (round_id,))
        out = []
        for run_id, created, payload in runs:
            meta = decode(payload)
            finished = self.rows('agentic', "SELECT payload FROM investigation_events WHERE run_id=? AND "
                                 "kind='finished'", (run_id,))
            f = decode(finished[0][0]) if finished else {}
            out.append((when(created), meta.get('agent_role', meta.get('scenario')), run_id[:12],
                        f.get('status', 'running?'), f.get('tool_calls', '-'), f.get('duration_seconds', '-')))
        table(('started (MYT)', 'agent', 'run ID', 'status', 'tool calls', 'seconds'), out)
        if not show_log:
            if runs:
                print('\n  Add --log to see every step the agents took.')
            return
        for run_id, _, payload in runs:
            heading(f"Steps: {decode(payload).get('agent_role', '')} ({run_id[:12]})")
            for kind, created, event in self.rows('agentic', 'SELECT kind, created_at, payload FROM '
                                                  'investigation_events WHERE run_id=? ORDER BY sequence', (run_id,)):
                e = decode(event)
                text = {'request': lambda: f"model asked (step {e.get('step')})",
                        'tool': lambda: f"{e['name']}({compact(without_target(e.get('arguments')))}) -> "
                                        f"{compact(e.get('result'))}",
                        'tool_rejected': lambda: f"REFUSED {e['name']}({compact(without_target(e.get('arguments')))}"
                                                 f"): {e.get('error')}",
                        'nudge': lambda: 'reminded to answer with a tool call: ' + ', '.join(e.get('available', [])),
                        'finished': lambda: f"finished: {e.get('status')} ({e.get('summary', '')})"}
                print(f"  {myt(created, '%H:%M:%S')}  " + text.get(kind, lambda: f'{kind}: {compact(e)}')())

    # ------------------------------------------------------------------ other views
    def proposals(self, limit):
        heading(f'Latest {limit} proposals (newest first)')
        table(('created (MYT)', 'proposal', 'control', 'action', 'change', 'risk', 'decision', 'verdict'),
              [(p['created'], p['id'], p['control'], p['action'], p['change'], p['risk'], p['decision'], p['verdict'])
               for p in self.proposal_rows()[:limit]])

    def drift(self, limit):
        heading(f'Latest {limit} drift records (newest first)')
        table(('detected (MYT)', 'control', 'title', 'before', 'after', 'status change', 'kind'),
              [(when(d['detected_at']), d['control_id'], d.get('title', ''), shown(d['before']), shown(d['after']),
                f"{d['status_before']} -> {d['status_after']}", d['change'])
               for d in (decode(p) for (p,) in self.rows('agentic', 'SELECT payload FROM drift_records '
                                                         'ORDER BY rowid DESC LIMIT ?', (limit,)))])

    def raw_table(self, name, limit):
        owner = next((n for n, db in self.db.items() if db and db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()), None)
        if owner is None:
            sys.exit(f'No table named {name!r}. Run without arguments to list the tables.')
        cursor = self.db[owner].execute(f'SELECT * FROM "{name}" ORDER BY rowid DESC LIMIT ?', (limit,))
        columns = [c[0] for c in cursor.description]
        heading(f'{name} in {owner} ({limit} newest rows)')
        for row in cursor.fetchall():
            print()
            for column, value in zip(columns, row):
                value = decode(value)
                if column == 'raw' or (isinstance(value, dict) and 'before_evidence' in value):
                    value = shorten_evidence(value)
                elif column == 'snapshot' and isinstance(value, list):
                    value = f'<{len(value)} control results; see them with: scan {row[0][:12]}>'
                text = json.dumps(value, indent=2, default=str) if isinstance(value, (dict, list)) else str(value)
                print(f'  {column}: ' + text.replace('\n', '\n    '))


def without_target(arguments):
    return {k: v for k, v in arguments.items() if k != 'target_id'} if isinstance(arguments, dict) else arguments


def compact(value, limit=160):
    text = json.dumps(value, default=str) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[:limit] + '...'


def shorten_evidence(value):
    """Raw collector output and receipt evidence are long; show their size, not every byte."""
    if isinstance(value, dict) and 'before_evidence' in value:
        return {k: (f'<base64 evidence, {len(base64.b64decode(v))} bytes>' if k.endswith('_evidence') and v else v)
                for k, v in value.items()}
    if isinstance(value, dict):
        return {k: (f'<{len(v)} entries>' if isinstance(v, list) else v) for k, v in value.items()}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--database', type=Path, default=None,
                        help='imported-evidence database (default: the dashboard\'s, see CIS_DASHBOARD_DB)')
    commands = parser.add_subparsers(dest='command')
    for name, default in (('scans', 10), ('rounds', 10), ('proposals', 20), ('drift', 20)):
        commands.add_parser(name).add_argument('--limit', type=int, default=default)
    commands.add_parser('scan').add_argument('id')
    one = commands.add_parser('round')
    one.add_argument('id')
    one.add_argument('--log', action='store_true', help='show every agent step')
    raw = commands.add_parser('table')
    raw.add_argument('name')
    raw.add_argument('--limit', type=int, default=5)
    args = parser.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    viewer = Viewer(args.database or imports_database())
    try:
        if not any(viewer.db.values()):
            sys.exit(f'No database found next to {viewer.paths["imports"]}.')
        {'scans': lambda: viewer.scans(args.limit), 'rounds': lambda: viewer.rounds(args.limit),
         'proposals': lambda: viewer.proposals(args.limit), 'drift': lambda: viewer.drift(args.limit),
         'scan': lambda: viewer.scan(args.id), 'round': lambda: viewer.round(args.id, args.log),
         'table': lambda: viewer.raw_table(args.name, args.limit), None: viewer.overview}[args.command]()
    finally:
        viewer.close()


if __name__ == '__main__':
    main()
