"""Complete hardening for Ubuntu (module 1), as on the Windows page: exceptions with a reason, and the completion.

Each Ubuntu control has a program fix, so the only choice is to accept a control that stays open as an exception,
with the administrator's name and a reason. Choices belong to one hardening session (workflow); records are
append-only and the latest per control counts. A session is completed, once, by a final read-only scan in which every
control is Compliant or accepted as an exception; it is then read-only. A later scan decides whether a control is
compliant, never the choice.

The Windows store (`hardening/manual_controls.py`) accepts Windows control IDs only and is not changed, so Ubuntu keeps
its own small store next to the Ubuntu stores.
"""
from contextlib import closing
from datetime import datetime, timezone
import json
import sqlite3

MAX_REASON = 500


def open_items(controls, exceptions):
    """What keeps a session from completing, from one scan's controls (objects with control_id, title, status) and
    the session's exceptions: every control not Compliant and not accepted, with why, in the administrator's terms."""
    items = []
    for c in controls:
        status = c.status.value
        if status == 'Compliant' or c.control_id in exceptions:
            continue
        if status in ('Unknown', 'Error'):
            why = f'{status}: no value could be judged. A new round may read it, or accept it as an exception.'
        else:
            why = 'Still Non-Compliant: approve and execute its fix in the next round, or accept it as an exception.'
        items.append({'control_id': c.control_id, 'title': c.title, 'status': status, 'why': why})
    return items


class CompletionStore:
    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS exceptions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL, workflow_session_id TEXT NOT NULL,
                control_id TEXT NOT NULL, reason TEXT NOT NULL, operator TEXT NOT NULL, round_id TEXT,
                decided_at TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS completions (
                target_id TEXT NOT NULL, workflow_session_id TEXT PRIMARY KEY, operator TEXT NOT NULL,
                final_run_id TEXT NOT NULL, compliant INTEGER NOT NULL, total INTEGER NOT NULL, exceptions TEXT NOT NULL,
                completed_at TEXT NOT NULL)''')

    def accept(self, target_id, workflow, control_id, *, operator, reason, round_id):
        operator, reason = (operator or '').strip(), (reason or '').strip()
        if not operator or len(operator) > 64:
            raise ValueError('Your name is recorded with each exception (up to 64 characters).')
        if not reason:
            raise ValueError('An exception needs a reason.')
        if len(reason) > MAX_REASON:
            raise ValueError(f'The reason is limited to {MAX_REASON} characters.')
        stamp = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('INSERT INTO exceptions (target_id, workflow_session_id, control_id, reason, operator, round_id, '
                       'decided_at) VALUES (?,?,?,?,?,?,?)',
                       (target_id, workflow, control_id, reason, operator, round_id, stamp))
        return stamp

    def exceptions(self, target_id, workflow):
        """{control_id: {reason, operator, round_id, decided_at}} of this session; the latest record counts."""
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            rows = db.execute('SELECT control_id, reason, operator, round_id, decided_at FROM exceptions WHERE '
                              'target_id=? AND workflow_session_id=? ORDER BY sequence', (target_id, workflow)).fetchall()
        return {c: {'reason': r, 'operator': o, 'round_id': i, 'decided_at': d} for c, r, o, i, d in rows}

    def complete(self, target_id, workflow, *, operator, final_run_id, compliant, total, exceptions):
        operator = (operator or '').strip()
        if not operator or len(operator) > 64:
            raise ValueError('Your name is recorded with the completion (up to 64 characters).')
        if self.completion(target_id, workflow) is not None:
            raise ValueError('This hardening session is already completed.')
        stamp = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('INSERT INTO completions VALUES (?,?,?,?,?,?,?,?)',
                       (target_id, workflow, operator, final_run_id, int(compliant), int(total),
                        json.dumps(list(exceptions)), stamp))
        return stamp

    def completion(self, target_id, workflow):
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            row = db.execute('SELECT operator, final_run_id, compliant, total, exceptions, completed_at FROM completions '
                             'WHERE target_id=? AND workflow_session_id=?', (target_id, workflow)).fetchone()
        if row is None:
            return None
        operator, final_run_id, compliant, total, exceptions, completed_at = row
        return {'operator': operator, 'final_run_id': final_run_id, 'compliant': compliant, 'total': total,
                'exceptions': json.loads(exceptions), 'completed_at': completed_at}
