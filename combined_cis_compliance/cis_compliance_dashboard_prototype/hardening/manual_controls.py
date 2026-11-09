"""Windows controls this program assesses but never changes, how to fix them by hand, and what the administrator chose.

The catalogue's firewall on/off and inbound-block controls (9.2.1, 9.2.2, 9.3.1, 9.3.2) have no library action: changing
them over the network could cut the WinRM connection the agents use. They stay applicable and are reported exactly as
scanned. They are never shown as Not applicable and never counted as passed, so the compliance figure stays honest.

For each one the administrator records a choice: fix it by hand on the server, or accept it as an exception with a
reason. Any other control still open when a hardening session is completed (a rejected fix, an Unknown or Error result)
can be accepted as an exception too. Choices belong to one hardening session: a new session starts with none (earlier
ones stay in their own records and reports). Records are append-only. The latest record per control counts, and
withdrawing a choice adds a record too. A later scan decides whether a control is compliant, never the choice.

Completing a session (Complete hardening, on the Agentic hardening page) needs a final scan in which every control is
compliant or accepted as an exception; the completion is recorded here, once per session.
"""
from contextlib import closing
from datetime import datetime, timezone
import json
import sqlite3

from .action_library import LIBRARY
from .domain import Status
from .server2022_catalogue import CATALOGUE

AUTOMATED = frozenset(action.control_id for action in LIBRARY.values())
CONTROL_IDS = frozenset(c.control_id for c in CATALOGUE)
NOT_AUTOMATED = tuple(c.control_id for c in CATALOGUE if c.control_id not in AUTOMATED)
PROGRAM_FIX, MANUAL_FIX = 'Program fix', 'Manual: not automated'

WHY = ('Assessed, never changed by this program. These settings turn the firewall on and block incoming connections by '
       "default. Changing them over the network could cut the connection this program uses to reach the server, so they "
       'are fixed by hand on the server itself, or accepted as an exception. They still count as Non-Compliant until a '
       'scan finds them compliant.')
CHOICES = {'manual_fix': 'Will fix it by hand on the server', 'exception': 'Accepted as an exception'}
WITHDRAWN = 'withdrawn'
MAX_REASON = 500

# What each control needs, in the words of the Windows dialog that sets it.
_FIREWALL = {'9.2.1': ('Private', 'Firewall state', 'On (recommended)'),
             '9.2.2': ('Private', 'Inbound connections', 'Block (default)'),
             '9.3.1': ('Public', 'Firewall state', 'On (recommended)'),
             '9.3.2': ('Public', 'Inbound connections', 'Block (default)')}


_WORDS = {'Firewall state': {1: 'On', 0: 'Off'}, 'Inbound connections': {1: 'Block', 0: 'Allow'}}


def in_words(control_id, value):
    """The scanned value as the dialog names it (On/Off, Block/Allow), or None when there is no such word."""
    if control_id not in _FIREWALL or type(value) is not int:
        return None
    word = _WORDS[_FIREWALL[control_id][1]].get(value)
    return f'{word} ({value})' if word else None


def setting(control_id):
    """One line: the setting and the value it needs, for this program's not-automated controls."""
    if control_id in _FIREWALL:
        profile, name, value = _FIREWALL[control_id]
        return f'{profile} Profile tab: {name} = {value}'
    return 'See the CIS benchmark text for this control.'


def steps(control_id, *, check='run the next round'):
    """How to fix it by hand on the server. About two minutes; all four firewall settings are in the same dialog.
    `check`: how the administrator then has it scanned (in the Complete hardening panel, the final scan)."""
    if control_id not in _FIREWALL:
        return ('Fix it on the server itself, following the CIS benchmark text for this control.',
                f'Back here, {check}: the scan shows whether it is compliant now.')
    profile, name, value = _FIREWALL[control_id]
    return ('On the server itself (its own screen, not over the network), sign in as Administrator.',
            'Press Win+R, type gpedit.msc and press Enter.',
            'Open Computer Configuration > Windows Settings > Security Settings > Windows Defender Firewall with '
            'Advanced Security.',
            'Right-click "Windows Defender Firewall with Advanced Security - Local Group Policy Object" and choose '
            'Properties.',
            f'On the {profile} Profile tab, set {name} to {value}. The other firewall controls of this program are on the '
            'Private and Public Profile tabs of the same dialog, so all four can be set at once. Click OK.',
            'Open Command Prompt as administrator and run: gpupdate /force',
            f'Back here, {check}: the scan shows whether it is compliant now.',
            "Blocking inbound connections does not cut this program: the server access helper's allow rule for this "
            'laptop still applies.')


def completion_steps(control_id, status):
    """How to close one control that keeps a session from completing (the Complete hardening panel)."""
    final = 'click Run final scan and complete'
    if control_id in NOT_AUTOMATED:
        return steps(control_id, check=final)
    if status in (Status.UNKNOWN.value, Status.ERROR.value):
        return ('Click Run next round: a fresh scan may read it (an Error is often a passing collection problem).',
                'If it was waiting for another control (for example 1.2.1 and 1.2.4 wait for 1.2.2), fix that one '
                'first; this one then gets a value.',
                'If it stays Unknown or Error, check the setting on the server itself, or accept it as an exception '
                'here with your reason.')
    return ('Click Run next round: the scan finds it again and the Orchestrator proposes its fix.',
            'In Fixes, approve the fix, then Execute it. The verification rescan confirms it.',
            f'Back here, {final}. If you would rather keep it as it is, accept it as an exception with your reason.')


def open_items(results, choices):
    """What keeps a hardening session from being completed, from one scan's results and the session's choices: each
    control that is not compliant and not accepted as an exception, with why, in the administrator's terms."""
    items = []
    for result in results:
        control = result.control.control_id
        if result.status == Status.COMPLIANT:
            continue
        choice = (choices.get(control) or {}).get('choice')
        if choice == 'exception':
            continue
        status = result.status.value
        if choice == 'manual_fix':
            why = f'You chose to fix it by hand, but the scan still finds it {status}. Fix it on the server first.'
        elif control in NOT_AUTOMATED:
            why = 'Not fixed by this program: fix it by hand on the server, or accept it as an exception.'
        elif result.status in (Status.UNKNOWN, Status.ERROR):
            why = f'{status}: no value could be judged. A new round may resolve it, or accept it as an exception.'
        else:
            why = 'Still Non-Compliant: approve and execute its fix in the next round, or accept it as an exception.'
        items.append(dict(control_id=control, title=result.control.title, status=status, why=why))
    return items


class ManualDecisionStore:
    """The administrator's choices per hardening session (append-only), and each session's completion."""

    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS manual_decisions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL, control_id TEXT NOT NULL,
                choice TEXT NOT NULL, reason TEXT NOT NULL, operator TEXT NOT NULL, round_id TEXT,
                decided_at TEXT NOT NULL)''')
            # Added when choices became per session; earlier records have none and belong to no session.
            if 'session_id' not in {row[1] for row in db.execute('PRAGMA table_info(manual_decisions)')}:
                db.execute('ALTER TABLE manual_decisions ADD COLUMN session_id TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS completions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL, session_id TEXT NOT NULL,
                operator TEXT NOT NULL, final_run_id TEXT NOT NULL, compliant INTEGER NOT NULL, total INTEGER NOT NULL,
                exceptions TEXT NOT NULL, completed_at TEXT NOT NULL)''')

    def record(self, target_id, control_id, choice, *, operator, reason='', round_id=None, session_id=None):
        operator, reason = (operator or '').strip(), (reason or '').strip()
        if control_id not in CONTROL_IDS:
            raise ValueError('Unknown control.')
        if choice not in CHOICES and choice != WITHDRAWN:
            raise ValueError('Unknown choice.')
        if choice == 'manual_fix' and control_id not in NOT_AUTOMATED:
            raise ValueError('Only controls this program does not fix are fixed by hand; this one has a program fix.')
        if not operator or len(operator) > 64:
            raise ValueError('Your name is recorded with each choice (up to 64 characters).')
        if len(reason) > MAX_REASON:
            raise ValueError(f'The reason is limited to {MAX_REASON} characters.')
        if choice == 'exception' and not reason:
            raise ValueError('An exception needs a reason.')
        if type(target_id) is not str or not target_id:
            raise ValueError('Unknown server.')
        stamp = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('INSERT INTO manual_decisions (target_id, control_id, choice, reason, operator, round_id, '
                       'decided_at, session_id) VALUES (?,?,?,?,?,?,?,?)',
                       (target_id, control_id, choice, reason, operator, round_id, stamp, session_id))
        return stamp

    def latest(self, target_id, session_id=None):
        """{control_id: choice record} for this server (and, given one, this hardening session only); a withdrawn
        choice leaves the control undecided."""
        query = ('SELECT control_id, choice, reason, operator, round_id, decided_at FROM manual_decisions '
                 'WHERE target_id=?' + (' AND session_id=?' if session_id is not None else '') + ' ORDER BY sequence')
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            rows = db.execute(query, (target_id,) + ((session_id,) if session_id is not None else ())).fetchall()
        latest = {}
        for control_id, choice, reason, operator, round_id, decided_at in rows:
            latest[control_id] = dict(choice=choice, reason=reason, operator=operator, round_id=round_id,
                                      decided_at=decided_at)
        return {c: d for c, d in latest.items() if d['choice'] != WITHDRAWN}

    def complete(self, target_id, session_id, *, operator, final_run_id, compliant, total, exceptions):
        """Record that this hardening session is complete, once. `exceptions`: the controls not compliant in the final
        scan, each accepted as an exception (control_id, title, status, reason, operator)."""
        operator = (operator or '').strip()
        if not operator or len(operator) > 64:
            raise ValueError('Your name is recorded with the completion (up to 64 characters).')
        if not session_id or not final_run_id:
            raise ValueError('A completion needs its session and its final scan.')
        if self.completion(target_id, session_id) is not None:
            raise ValueError('This session is already completed.')
        stamp = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('INSERT INTO completions (target_id, session_id, operator, final_run_id, compliant, total, '
                       'exceptions, completed_at) VALUES (?,?,?,?,?,?,?,?)',
                       (target_id, session_id, operator, final_run_id, int(compliant), int(total),
                        json.dumps(list(exceptions)), stamp))
        return stamp

    def completion(self, target_id, session_id):
        """This session's completion record, or None."""
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            row = db.execute('SELECT operator, final_run_id, compliant, total, exceptions, completed_at FROM completions '
                             'WHERE target_id=? AND session_id=? ORDER BY sequence LIMIT 1',
                             (target_id, session_id)).fetchone()
        if row is None:
            return None
        return dict(operator=row[0], final_run_id=row[1], compliant=row[2], total=row[3],
                    exceptions=json.loads(row[4]), completed_at=row[5])
