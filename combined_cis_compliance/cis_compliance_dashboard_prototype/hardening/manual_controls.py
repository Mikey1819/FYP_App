"""Windows controls this program assesses but never changes, how to fix them by hand, and what the administrator chose.

The catalogue's firewall on/off and inbound-block controls (9.2.1, 9.2.2, 9.3.1, 9.3.2) have no library action: changing
them over the network could cut the WinRM connection the agents use. They stay applicable and are reported exactly as
scanned. They are never shown as Not applicable and never counted as passed, so the compliance figure stays honest.

For each one, on each server, the administrator records a choice: fix it by hand on the server, or accept it as an
exception with a reason. Records are append-only. The latest record per control counts, and withdrawing a choice adds a
record too. A later scan decides whether a control is compliant, never the choice.
"""
from contextlib import closing
from datetime import datetime, timezone
import sqlite3

from .action_library import LIBRARY
from .server2022_catalogue import CATALOGUE

AUTOMATED = frozenset(action.control_id for action in LIBRARY.values())
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


def steps(control_id):
    """How to fix it by hand on the server. About two minutes; all four firewall settings are in the same dialog."""
    if control_id not in _FIREWALL:
        return ('Fix it on the server itself, following the CIS benchmark text for this control.',
                'Run the next round: the scan shows whether it is compliant now.')
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
            'Back here, run the next round: the scan shows whether it is compliant now.',
            "Blocking inbound connections does not cut this program: the server access helper's allow rule for this "
            'laptop still applies.')


class ManualDecisionStore:
    """The administrator's choice per server and not-automated control (append-only)."""

    def __init__(self, path):
        self.path = path
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS manual_decisions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL, control_id TEXT NOT NULL,
                choice TEXT NOT NULL, reason TEXT NOT NULL, operator TEXT NOT NULL, round_id TEXT,
                decided_at TEXT NOT NULL)''')

    def record(self, target_id, control_id, choice, *, operator, reason='', round_id=None):
        operator, reason = (operator or '').strip(), (reason or '').strip()
        if control_id not in NOT_AUTOMATED:
            raise ValueError('Only controls this program does not fix take a manual choice.')
        if choice not in CHOICES and choice != WITHDRAWN:
            raise ValueError('Unknown choice.')
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
                       'decided_at) VALUES (?,?,?,?,?,?,?)',
                       (target_id, control_id, choice, reason, operator, round_id, stamp))
        return stamp

    def latest(self, target_id):
        """{control_id: choice record} for this server; a withdrawn choice leaves the control undecided."""
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            rows = db.execute('SELECT control_id, choice, reason, operator, round_id, decided_at FROM manual_decisions '
                              'WHERE target_id=? ORDER BY sequence', (target_id,)).fetchall()
        latest = {}
        for control_id, choice, reason, operator, round_id, decided_at in rows:
            latest[control_id] = dict(choice=choice, reason=reason, operator=operator, round_id=round_id,
                                      decided_at=decided_at)
        return {c: d for c, d in latest.items() if d['choice'] != WITHDRAWN}
