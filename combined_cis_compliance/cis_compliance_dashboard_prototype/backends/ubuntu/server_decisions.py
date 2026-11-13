"""Reviewed per-server decisions for Ubuntu, recorded by the administrator on the Ubuntu page (13 November 2026).

Two fixes need a decision about the server that no scan can make for the administrator:
- `firewall_manager`: the server's firewall is managed by UFW ('ufw'), or not ('none'). The UFW fixes (4.1.3, 4.1.4,
  4.1.7) write UFW's rules; on a server firewalled by nftables or firewalld they could conflict and cut the laptop off.
  The collector still checks for competing managers on every scan.
- `avahi_2_1_2`: CIS 2.1.2 allows removing avahi-daemon or keeping it with its socket and service stopped and masked;
  removing it also removes packages that depend on it. 'mask' records the administrator's choice to keep and mask it;
  'none' leaves 2.1.2 without a fix.

They were registered in code for one machine only (system/config.py, the first lab VM), so a new VM could never plan
2.1.2, 4.1.4 or 4.1.7. Those code registrations still count; any other server gets its decision here, keyed by its
verified machine ID, with the administrator's name and the time. Records are append-only; the latest counts.
"""
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3

CHOICES = {'firewall_manager': ('ufw', 'none'), 'avahi_2_1_2': ('mask', 'none')}
_MACHINE = re.compile(r'[0-9a-f]{32}')


def store_path():
    from system.config import PATHS
    return Path(PATHS.ubuntu_imports).with_name('ubuntu_server_decisions.sqlite3')


def _registered(machine_id, key):
    from system.config import UBUNTU_AVAHI_RETENTION, UBUNTU_FIREWALL_REGISTRATIONS
    return (UBUNTU_FIREWALL_REGISTRATIONS if key == 'firewall_manager' else UBUNTU_AVAHI_RETENTION).get(machine_id)


def decision(machine_id, key):
    """The decision in force for this server: the code registration, else the latest recorded one, else None."""
    registered = _registered(machine_id, key)
    if registered is not None:
        return registered
    path = store_path()
    if not path.exists():
        return None  # nothing recorded yet; reading never creates the store
    record = ServerDecisions(path).latest(machine_id).get(key)
    return record['value'] if record else None


def source(machine_id, key):
    """'code' (system/config.py), 'recorded' (on the page) or None."""
    if _registered(machine_id, key) is not None:
        return 'code'
    path = store_path()
    return 'recorded' if path.exists() and key in ServerDecisions(path).latest(machine_id) else None


class ServerDecisions:
    def __init__(self, path):
        self.path = Path(path)
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS decisions (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT, machine_id TEXT NOT NULL, decision TEXT NOT NULL,
                value TEXT NOT NULL, operator TEXT NOT NULL, decided_at TEXT NOT NULL)''')

    def record(self, machine_id, key, value, *, operator):
        operator = (operator or '').strip()
        if not _MACHINE.fullmatch(str(machine_id)):
            raise ValueError('Unknown server.')
        if value not in CHOICES.get(key, ()):
            raise ValueError('Unknown decision.')
        if not operator or len(operator) > 64:
            raise ValueError('Your name is recorded with each decision (up to 64 characters).')
        stamp = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            db.execute('INSERT INTO decisions (machine_id, decision, value, operator, decided_at) VALUES (?,?,?,?,?)',
                       (machine_id, key, value, operator, stamp))
        return stamp

    def latest(self, machine_id):
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            rows = db.execute('SELECT decision, value, operator, decided_at FROM decisions WHERE machine_id=? '
                              'ORDER BY sequence', (machine_id,)).fetchall()
        return {key: {'value': value, 'operator': operator, 'decided_at': at} for key, value, operator, at in rows}
