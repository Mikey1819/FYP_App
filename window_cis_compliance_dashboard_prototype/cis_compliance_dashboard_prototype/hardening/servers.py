"""Saved servers ("My servers"): which machines this laptop works with, and where it last found them.

A server is keyed by its machine UUID, read from the server itself when it was added. Every later connection checks
that the machine answering at the saved address still has that hostname and UUID, so the agents can only act on the
server that was saved. Passwords are never stored. Assessment records are kept elsewhere and are not touched when a
server is removed from this list.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from uuid import UUID

from .winrm_channel import WinRmTarget

MAX_NOTE = 120


@dataclass(frozen=True)
class SavedServer:
    machine_uuid: str
    hostname: str
    os_caption: str
    host: str
    port: int
    username: str
    note: str
    added_at: str
    last_connected_at: str | None
    # Filled by code pairing (docs/design/LAN_PAIRING_DESIGN.md); empty for a server added by address.
    pairing_id: str | None = None
    laptop_address: str | None = None
    paired_at: str | None = None

    @property
    def target_id(self):
        return 'windows:' + self.machine_uuid

    def target(self, password):
        """The connection target for this server; the password exists only in the caller's memory."""
        return WinRmTarget(self.hostname, self.machine_uuid, self.username, password, self.host, self.port)


def _now(now=None):
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


def _uuid(value):
    try:
        return str(UUID(str(value)))
    except ValueError:
        raise ValueError('Invalid machine UUID') from None


def _text(value, label, maximum):
    if type(value) is not str or len(value.strip()) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError(f'{label} must be text of at most {maximum} characters')
    return value.strip()


def _address(host, port):
    host = _text(host, 'Server address', 253)
    if not host or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('A server needs an address and a port between 1 and 65535')
    return host, port


class ServerRegistry:
    COLUMNS = ('machine_uuid', 'hostname', 'os_caption', 'host', 'port', 'username', 'note', 'added_at',
               'last_connected_at', 'pairing_id', 'laptop_address', 'paired_at')

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            tables = {name for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if version not in (0, 1) or (tables and tables != {'servers'}):
                raise ValueError('Unsupported servers database; existing data was not reset')
            db.execute("""CREATE TABLE IF NOT EXISTS servers (
                machine_uuid TEXT PRIMARY KEY, hostname TEXT NOT NULL, os_caption TEXT NOT NULL,
                host TEXT NOT NULL, port INTEGER NOT NULL, username TEXT NOT NULL, note TEXT NOT NULL,
                added_at TEXT NOT NULL, last_connected_at TEXT,
                pairing_id TEXT, laptop_address TEXT, paired_at TEXT)""")
            db.execute('PRAGMA user_version = 1')

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=5)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def all(self):
        """Most recently used first; never-connected servers by when they were added."""
        with self._connection() as db:
            rows = db.execute(f'SELECT {", ".join(self.COLUMNS)} FROM servers '
                              'ORDER BY COALESCE(last_connected_at, added_at) DESC').fetchall()
        return [SavedServer(*row) for row in rows]

    def get(self, machine_uuid):
        with self._connection() as db:
            row = db.execute(f'SELECT {", ".join(self.COLUMNS)} FROM servers WHERE machine_uuid=?',
                             (_uuid(machine_uuid),)).fetchone()
        return SavedServer(*row) if row else None

    def add(self, identity, host, port, username, note='', *, now=None):
        """Save the server that answered (identity from the server itself). The same machine added again keeps its
        record and note and gets the new address. Returns (server, is_new)."""
        machine_uuid = _uuid(identity['machine_uuid'])
        hostname = _text(identity['hostname'], 'Hostname', 63)
        os_caption = _text(identity['os_caption'], 'Operating system', 200)
        host, port = _address(host, port)
        username = _text(username, 'Account', 104)
        note = _text(note, 'Note', MAX_NOTE)
        if not hostname or not username:
            raise ValueError('A server needs a hostname and an account')
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT note FROM servers WHERE machine_uuid=?', (machine_uuid,)).fetchone()
            if existing:
                db.execute('UPDATE servers SET hostname=?, os_caption=?, host=?, port=?, username=?, note=? '
                           'WHERE machine_uuid=?', (hostname, os_caption, host, port, username,
                                                    note or existing[0], machine_uuid))
            else:
                db.execute('INSERT INTO servers (machine_uuid, hostname, os_caption, host, port, username, note, '
                           'added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                           (machine_uuid, hostname, os_caption, host, port, username, note, _now(now)))
        return self.get(machine_uuid), existing is None

    def connected(self, machine_uuid, *, now=None):
        self._update(machine_uuid, 'last_connected_at=?', (_now(now),))

    def paired(self, machine_uuid, pairing_id, laptop_address, *, now=None):
        """Remember this laptop's pairing with the server, so the paired-laptops list can mark "this laptop"."""
        if type(pairing_id) is not str or len(pairing_id) != 32 or any(c not in '0123456789abcdef' for c in pairing_id):
            raise ValueError('Invalid pairing id')
        laptop_address = _text(laptop_address, 'Laptop address', 45)
        self._update(machine_uuid, 'pairing_id=?, laptop_address=?, paired_at=?', (pairing_id, laptop_address, _now(now)))

    def set_note(self, machine_uuid, note):
        self._update(machine_uuid, 'note=?', (_text(note, 'Note', MAX_NOTE),))

    def remove(self, machine_uuid):
        """Forget the server on this laptop. Its assessment history stays in the assessment databases."""
        with self._connection() as db:
            db.execute('DELETE FROM servers WHERE machine_uuid=?', (_uuid(machine_uuid),))

    def _update(self, machine_uuid, assignment, values):
        with self._connection() as db:
            changed = db.execute(f'UPDATE servers SET {assignment} WHERE machine_uuid=?',
                                 (*values, _uuid(machine_uuid))).rowcount
        if not changed:
            raise KeyError(machine_uuid)
