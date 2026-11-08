"""Saved servers ("My servers"): which machines this laptop works with, and where it last found them.

A server is keyed by its system and machine identity, read from the server itself when it was paired: the machine
UUID on Windows Server 2022, /etc/machine-id on Ubuntu 22.04. Every later connection checks that the machine
answering at the saved address still has that hostname and identity (system/connection.py), and on Ubuntu also the
SSH host key pinned at pairing (system/ledger.py), so the agents can only act on the server that was saved.
Passwords are never stored; for an SSH key only its file path is kept. Assessment records are kept elsewhere and are
not touched when a server is removed from this list.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
from uuid import UUID

MAX_NOTE = 120
PLATFORMS = {'windows': 'winrm', 'ubuntu': 'ssh'}  # Each system and the only transport it is reached by.


@dataclass(frozen=True)
class SavedServer:
    platform: str          # 'windows' or 'ubuntu'
    machine_identity: str  # Windows: machine UUID (with dashes). Ubuntu: /etc/machine-id (32 hexadecimal).
    hostname: str
    os_caption: str
    host: str
    port: int
    username: str
    auth: str              # 'password' or 'key' (Ubuntu only)
    key_path: str          # The selected SSH private key file, when auth is 'key'; never the key itself.
    note: str
    added_at: str
    last_connected_at: str | None
    pairing_id: str | None = None
    laptop_address: str | None = None
    paired_at: str | None = None

    @property
    def transport(self):
        return PLATFORMS[self.platform]

    @property
    def key(self):
        """The registry key, one string: '<platform>:<identity>'."""
        return self.platform + ':' + self.machine_identity

    @property
    def system_label(self):
        return 'Windows Server 2022' if self.platform == 'windows' else 'Ubuntu 22.04 LTS'


def _now(now=None):
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()


def identity_of(platform, value):
    """The machine identity in its stored form, or ValueError."""
    if platform not in PLATFORMS:
        raise ValueError('Supported systems are Windows Server 2022 and Ubuntu 22.04')
    try:
        parsed = UUID(str(value))
    except ValueError:
        raise ValueError('Invalid machine identity') from None
    if platform == 'ubuntu':
        if not re.fullmatch(r'[0-9a-f]{32}', str(value)):
            raise ValueError('Ubuntu machine identity must be 32 lowercase hexadecimal characters')
        return parsed.hex
    return str(parsed)


def split_key(key):
    platform, _, identity = str(key).partition(':')
    return platform, identity_of(platform, identity)


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
    COLUMNS = ('platform', 'machine_identity', 'hostname', 'os_caption', 'host', 'port', 'username', 'auth',
               'key_path', 'note', 'added_at', 'last_connected_at', 'pairing_id', 'laptop_address', 'paired_at')

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
                platform TEXT NOT NULL CHECK (platform IN ('windows', 'ubuntu')), machine_identity TEXT NOT NULL,
                hostname TEXT NOT NULL, os_caption TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
                username TEXT NOT NULL, auth TEXT NOT NULL CHECK (auth IN ('password', 'key')), key_path TEXT NOT NULL,
                note TEXT NOT NULL, added_at TEXT NOT NULL, last_connected_at TEXT,
                pairing_id TEXT, laptop_address TEXT, paired_at TEXT,
                PRIMARY KEY (platform, machine_identity))""")
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

    def get(self, platform, machine_identity):
        with self._connection() as db:
            row = db.execute(f'SELECT {", ".join(self.COLUMNS)} FROM servers WHERE platform=? AND machine_identity=?',
                             (platform, identity_of(platform, machine_identity))).fetchone()
        return SavedServer(*row) if row else None

    def add(self, platform, machine_identity, hostname, os_caption, host, port, username, *, auth='password',
            key_path='', note='', now=None):
        """Save the server that was paired (identity from the server itself). The same machine paired again keeps its
        record and note and gets the new address. Returns (server, is_new)."""
        machine_identity = identity_of(platform, machine_identity)
        hostname = _text(hostname, 'Hostname', 63)
        os_caption = _text(os_caption, 'Operating system', 200)
        host, port = _address(host, port)
        username = _text(username, 'Account', 104)
        note = _text(note, 'Note', MAX_NOTE)
        key_path = _text(key_path, 'SSH key path', 260)
        if auth not in ('password', 'key') or (auth == 'key') != bool(key_path) or (auth == 'key' and platform != 'ubuntu'):
            raise ValueError('A Windows server logs in with a password; an Ubuntu server with a password or one SSH key')
        if not hostname or not username:
            raise ValueError('A server needs a hostname and an account')
        with self._connection() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT note FROM servers WHERE platform=? AND machine_identity=?',
                                  (platform, machine_identity)).fetchone()
            if existing:
                db.execute('UPDATE servers SET hostname=?, os_caption=?, host=?, port=?, username=?, auth=?, key_path=?, '
                           'note=? WHERE platform=? AND machine_identity=?',
                           (hostname, os_caption, host, port, username, auth, key_path, note or existing[0], platform,
                            machine_identity))
            else:
                db.execute('INSERT INTO servers (platform, machine_identity, hostname, os_caption, host, port, username, '
                           'auth, key_path, note, added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                           (platform, machine_identity, hostname, os_caption, host, port, username, auth, key_path,
                            note, _now(now)))
        return self.get(platform, machine_identity), existing is None

    def connected(self, platform, machine_identity, *, now=None):
        self._update(platform, machine_identity, 'last_connected_at=?', (_now(now),))

    def paired(self, platform, machine_identity, pairing_id, laptop_address, *, now=None):
        """Remember this laptop's pairing with the server, so the paired-laptops list can mark "this laptop"."""
        if type(pairing_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', pairing_id):
            raise ValueError('Invalid pairing id')
        laptop_address = _text(laptop_address, 'Laptop address', 45)
        self._update(platform, machine_identity, 'pairing_id=?, laptop_address=?, paired_at=?',
                     (pairing_id, laptop_address, _now(now)))

    def set_note(self, platform, machine_identity, note):
        self._update(platform, machine_identity, 'note=?', (_text(note, 'Note', MAX_NOTE),))

    def remove(self, platform, machine_identity):
        """Forget the server on this laptop. Its assessment history stays in the assessment databases."""
        with self._connection() as db:
            db.execute('DELETE FROM servers WHERE platform=? AND machine_identity=?',
                       (platform, identity_of(platform, machine_identity)))

    def _update(self, platform, machine_identity, assignment, values):
        with self._connection() as db:
            changed = db.execute(f'UPDATE servers SET {assignment} WHERE platform=? AND machine_identity=?',
                                 (*values, platform, identity_of(platform, machine_identity))).rowcount
        if not changed:
            raise KeyError(platform + ':' + str(machine_identity))
