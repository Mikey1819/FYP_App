"""Is the connected Windows server still answering? A read-only check of its WinRM port, every few seconds.

A Windows connection is not a live link: each action opens its own WinRM connection, so a server that was powered
off, went to sleep or changed network was only noticed when the next action failed (often the clock check). This
check only opens and closes a TCP connection to the server's WinRM port: no login, no password, nothing sent, nothing
changed. On Ubuntu the SSH connection itself is checked instead (connection_view.connected_session).
"""
from datetime import datetime, timezone
import socket

CHECK_EVERY_SECONDS = 15  # How often the sidebar checks; a full page run reuses a check younger than this.
TIMEOUT_SECONDS = 1.5     # A server on the same network answers in milliseconds.


def answers(host, port, timeout=TIMEOUT_SECONDS):
    """True when something accepts a TCP connection at host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check(previous, key, host, port, *, now=None, probe=None):
    """The new reachability state of this server: dict(key, ok, since, checked_at, changed). `previous` is the last
    state (any server); a check younger than CHECK_EVERY_SECONDS for the same server is reused. `changed` is True when
    the server just stopped or started answering (or was first checked)."""
    now = now or datetime.now(timezone.utc)
    if (previous and previous['key'] == key
            and (now - previous['checked_at']).total_seconds() < CHECK_EVERY_SECONDS):
        return dict(previous, changed=False)
    ok = (probe or answers)(host, port)
    if previous and previous['key'] == key and previous['ok'] == ok:
        return dict(previous, checked_at=now, changed=False)
    return dict(key=key, ok=ok, since=now, checked_at=now, changed=True,
                back=bool(previous and previous['key'] == key and not previous['ok'] and ok))
