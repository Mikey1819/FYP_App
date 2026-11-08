"""Read-only views of a saved server's records, for the Overview and History pages, whether connected or not.

The Agentic hardening page acts only on the connected server. Overview and History may show any saved server: a
Windows server's records are read from the Windows store directly, and an Ubuntu server's through its backend's read
models with a session that has no channel, so nothing can reach the server from such a view.
"""
from uuid import uuid4

from .connection import VerifiedSession
from .identity import VerifiedIdentity


class ReadOnlyHistory:
    """Only the read models of a backend: history, overview, drift and comparisons. No command, no channel."""

    def __init__(self, backend):
        self._backend = backend

    @property
    def session(self):
        return self._backend.session

    @property
    def connection_id(self):
        return self._backend.session.connection_session_id

    def history(self, target_id=None, limit=50):
        return self._backend.history(target_id, limit)

    def overview(self, connection_session_id):
        return self._backend.overview(connection_session_id)

    def drift(self):
        return self._backend.drift()

    def compare(self, before, after):
        return self._backend.compare(before, after)

    def compare_rows(self, before, after):
        return self._backend.compare_rows(before, after)


def ubuntu_view(ledger, saved, database_path):
    """A read-only view of a saved Ubuntu server's records, from its registration in the coordination ledger (target,
    registration epoch, hostname, host key). None when the ledger has no registration for it."""
    from backends.ubuntu.adapter import UbuntuBackend
    registration = ledger.registration('ubuntu', saved.machine_identity)
    if registration is None:
        return None
    host, _, port = registration['endpoint'].rpartition(':')
    session = VerifiedSession('view:' + uuid4().hex,
                              VerifiedIdentity('ubuntu', registration['hostname'], saved.machine_identity, '22.04', 'ssh',
                                               registration['fingerprint']),
                              registration['target_id'], registration['epoch'], saved.username, host, int(port), None)
    return ReadOnlyHistory(UbuntuBackend(database_path, session=session, ledger=ledger))
