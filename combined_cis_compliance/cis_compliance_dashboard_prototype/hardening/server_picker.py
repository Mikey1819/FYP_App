"""The Server dropdown on Overview and History: every saved server, Windows Server 2022 and Ubuntu 22.04.

It starts on the connected server. Choosing another one only reads its stored records (system/viewing.py); acting on a
server still needs a connection on the Servers page, and the Agentic hardening page always shows the connected one.
"""
from dataclasses import dataclass

import streamlit as st

from .connection_view import LIVE_TARGET, connected_session
from .servers import ServerRegistry
from .ui import md_escape
from system import config
from system.bootstrap import CONNECTION_KEY, active_backend

SYSTEMS = {'windows': 'Windows Server 2022', 'ubuntu': 'Ubuntu 22.04 LTS'}


@dataclass(frozen=True)
class Choice:
    platform: str
    machine_identity: str
    hostname: str
    connected: bool
    reader: object = None        # Ubuntu: the connected backend, or a read-only view of its records.
    connection_id: str | None = None


def _options(servers_path):
    """Saved servers, plus the connected one if it is not saved (for example a target set up by a test)."""
    found = {}
    if servers_path is not None:
        try:
            for s in ServerRegistry(servers_path).all():
                found[(s.platform, s.machine_identity)] = (s.hostname, s)
        except (OSError, ValueError):
            pass
    try:
        session = connected_session()
    except AttributeError:  # A stand-in connection service that cannot report its session.
        session = None
    if session is not None:
        found.setdefault((session.identity.platform, session.identity.machine_identity), (session.identity.hostname, None))
        here = (session.identity.platform, session.identity.machine_identity)
    else:
        target = st.session_state.get(LIVE_TARGET)
        here = ('windows', target.machine_uuid.lower()) if target is not None else None
        if here:
            found.setdefault(here, (target.hostname, None))
    return found, here


def choose_server(key, servers_path=None):
    """The server whose records the page shows, or None when there is none to choose (the page then lists what its
    store holds, as the Windows project did). `servers_path` is the saved-servers file; without it only the connected
    server is offered."""
    found, here = _options(servers_path)
    if not found:
        return None
    keys = list(found)
    if here in found:
        keys.remove(here)
        keys.insert(0, here)

    def label(k):
        return (f'{found[k][0]} · {SYSTEMS[k[0]]} · {k[1]}' + (' (connected)' if k == here else ''))
    platform, identity = st.selectbox('Server', keys, format_func=label, key=key,
                                      help='Every saved server. Another server is shown read-only from its stored records; '
                                           'to act on it, connect to it on the Servers page.')
    hostname, saved = found[(platform, identity)]
    connected = (platform, identity) == here
    if platform != 'ubuntu':
        return Choice(platform, identity, hostname, connected)
    if connected:
        return Choice(platform, identity, hostname, True, active_backend(st.session_state),
                      st.session_state.get(CONNECTION_KEY))
    from system.ledger import CoordinationLedger
    from system.viewing import ubuntu_view
    view = ubuntu_view(CoordinationLedger(config.PATHS.coordination), saved, config.PATHS.ubuntu_imports) if saved else None
    if view is None:
        st.info(f'No records yet for {md_escape(hostname)}.')
    return Choice(platform, identity, hostname, False, view, view.connection_id if view else None)
