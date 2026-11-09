"""The live server connection, shown on every page that acts on it. Connecting happens on the Servers page.

A server is reached only after pairing it by its one-time code (servers_view.py): the administrator never types its
name, machine UUID, address or SSH fingerprint. The agents then reach it themselves, over PowerShell Remoting on
Windows Server 2022 or SSH on Ubuntu 22.04, through the shared connection service (system/connection.py).
"""
import streamlit as st

from . import background
from .ui import md_escape
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from system.session import clear_target_state

LIVE_TARGET = 'vm_live_target'
LOCKED = 'Locked while work runs on this server, so it is not cut off half-way.'


def disconnect():
    """End this session with the server: nothing changes on it. Its password leaves this session's memory."""
    service = st.session_state.get(SERVICE_KEY)
    connection_id = st.session_state.get(CONNECTION_KEY)
    if service is not None and connection_id:
        try:
            service.disconnect(connection_id)
        except ValueError:
            pass  # Already gone.
    clear_target_state(st.session_state)


def connected_session():
    """The verified session of the connected server, or None."""
    service = st.session_state.get(SERVICE_KEY)
    connection_id = st.session_state.get(CONNECTION_KEY)
    if not (service and connection_id):
        return None
    try:
        session = service.session(connection_id)
    except ValueError:
        clear_target_state(st.session_state)
        return None
    alive = getattr(session.channel, 'alive', None)  # SSH only; a WinRM call opens its own connection each time.
    if alive is not None and not alive():
        disconnect()
        st.warning(f'The connection to {md_escape(session.identity.hostname)} was lost (the server may have '
                   'restarted). Connect again under **Servers > My servers**.')
        return None
    return session


def job_key():
    """The key background work is held under (background.py): the connected server's system and identity."""
    service = st.session_state.get(SERVICE_KEY)
    connection_id = st.session_state.get(CONNECTION_KEY)
    if service and connection_id:
        try:
            identity = service.session(connection_id).identity
        except ValueError:
            return None
        return identity.platform + ':' + identity.machine_identity
    target = st.session_state.get(LIVE_TARGET)  # A Windows target set without the connection service (tests).
    return 'windows:' + target.machine_uuid if target is not None else None


def running_job():
    """The round or execution still running on the connected server, or None."""
    return background.running(job_key())


def render_connection(*, key):
    """Returns the connected target (a WinRM target on Windows, the verified session on Ubuntu), or None. Once
    connected, the target is kept in this session's memory until the administrator disconnects, so switching pages
    never drops the connection. Disconnecting changes nothing on the server."""
    verified = connected_session()
    if verified is not None:
        with st.container(horizontal=True, vertical_alignment='center'):
            st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(verified.identity.hostname)}** · '
                        f'{"Windows Server 2022" if verified.identity.platform == "windows" else "Ubuntu 22.04"} via '
                        f'{verified.identity.transport.upper()} · {md_escape(verified.host)}:{verified.port}')
            busy = running_job() is not None
            if st.button('Disconnect', key=key + '_disconnect', type='tertiary', disabled=busy,
                         help=LOCKED if busy else 'End this session with the server. Nothing changes on the server.'):
                disconnect()
                st.rerun()
        return verified.target if verified.identity.platform == 'windows' else verified
    target = st.session_state.get(LIVE_TARGET)
    if target is not None:  # A Windows target set without the connection service (tests and the Windows-only engine).
        with st.container(horizontal=True, vertical_alignment='center'):
            st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(target.hostname)}** · '
                        f'{md_escape(target.username)} via {md_escape(target.host)}:{target.port} · '
                        f'UUID {md_escape(target.machine_uuid)}')
            busy = running_job() is not None
            if st.button('Disconnect', key=key + '_disconnect', type='tertiary', disabled=busy,
                         help=LOCKED if busy else 'End this session with the server. Nothing changes on the server.'):
                disconnect()
                st.rerun()
        return target
    st.info('No server is connected. Open **Servers** to pair a server by its code, or to connect a saved one.')
    return None
