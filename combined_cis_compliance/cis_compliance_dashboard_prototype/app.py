"""Agentic hardening workspace. No synthetic seeding; the target is a saved server the administrator connected to.

This program supports only Windows Server 2022 (stand-alone) and Ubuntu 22.04.5 LTS.

The Servers page comes first. Until a server is connected it is the only page: the workspace pages are not in the
menu and cannot be opened by typing their address either (they lead back to Servers). Once a server is connected,
the workspace opens on Overview, with the same three pages for both systems: Overview, Agentic hardening, and
History and drift. Each page shows the connected system's own content (the shared connection service says which
system it is, from what the server itself reported after login).
"""
from datetime import datetime, timezone

import streamlit as st
from hardening import background
from hardening.agentic_view import render_agentic
from hardening.connection_view import LIVE_TARGET, LOCKED, connected_session, job_key
from system.config import PATHS
from tools.baseline import verify_import_origin
from hardening.history_view import render_history
from hardening.ollama_client import OllamaClient, model_available
from hardening.overview_view import render_overview
from hardening.servers_view import NOTICE, forget_connection, render_servers
from hardening.system_detect import SUPPORTED_SYSTEMS
from hardening.ui import CARTOON_CSS, md_escape

st.set_page_config(page_title="Server Hardening Workspace", page_icon=":material/shield:", layout="wide")

OPENED = 'workspace_opened_for'  # The connection whose workspace was opened, so connecting moves to Overview only once.
ARRIVED = 'workspace_arrived'    # The Servers page's "Connected to ..." message, shown after the move.
SYSTEMS = {'windows': 'Windows Server 2022', 'ubuntu': 'Ubuntu 22.04 LTS'}


@st.cache_data(ttl=30, show_spinner=False)
def _model_ready():
    return model_available()


def agentic_page():
    render_agentic(PATHS.windows_imports)


def overview_page():
    render_overview(PATHS.windows_imports, PATHS.servers)


def history_page():
    render_history(PATHS.windows_imports, PATHS.servers)


def servers_page():
    render_servers(PATHS.servers)


# The three workspace pages, the same places for every system: (view, title, icon, address).
PAGES = ((overview_page, 'Overview', ':material/dashboard:', 'overview'),
         (agentic_page, 'Agentic hardening', ':material/security:', 'agentic'),
         (history_page, 'History and drift', ':material/history:', 'history'))


def connected():
    """(hostname, system, key) of the connected server, or None. The key changes with every new connection."""
    session = connected_session()
    if session is not None:
        return session.identity.hostname, session.identity.platform, session.connection_session_id
    target = st.session_state.get(LIVE_TARGET)  # A Windows target set without the connection service (tests).
    if target is not None:
        return target.hostname, 'windows', target.machine_uuid
    return None


@st.fragment(run_every=3)
def _work_status(key):
    """A round or an execution running on this server, on every page. Reloads the page once it has finished."""
    job = background.running(key)
    if job is None:
        st.rerun()
    seconds = int((datetime.now(timezone.utc) - job.started_at).total_seconds())
    st.markdown(':blue-badge[:material/progress_activity: Agents working]')
    st.caption(f'{md_escape(job.label)}: {seconds // 60} min {seconds % 60:02d} s so far. Other pages can be opened; '
               'the work goes on.')


def _status_panel(server, servers):
    """Where the workspace stands, on every page: the server connection and the local model."""
    st.markdown('**Status**')
    key = job_key() if server else None
    busy = background.running(key) is not None
    if server:
        st.markdown(':green-badge[:material/lan: Server connected]  \n' + md_escape(server[0]))
        st.caption(f'Workspace: {SYSTEMS[server[1]]}')
        if busy:
            _work_status(key)
        elif background.finished(key):
            st.markdown(':green-badge[:material/task_alt: Agents finished]')
            st.caption('Open **Agentic hardening** to see the result.')
    else:
        st.markdown(':gray-badge[:material/lan: No server connected]')
        st.caption('Pair or connect a server first. The workspace opens once a server is connected.')
    st.markdown(f':green-badge[:material/memory: {OllamaClient.model} ready]' if _model_ready()
                else f':orange-badge[:material/memory: {OllamaClient.model} unavailable]')
    if server:
        st.page_link(servers, label='Servers', icon=':material/dns:', help='Switch server, re-pair, or manage who '
                     'can reach this server.')
        if st.button('Disconnect', key='sidebar_disconnect', icon=':material/link_off:', disabled=busy,
                     help=LOCKED if busy else 'End this session with the server. Nothing changes on the server.'):
            forget_connection(f'Disconnected from {server[0]}. Nothing changed on the server.')
    st.caption('Every change on a server needs your approval.')
    st.caption(f'Supported: {SUPPORTED_SYSTEMS}.')


def main():
    verify_import_origin(PATHS.app)
    PATHS.prepare()
    server = connected()
    servers = st.Page(servers_page, title="Servers", icon=":material/dns:", url_path="servers",
                      default=server is None, visibility='visible' if server is None else 'hidden')
    # Not connected: the workspace addresses still exist, but each one only leads back to the Servers page.
    workspace = [st.Page(view if server else (lambda: st.switch_page(servers)), title=title, icon=icon, url_path=url,
                         default=bool(server) and url == 'overview', visibility='visible' if server else 'hidden')
                 for view, title, icon, url in PAGES]
    pages = st.navigation(workspace + [servers], position='sidebar' if server else 'hidden')
    if server is None:
        st.session_state.pop(OPENED, None)
    elif st.session_state.get(OPENED) != server[2]:  # Just connected: open the workspace on Overview.
        st.session_state[OPENED] = server[2]
        if NOTICE in st.session_state:
            st.session_state[ARRIVED] = st.session_state.pop(NOTICE)
        st.switch_page(workspace[0])
    st.html(CARTOON_CSS)
    if ARRIVED in st.session_state:
        st.toast(md_escape(st.session_state.pop(ARRIVED)), icon=':material/lan:')
    pages.run()
    # After the page: the page may just have taken a finished round's result, so the status says what is true now.
    with st.sidebar:
        st.markdown('### Server Hardening Workspace')
        _status_panel(server, servers)


if __name__ == "__main__":
    main()
