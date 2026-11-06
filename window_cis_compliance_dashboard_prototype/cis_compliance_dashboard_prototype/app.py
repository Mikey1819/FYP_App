"""Agentic hardening workspace. No synthetic seeding; the target is a saved server the administrator connected to.

The Servers page comes first. Until a server is connected it is the only page: the workspace pages are not in the
menu and cannot be opened by typing their address either (they lead back to Servers). Once a server is connected,
the workspace for that server's operating system opens on Overview, with the same three pages for every system:
Overview, Agentic hardening, and History and drift.
  - Windows Server 2022: the pages in hardening/ (what this program checks today).
  - Ubuntu Linux: the pages in ubuntu/, placeholders until Ubuntu is linked (see ubuntu/__init__.py).
The connected target says which workspace it belongs to (`workspace`: 'windows' for a WinRM target). The system the
server reported at pairing (hardening/system_detect.py) decides whether it may be connected at all.
"""
import streamlit as st
from hardening.agentic_view import render_agentic
from hardening.connection_view import LIVE_TARGET
from hardening.databases import imports_database, servers_database
from hardening.history_view import render_history
from hardening.ollama_client import OllamaClient, model_available
from hardening.overview_view import render_overview
from hardening.servers_view import NOTICE, forget_connection, render_servers
from hardening.ui import CARTOON_CSS, md_escape
from ubuntu import agentic_view as ubuntu_agentic, history_view as ubuntu_history, overview_view as ubuntu_overview

st.set_page_config(page_title="Server Hardening Workspace", page_icon=":material/shield:", layout="wide")

OPENED = 'workspace_opened_for'  # The server whose workspace was opened, so connecting moves to Overview only once.
ARRIVED = 'workspace_arrived'    # The Servers page's "Connected to ..." message, shown after the move.


@st.cache_data(ttl=30, show_spinner=False)
def _model_ready():
    return model_available()


def agentic_page():
    render_agentic(imports_database())


def overview_page():
    render_overview(imports_database())


def servers_page():
    render_servers(servers_database())


def history_page():
    render_history(imports_database())


# The three workspace pages, the same places for every system: (title, icon, address).
PAGES = (('Overview', ':material/dashboard:', 'overview'),
         ('Agentic hardening', ':material/security:', 'agentic'),
         ('History and drift', ':material/history:', 'history'))
# Each system's own pages for those three places, from its own folder.
WORKSPACES = {
    'windows': ('Windows Server 2022', (overview_page, agentic_page, history_page)),
    'ubuntu': ('Ubuntu Linux', (ubuntu_overview.render_overview, ubuntu_agentic.render_agentic,
                                ubuntu_history.render_history)),
}


def workspace_of(target):
    """The workspace for the connected server; None when no server (or a kind with no workspace) is connected."""
    kind = getattr(target, 'workspace', None) if target is not None else None
    return kind if kind in WORKSPACES else None


def _status_panel(target, kind, servers):
    """Where the workspace stands, on every page: the server connection and the local model."""
    st.markdown('**Status**')
    if kind:
        st.markdown(':green-badge[:material/lan: Server connected]  \n' + md_escape(target.hostname))
        st.caption(f'Workspace: {WORKSPACES[kind][0]}')
    else:
        st.markdown(':gray-badge[:material/lan: No server connected]')
        st.caption('Pair or connect a server first. The workspace opens once a server is connected.')
    st.markdown(f':green-badge[:material/memory: {OllamaClient.model} ready]' if _model_ready()
                else f':orange-badge[:material/memory: {OllamaClient.model} unavailable]')
    if kind:
        st.page_link(servers, label='Servers', icon=':material/dns:', help='Switch server, re-pair, or manage who '
                     'can reach this server.')
        if st.button('Disconnect', key='sidebar_disconnect', icon=':material/link_off:',
                     help='End this session with the server. Nothing changes on the server.'):
            forget_connection(f'Disconnected from {target.hostname}. Nothing changed on the server.')
    st.caption('Every change on a server needs your approval.')


def main():
    target = st.session_state.get(LIVE_TARGET)
    kind = workspace_of(target)
    servers = st.Page(servers_page, title="Servers", icon=":material/dns:", url_path="servers",
                      default=kind is None, visibility='visible' if kind is None else 'hidden')
    # Not connected: the workspace addresses still exist, but each one only leads back to the Servers page.
    views = WORKSPACES[kind][1] if kind else [lambda: st.switch_page(servers)] * len(PAGES)
    workspace = [st.Page(view, title=title, icon=icon, url_path=url, default=bool(kind) and url == 'overview',
                         visibility='visible' if kind else 'hidden')
                 for view, (title, icon, url) in zip(views, PAGES)]
    pages = st.navigation(workspace + [servers], position='sidebar' if kind else 'hidden')
    if kind is None:
        st.session_state.pop(OPENED, None)
    elif st.session_state.get(OPENED) != target.machine_uuid:  # Just connected: open the workspace on Overview.
        st.session_state[OPENED] = target.machine_uuid
        if NOTICE in st.session_state:
            st.session_state[ARRIVED] = st.session_state.pop(NOTICE)
        st.switch_page(workspace[0])
    st.html(CARTOON_CSS)
    with st.sidebar:
        st.markdown('### Server Hardening Workspace')
        _status_panel(target, kind, servers)
    if ARRIVED in st.session_state:
        st.toast(md_escape(st.session_state.pop(ARRIVED)), icon=':material/lan:')
    pages.run()


if __name__ == "__main__":
    main()
