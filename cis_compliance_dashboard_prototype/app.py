"""Agentic hardening workspace. No synthetic seeding; the target is the registered lab VM."""
import streamlit as st
from hardening.agentic_view import render_agentic
from hardening.connection_view import LIVE_TARGET
from system.config import PATHS
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from tools.baseline import verify_import_origin
from hardening.history_view import render_history
from hardening.ollama_client import OllamaClient, model_available
from hardening.overview_view import render_overview
from hardening.ui import CARTOON_CSS, md_escape

st.set_page_config(page_title="VM Hardening Workspace", page_icon=":material/shield:", layout="wide")


@st.cache_data(ttl=30, show_spinner=False)
def _model_ready():
    return model_available()


def agentic_page():
    render_agentic(PATHS.windows_imports)


def overview_page():
    render_overview(PATHS.windows_imports)


def history_page():
    render_history(PATHS.windows_imports)


def _status_panel():
    """Where the workspace stands, on every page: the VM connection and the local model."""
    target = st.session_state.get(LIVE_TARGET)
    service = st.session_state.get(SERVICE_KEY)
    connection_id = st.session_state.get(CONNECTION_KEY)
    hostname = service.session(connection_id).identity.hostname if service and connection_id else (target.hostname if target else None)
    st.markdown('**Status**')
    st.markdown(':green-badge[:material/lan: VM connected]  \n' + md_escape(hostname) if hostname
                else ':gray-badge[:material/lan: VM not connected]')
    st.markdown(f':green-badge[:material/memory: {OllamaClient.model} ready]' if _model_ready()
                else f':orange-badge[:material/memory: {OllamaClient.model} unavailable]')
    st.caption('Every change on the VM needs your approval.')


def main():
    verify_import_origin(PATHS.app)
    PATHS.prepare()
    pages = st.navigation([st.Page(overview_page, title="Overview", icon=":material/dashboard:", default=True),
                           st.Page(agentic_page, title="Agentic hardening", icon=":material/security:",
                                   url_path="agentic"),
                           st.Page(history_page, title="History and drift", icon=":material/history:",
                                   url_path="history")])
    st.html(CARTOON_CSS)
    with st.sidebar:
        st.markdown('### VM Hardening Workspace')
        _status_panel()
    pages.run()


if __name__ == "__main__":
    main()
