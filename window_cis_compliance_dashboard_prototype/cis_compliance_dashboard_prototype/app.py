"""Agentic hardening workspace. No synthetic seeding; the target is the registered lab VM."""
import streamlit as st
from hardening.agentic_view import render_agentic
from hardening.connection_view import LIVE_TARGET
from hardening.databases import imports_database
from hardening.history_view import render_history
from hardening.ollama_client import OllamaClient, model_available
from hardening.overview_view import render_overview
from hardening.ui import md_escape

st.set_page_config(page_title="VM Hardening Workspace", page_icon=":material/shield:", layout="wide")


@st.cache_data(ttl=30, show_spinner=False)
def _model_ready():
    return model_available()


def agentic_page():
    render_agentic(imports_database())


def overview_page():
    render_overview(imports_database())


def history_page():
    render_history(imports_database())


def _status_panel():
    """Where the workspace stands, on every page: the VM connection and the local model."""
    target = st.session_state.get(LIVE_TARGET)
    st.markdown('**Status**')
    st.markdown(':green-badge[:material/lan: VM connected]  \n' + md_escape(target.hostname) if target
                else ':gray-badge[:material/lan: VM not connected]')
    st.markdown(f':green-badge[:material/memory: {OllamaClient.model} ready]' if _model_ready()
                else f':orange-badge[:material/memory: {OllamaClient.model} unavailable]')
    st.caption('Every change on the VM needs your approval.')


def main():
    pages = st.navigation([st.Page(overview_page, title="Overview", icon=":material/dashboard:", default=True),
                           st.Page(agentic_page, title="Agentic hardening", icon=":material/security:",
                                   url_path="agentic"),
                           st.Page(history_page, title="History and drift", icon=":material/history:",
                                   url_path="history")])
    with st.sidebar:
        st.markdown('### VM Hardening Workspace')
        _status_panel()
    pages.run()


if __name__ == "__main__":
    main()
