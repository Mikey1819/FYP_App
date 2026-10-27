"""Agentic hardening workspace. No synthetic seeding; the target is the registered lab VM."""
import streamlit as st
from hardening.agentic_view import render_agentic
from hardening.databases import imports_database
from hardening.history_view import render_history
from hardening.overview_view import render_overview

st.set_page_config(page_title="VM Hardening Workspace", page_icon="🛡️", layout="wide")


def agentic_page():
    render_agentic(imports_database())


def overview_page():
    render_overview(imports_database())


def history_page():
    render_history(imports_database())


def main():
    with st.sidebar:
        st.title("VM Hardening Workspace")
        st.caption("Scanner, Analysis and Remediation agents coordinated by a local AI Orchestrator. "
                   "Every configuration change needs your approval.")
    st.navigation([st.Page(overview_page, title="Overview", icon="📊", default=True),
                   st.Page(agentic_page, title="Agentic hardening", icon="🤖", url_path="agentic"),
                   st.Page(history_page, title="History and drift", icon="🕒", url_path="history")]).run()


if __name__ == "__main__":
    main()
