"""Agentic hardening workspace. No synthetic seeding; the target is the registered lab VM."""
import streamlit as st
import legacy_app
from hardening.agentic_view import render_agentic

st.set_page_config(page_title="VM Hardening Workspace", page_icon="🛡️", layout="wide")


def agentic_page():
    render_agentic(legacy_app.imports_database())


def main():
    with st.sidebar:
        st.title("VM Hardening Workspace")
        st.caption("Scanner, Analysis and Remediation agents coordinated by a local AI Orchestrator. "
                   "Every configuration change needs your approval.")
    st.navigation([st.Page(agentic_page, title="Agentic hardening", icon="🤖", default=True),
                   st.Page(legacy_app.render, title="Evidence upload (legacy)", icon="📄", url_path="upload")]).run()


if __name__ == "__main__":
    main()
