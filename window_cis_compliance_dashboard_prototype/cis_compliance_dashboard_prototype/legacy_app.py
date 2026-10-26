"""Legacy evidence-upload workflow; a page of app.py and a standalone entry point for its tests."""
import os
from pathlib import Path
import streamlit as st
from hardening.import_view import render_imported_evidence


def imports_database():
    database = Path(os.environ.get("CIS_DASHBOARD_DB", str(Path(__file__).parent / "data" / "preview.sqlite3")))
    return database.with_name(database.stem + "_imports.sqlite3")


def render():
    render_imported_evidence(imports_database())


if __name__ == "__main__":
    st.set_page_config(page_title="VM Hardening Workspace", page_icon="🛡️", layout="wide")
    render()
