"""What every Ubuntu page shows until Ubuntu is linked."""
import streamlit as st

from hardening.connection_view import render_connection

NOT_LINKED = ('Ubuntu Linux workspace. Checks for Ubuntu are not linked to this program yet, so nothing is scanned '
              'or changed on this server from here.')


def render_not_linked(title, *, key, will_show):
    st.title(title)
    target = render_connection(key=key)
    st.info(NOT_LINKED, icon=':material/info:')
    st.caption('When Ubuntu is linked, this page will ' + will_show)
    return target
