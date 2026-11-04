"""The live server connection, shown on every page that acts on it. Connecting happens on the Servers page."""
import streamlit as st

from .ui import md_escape

LIVE_TARGET = 'vm_live_target'


def render_connection(*, key):
    """Returns the connected target, or None. Once connected, the target is kept in this session's memory until the
    administrator disconnects, so switching pages never drops the connection. Disconnecting changes nothing on the
    server: it only forgets the target and its password here."""
    target = st.session_state.get(LIVE_TARGET)
    if target is None:
        return None
    with st.container(horizontal=True, vertical_alignment='center'):
        st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(target.hostname)}** · '
                    f'{md_escape(target.username)} via {md_escape(target.host)}:{target.port} · '
                    f'UUID {md_escape(target.machine_uuid)}')
        if st.button('Disconnect', key=key + '_disconnect', type='tertiary',
                     help='End this session with the server. Nothing changes on the server.'):
            del st.session_state[LIVE_TARGET]
            st.rerun()
    return target
