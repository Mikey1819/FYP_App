"""Servers page: the saved servers ("My servers"), connecting to one, and adding a new one."""
from pathlib import Path
import sqlite3

import streamlit as st

from .connection_view import LIVE_TARGET, render_connection
from .server_access import helper_bundle, helper_sha256
from .servers import MAX_NOTE, ServerRegistry
from .ui import md_escape, myt
from .winrm_channel import DEFAULT_PORT, ChannelError, LiveScanner, WinRmLogin, probe_identity

PICK = 'servers_pick'
# Plain session keys (not widget keys): set by an action, read on the next run.
SELECT_NEXT = 'servers_select_next'
NOTICE = 'servers_notice'
REMOVING = 'servers_removing'

# What a failed connection to a saved server most likely means, in the administrator's terms.
HINTS = {
    'unreachable': 'Its address may have changed, or access was reverted on the server. Run the server access '
                   'helper on it again.',
    'wrong_target': 'Another machine now uses this address. Check the address, or add the server again.',
    'auth_failed': 'Check the account and password.',
    'not_admin': 'Use the built-in Administrator account.',
}


def _label(server):
    note = f' – {server.note}' if server.note else ''
    return f'{server.hostname} ({server.host}:{server.port}){note}'


def _connect(registry, server, password):
    target = server.target(password)
    status = LiveScanner(None, target).worker_status(target.hostname, target.machine_uuid)
    if status['state'] != 'ready':
        hint = HINTS.get(status['state'], '')
        st.error(f'Not connected ({status["state"]}): {md_escape(status["detail"])} {md_escape(hint)}')
        return
    registry.connected(server.machine_uuid)
    st.session_state[LIVE_TARGET] = target
    st.session_state[NOTICE] = f'Connected to {server.hostname}.'
    st.rerun()


def _add(registry, host, port, username, password, note):
    try:
        login = WinRmLogin(username.strip(), password, host.strip(), int(port))
        found = probe_identity(login)
        server, is_new = registry.add(found, login.host, login.port, login.username, note)
    except ChannelError as exc:
        st.error(f'Not added ({exc.state}): {md_escape(exc.detail)}')
        return
    except ValueError as exc:
        st.error('Not added: ' + md_escape(exc))
        return
    # The identity was just read from this address with this login, so the session can start without a second probe.
    registry.connected(server.machine_uuid)
    st.session_state[LIVE_TARGET] = server.target(password)
    st.session_state[SELECT_NEXT] = server.machine_uuid
    st.session_state[NOTICE] = (f'Added and connected to {server.hostname}.' if is_new else
                                f'{server.hostname} was already saved: its address is now {server.host}:{server.port}. '
                                'Connected.')
    st.rerun()


def _show_saved(registry, saved, connected):
    rows = [{'Server': s.hostname, 'Address': f'{s.host}:{s.port}', 'System': s.os_caption, 'Account': s.username,
             'Note': s.note, 'Last connected': myt(s.last_connected_at) if s.last_connected_at else 'Never',
             'Connected now': connected is not None and connected.machine_uuid == s.machine_uuid} for s in saved]
    st.dataframe(rows, hide_index=True)
    uuids = [s.machine_uuid for s in saved]
    if st.session_state.get(SELECT_NEXT) in uuids:
        st.session_state[PICK] = st.session_state.pop(SELECT_NEXT)
    by_uuid = {s.machine_uuid: s for s in saved}
    chosen = by_uuid[st.selectbox('Server', uuids, format_func=lambda u: _label(by_uuid[u]), key=PICK)]
    with st.container(border=True):
        st.markdown(f'**{md_escape(chosen.hostname)}** · {md_escape(chosen.os_caption)}  \n'
                    f'Address {md_escape(chosen.host)}:{chosen.port} · account {md_escape(chosen.username)} · '
                    f'UUID {md_escape(chosen.machine_uuid)}  \n'
                    f'Added {myt(chosen.added_at)} · last connected '
                    f'{myt(chosen.last_connected_at) if chosen.last_connected_at else "never"}')
        with st.container(horizontal=True, vertical_alignment='bottom'):
            password = st.text_input(f'Password for {chosen.username}', type='password', key='servers_password')
            if st.button('Connect', key='servers_connect', type='primary', disabled=not password,
                         icon=':material/lan:'):
                _connect(registry, chosen, password)
        with st.container(horizontal=True, vertical_alignment='bottom'):
            note = st.text_input('Note (only on this laptop)', value=chosen.note, max_chars=MAX_NOTE,
                                 key='servers_note_' + chosen.machine_uuid)
            if st.button('Save note', key='servers_note_save', disabled=note.strip() == chosen.note):
                registry.set_note(chosen.machine_uuid, note)
                st.rerun()
            if st.button('Remove from list', key='servers_remove', icon=':material/delete:'):
                st.session_state[REMOVING] = chosen.machine_uuid
        if st.session_state.get(REMOVING) == chosen.machine_uuid:
            st.warning(f'Remove **{md_escape(chosen.hostname)}** from this list? Its assessment history stays, and '
                       'nothing changes on the server. To add it again you need its address and password.')
            with st.container(horizontal=True):
                if st.button('Remove', key='servers_remove_confirm', type='primary'):
                    registry.remove(chosen.machine_uuid)
                    st.session_state.pop(REMOVING, None)
                    if connected is not None and connected.machine_uuid == chosen.machine_uuid:
                        del st.session_state[LIVE_TARGET]
                    st.session_state[NOTICE] = f'Removed {chosen.hostname} from the list.'
                    st.rerun()
                if st.button('Cancel', key='servers_remove_cancel'):
                    st.session_state.pop(REMOVING, None)
                    st.rerun()


def _show_add(registry):
    with st.container(border=True):
        left, middle = st.columns([3, 1])
        host = left.text_input('Server address (IP address or name)', key='servers_add_host')
        port = middle.number_input('Port', value=DEFAULT_PORT, min_value=1, max_value=65535, key='servers_add_port')
        left, right = st.columns(2)
        username = left.text_input('Administrator account', value='Administrator', key='servers_add_user')
        password = right.text_input('Password', type='password', key='servers_add_password')
        note = st.text_input('Note (optional, only on this laptop)', max_chars=MAX_NOTE, key='servers_add_note',
                             placeholder='For example: finance server, room 3')
        st.caption('The program reads the server\'s name and machine UUID from the server itself and saves them. '
                   'Every later connection checks them, so the agents only ever act on this machine. The password is '
                   'never saved, logged or sent to the model. For the lab VM through its port forward, use '
                   '127.0.0.1 and port 55985.')
        ready = all(value.strip() for value in (host, username, password))
        if st.button('Add and connect', key='servers_add', type='primary', disabled=not ready,
                     icon=':material/add_link:'):
            _add(registry, host, port, username, password, note)


def _show_helper():
    with st.expander('Server access helper: let this laptop reach a server'):
        st.markdown('Run it **on the server**, as administrator. It lets only this laptop\'s address reach WinRM on '
                    'that server, and **Revert** undoes it when you have finished.')
        st.download_button('Download helper (.zip)', helper_bundle(), file_name='FYP-ServerAccess.zip',
                           mime='application/zip', key='servers_helper', icon=':material/download:',
                           on_click='ignore')
        st.caption('Before running it, check on the server: `Get-FileHash .\\FYP-ServerAccess.ps1` must print '
                   f'`{helper_sha256().upper()}`.')


def render_servers(database_path: Path):
    st.title('Servers')
    if NOTICE in st.session_state:
        st.success(md_escape(st.session_state.pop(NOTICE)))
    connected = render_connection(key='servers')
    try:
        registry = ServerRegistry(database_path)
        saved = registry.all()
        st.subheader('My servers')
        if saved:
            _show_saved(registry, saved, connected)
        else:
            st.info('No saved servers yet. Add one below.')
        st.subheader('Add a server')
        _show_add(registry)
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Servers: ' + md_escape(exc))
    _show_helper()
