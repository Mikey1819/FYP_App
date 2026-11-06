"""Servers page: the saved servers ("My servers"), pairing a new one by code, and who has access to a server.

A server is added only by its pairing code: the administrator never types an address. Pairing
(docs/design/LAN_PAIRING_DESIGN.md), in the order the checks run:
  1. The administrator types the code shown on the server; find_server() accepts only an answer that proves it.
     The answer also says which operating system the server runs (system_detect.py). The page shows it as a note,
     and only a system this program can check (today Windows Server 2022) goes on to the login.
  2. Logging in with the Administrator password works.
  3. The machine that logged in is the one that answered (same hostname and UUID), a stand-alone Server 2022.
  4. The server's own pairing records, read over WinRM, hold this pairing for this laptop's address.
  5. Re-pairing a saved server: the UUID must be the saved one.
Only then is the server saved. Passwords are never saved.
"""
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
import sqlite3

import streamlit as st

from .connection_view import LIVE_TARGET, render_connection
from .pairing import PairingError, normalize_code
from .pairing_client import FoundServer, find_server
from .server_access import helper_bundle, helper_sha256
from .server_control import close_access, disconnect_laptop, paired_laptops
from .servers import MAX_NOTE, ServerRegistry
from .ui import md_escape, myt
from .winrm_channel import ChannelError, LiveScanner, WinRmLogin, WinRmTarget, probe_identity

PICK = 'servers_pick'
# Plain session keys (not widget keys): set by an action, read on a later run.
SELECT_NEXT = 'servers_select_next'
NOTICE = 'servers_notice'
REMOVING = 'servers_removing'
PENDING = 'servers_pending'          # A server that answered the code, waiting for the administrator to log in.
REPORT = 'servers_access_report'     # The last paired-laptops list read from the connected server.
CONFIRM_ACCESS = 'servers_confirm_access'

# What a failed connection to a saved server most likely means, in the administrator's terms.
HINTS = {
    'unreachable': 'Its address may have changed, or access was reverted on the server. Start pairing on the server '
                   'and use Re-pair below.',
    'wrong_target': 'Another machine now uses this address. Re-pair the server with a new code.',
    'auth_failed': 'Check the account and password.',
    'not_admin': 'Use the built-in Administrator account.',
}


def _label(server):
    note = f' – {server.note}' if server.note else ''
    return f'{server.hostname} ({server.host}:{server.port}){note}'


def _when(value):
    """A time from the server, shown in Malaysia time; shown as it is if it cannot be read."""
    try:
        return myt(datetime.fromisoformat(value))
    except (TypeError, ValueError):
        return str(value)


def forget_connection(notice):
    """End this session with the server (nothing changes on it) and say so on the Servers page."""
    st.session_state.pop(LIVE_TARGET, None)
    st.session_state.pop(REPORT, None)
    st.session_state.pop(CONFIRM_ACCESS, None)
    st.session_state[NOTICE] = notice
    st.rerun()


# ------------------------------------------------------------------ connecting to a saved server
def _connect(registry, server, password):
    target = server.target(password)
    status = LiveScanner(None, target).worker_status(target.hostname, target.machine_uuid)
    if status['state'] != 'ready':
        hint = HINTS.get(status['state'], '')
        st.error(f'Not connected ({status["state"]}): {md_escape(status["detail"])} {md_escape(hint)}')
        return
    registry.connected(server.machine_uuid)
    st.session_state[LIVE_TARGET] = target
    st.session_state.pop(REPORT, None)
    st.session_state[NOTICE] = f'Connected to {server.hostname}.'
    st.rerun()


def _show_saved(registry, saved, connected):
    rows = [{'Server': s.hostname, 'Address': f'{s.host}:{s.port}', 'System': s.os_caption, 'Account': s.username,
             'Note': s.note,
             'Last connected': myt(s.last_connected_at) if s.last_connected_at else 'Never',
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
                    f'{myt(chosen.last_connected_at) if chosen.last_connected_at else "never"}'
                    + (f' · paired by code {myt(chosen.paired_at)}' if chosen.paired_at else ''))
        with st.container(horizontal=True, vertical_alignment='bottom'):
            password = st.text_input(f'Password for {chosen.username}', type='password', key='servers_password')
            if st.button('Connect', key='servers_connect', type='primary', disabled=not password,
                         icon=':material/lan:'):
                _connect(registry, chosen, password)
        with st.expander('Address changed, or access was reverted? Re-pair with a new code'):
            st.caption('On the server, click **Start pairing** in the server access helper, then type the code here. '
                       'Only this same machine (same UUID) is accepted.')
            with st.container(horizontal=True, vertical_alignment='bottom'):
                code = st.text_input('Pairing code', key='servers_repair_code', placeholder='482-913-075')
                if st.button('Find', key='servers_repair', disabled=not code.strip(), icon=':material/wifi_find:'):
                    _find(code, expected_uuid=chosen.machine_uuid, username=chosen.username)
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
                       'nothing changes on the server. To add it again you need a new pairing code.')
            with st.container(horizontal=True):
                if st.button('Remove', key='servers_remove_confirm', type='primary'):
                    registry.remove(chosen.machine_uuid)
                    st.session_state.pop(REMOVING, None)
                    if connected is not None and connected.machine_uuid == chosen.machine_uuid:
                        st.session_state.pop(LIVE_TARGET, None)
                        st.session_state.pop(REPORT, None)
                    st.session_state[NOTICE] = f'Removed {chosen.hostname} from the list.'
                    st.rerun()
                if st.button('Cancel', key='servers_remove_cancel'):
                    st.session_state.pop(REMOVING, None)
                    st.rerun()


# ------------------------------------------------------------------ pairing by code
def _find(code, *, expected_uuid=None, username='Administrator'):
    """Step 1: find the server that shows this code. Nothing is saved yet."""
    try:
        found = find_server(normalize_code(code))
    except (ValueError, PairingError) as exc:
        st.error(md_escape(exc))
        return
    if expected_uuid and found.machine_uuid != expected_uuid:
        st.error(f'A different machine answered with this code ({md_escape(found.hostname)}, UUID '
                 f'{md_escape(found.machine_uuid)}). Nothing was saved. Check which server shows the code.')
        return
    st.session_state[PENDING] = dict(found=asdict(found), expected=expected_uuid, username=username)
    st.rerun()


def _finish_pairing(registry, pending, username, password, note):
    """Steps 2 to 5: log in, check the identity and the server's pairing record, then save and connect."""
    found = FoundServer(**pending['found'])
    if not found.system.supported:  # The button is not offered then; this keeps the rule in one more place.
        st.error('Not paired: ' + md_escape(found.system.note))
        return
    try:
        login = WinRmLogin(username.strip(), password, found.address, found.port)
        identity = probe_identity(login)
        if (identity['hostname'].casefold() != found.hostname.casefold()
                or identity['machine_uuid'] != found.machine_uuid
                or (pending['expected'] and identity['machine_uuid'] != pending['expected'])):
            raise ChannelError('wrong_target', 'The machine that accepted the login is not the one that answered '
                               'the code. Nothing was saved.')
        target = WinRmTarget(identity['hostname'], identity['machine_uuid'], login.username, password,
                             login.host, login.port)
        report = paired_laptops(target)
        record = next((p for p in report['pairings'] if p['pairing_id'] == found.pairing_id), None)
        if record is None or record['laptop_address'] != found.laptop_address:
            raise ChannelError('pairing_not_confirmed', 'The server has no record of this pairing for this laptop. '
                               'Start pairing on the server again and type the new code.')
        server, is_new = registry.add(identity, login.host, login.port, login.username, note)
        registry.paired(server.machine_uuid, found.pairing_id, found.laptop_address)
        registry.connected(server.machine_uuid)
    except ChannelError as exc:
        st.error(f'Not paired ({exc.state}): {md_escape(exc.detail)}')
        return
    except (ValueError, KeyError) as exc:
        st.error('Not paired: ' + md_escape(exc))
        return
    st.session_state.pop(PENDING, None)
    st.session_state[LIVE_TARGET] = target
    st.session_state[REPORT] = dict(uuid=server.machine_uuid, report=report)
    st.session_state[SELECT_NEXT] = server.machine_uuid
    st.session_state[NOTICE] = (f'Paired and connected to {server.hostname}.' if is_new else
                                f'Re-paired {server.hostname}: its address is now {server.host}:{server.port}. Connected.')
    st.rerun()


def _show_pending(registry):
    pending = st.session_state[PENDING]
    found = FoundServer(**pending['found'])
    system = found.system
    with st.container(border=True):
        st.markdown(f':green-badge[:material/wifi_find: Found] **{md_escape(found.hostname)}** at '
                    f'{md_escape(found.address)}, answering with the right code.')
        # The system the server reported about itself: the administrator never has to say it.
        badge = ':green-badge[:material/check: Supported]' if system.supported else ':orange-badge[Not supported yet]'
        st.markdown(f'System: **{md_escape(system.label)}** {badge}  \n'
                    f'{md_escape(system.note)} *(Reported by the server: {md_escape(system.reported or "nothing")}.)*')
        if not system.supported:
            st.caption('Nothing was saved on this laptop. The helper on the server may have recorded this pairing: '
                       'click **Revert changes** there to remove it.')
            if st.button('Cancel', key='servers_pair_cancel'):
                st.session_state.pop(PENDING, None)
                st.rerun()
            return
        st.caption('Log in to finish. The program then checks that the machine you log in to is this one, and that '
                   'the server recorded this pairing for this laptop. The password is never saved.')
        left, right = st.columns(2)
        username = left.text_input('Administrator account', value=pending['username'], key='servers_pair_user')
        password = right.text_input('Password', type='password', key='servers_pair_password')
        note = '' if pending['expected'] else st.text_input(
            'Note (optional, only on this laptop)', max_chars=MAX_NOTE, key='servers_pair_note',
            placeholder='For example: finance server, room 3')
        with st.container(horizontal=True):
            if st.button('Log in and save', key='servers_pair_finish', type='primary',
                         disabled=not (password and username.strip()), icon=':material/link:'):
                _finish_pairing(registry, pending, username, password, note)
            if st.button('Cancel', key='servers_pair_cancel'):
                st.session_state.pop(PENDING, None)
                st.rerun()


def _show_add_by_code():
    st.caption('On the server, run the server access helper (download it below) and click **Start pairing**. It '
               'shows a one-time code. This laptop and the server must be on the same network. You do not need its '
               'address, and the program finds out by itself which system the server runs.')
    with st.container(horizontal=True, vertical_alignment='bottom'):
        code = st.text_input('Pairing code shown on the server', key='servers_code', placeholder='482-913-075')
        if st.button('Find server', key='servers_find', type='primary', disabled=not code.strip(),
                     icon=':material/wifi_find:'):
            _find(code)


# ------------------------------------------------------------------ who has access to the connected server
def _show_access(registry, connected):
    saved = registry.get(connected.machine_uuid)
    own = saved.pairing_id if saved else None
    held = st.session_state.get(REPORT)
    report = held['report'] if held and held['uuid'] == connected.machine_uuid else None
    st.caption('Laptops paired through the server access helper can reach WinRM on this server. You can disconnect '
               'any of them from here, for example one you do not recognise.')
    try:
        if st.button('Refresh paired laptops' if report else 'Show paired laptops', key='servers_access_refresh',
                     icon=':material/refresh:'):
            report = paired_laptops(connected)
            st.session_state[REPORT] = dict(uuid=connected.machine_uuid, report=report)
        if report is None:
            return
        pairings = report['pairings']
        if not pairings:
            st.info('No laptop is paired through the helper on this server at the moment.')
            return
        st.dataframe([{'Laptop': p['laptop_name'], 'Address': p['laptop_address'], 'Paired': _when(p['paired_at']),
                       'This laptop': p['pairing_id'] == own} for p in pairings], hide_index=True)
        others = [p for p in pairings if p['pairing_id'] != own]
        if others:
            with st.container(horizontal=True, vertical_alignment='bottom'):
                by_id = {p['pairing_id']: p for p in others}
                pick = st.selectbox('Another paired laptop', list(by_id), key='servers_access_pick',
                                    format_func=lambda i: f"{by_id[i]['laptop_name']} ({by_id[i]['laptop_address']})")
                if st.button('Disconnect that laptop', key='servers_access_remove', icon=':material/link_off:'):
                    report = disconnect_laptop(connected, pick)
                    st.session_state[REPORT] = dict(uuid=connected.machine_uuid, report=report)
                    st.session_state[NOTICE] = (f"Disconnected {by_id[pick]['laptop_name']} "
                                                f"({by_id[pick]['laptop_address']}) from {connected.hostname}.")
                    st.rerun()
        with st.container(horizontal=True):
            if any(p['pairing_id'] == own for p in pairings) and st.button(
                    'Disconnect this laptop', key='servers_access_self', icon=':material/logout:'):
                st.session_state[CONFIRM_ACCESS] = 'self'
            if st.button('Close all access', key='servers_access_all', icon=':material/block:'):
                st.session_state[CONFIRM_ACCESS] = 'all'
        confirm = st.session_state.get(CONFIRM_ACCESS)
        if confirm:
            st.warning('**This laptop will lose access to the server** and this session ends. To connect again, '
                       'start pairing on the server and re-pair.' if confirm == 'self' else
                       '**Every paired laptop, this one included, will lose access to the server**, and this session '
                       'ends. To connect again, start pairing on the server.')
            with st.container(horizontal=True):
                if st.button('Yes, disconnect', key='servers_access_confirm', type='primary'):
                    if confirm == 'self':
                        disconnect_laptop(connected, own)
                        forget_connection(f'This laptop no longer has access to {connected.hostname}.')
                    else:
                        final = close_access(connected)
                        forget_connection(f'No laptop has access to {connected.hostname} any more.' + (
                            ' The helper had turned PowerShell Remoting on: click Revert changes in the helper on the '
                            'server to turn it off.' if final['helper_enabled_remoting'] else ''))
                if st.button('Cancel', key='servers_access_cancel'):
                    st.session_state.pop(CONFIRM_ACCESS, None)
                    st.rerun()
    except ChannelError as exc:
        st.error(f'Could not reach the server access helper ({exc.state}): {md_escape(exc.detail)}')


def _show_helper():
    with st.expander('Server access helper: download it for the server'):
        st.markdown('Run it **on the server**, as administrator, and click **Start pairing**. Only laptops that '
                    'typed its code can reach WinRM on that server, and **Revert changes** undoes everything when '
                    'you have finished.')
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
        if PENDING in st.session_state:
            _show_pending(registry)
        saved = registry.all()
        st.subheader('My servers')
        if saved:
            _show_saved(registry, saved, connected)
        else:
            st.info('No saved servers yet. Add one below.')
        if connected is not None:
            st.subheader(f'Who can reach {md_escape(connected.hostname)}')
            _show_access(registry, connected)
        st.subheader('Add a server')
        _show_add_by_code()
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Servers: ' + md_escape(exc))
    _show_helper()
