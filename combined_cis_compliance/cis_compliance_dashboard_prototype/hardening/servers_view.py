"""Servers page: the saved servers ("My servers"), pairing a new one by code, and who has access to a server.

This program supports only Windows Server 2022 (stand-alone) and Ubuntu 22.04.5 LTS.

A server is added only by its pairing code: the administrator never types its name, machine identity, address or
SSH fingerprint. Pairing (docs/design/LAN_PAIRING_DESIGN.md), in the order the checks run:
  1. The administrator types the code shown on the server; find_server() accepts only an answer that proves it.
     The answer also says which operating system the server runs (system_detect.py). The page shows it as a note,
     and only a system this program can check goes on to the login.
  2. Logging in works: the Administrator password over WinRM, or the server account (password or one SSH key) over
     SSH. On Ubuntu the SSH host key must be the one the signed answer named.
  3. The machine that logged in is the one that answered (same hostname and machine identity), and a supported
     system (system/connection.py).
  4. Windows only: the server's own pairing records, read over WinRM, hold this pairing for this laptop's address.
  5. Re-pairing a saved server: the identity must be the saved one.
Only then is the server saved. Passwords are never saved.
"""
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from uuid import uuid4

import streamlit as st

from . import background
from .connection_view import LIVE_TARGET, LOCKED, connected_session, disconnect, running_job
from .overview_view import NEW_SERVER
from .pairing import PairingError, normalize_code
from .pairing_client import FoundServer, find_server
from .reconnect import remember
from .server_access import helper_bundle, helper_sha256, ubuntu_helper, ubuntu_helper_sha256
from .server_control import close_access, disconnect_laptop, paired_laptops
from .servers import MAX_NOTE, ServerRegistry
from .system_detect import SUPPORTED_SYSTEMS
from .ui import md_escape, myt
from .winrm_channel import ChannelError
from system.bootstrap import CONNECTION_KEY, connection_service
from system.contracts import ConnectionRequest, Endpoint
from system.session import Credentials

PICK = 'servers_pick'
# Plain session keys (not widget keys): set by an action, read on a later run.
SELECT_NEXT = 'servers_select_next'
NOTICE = 'servers_notice'
REMOVING = 'servers_removing'
PENDING = 'servers_pending'          # A server that answered the code, waiting for the administrator to log in.
REPORT = 'servers_access_report'     # The last paired-laptops list read from the connected server.
CONFIRM_ACCESS = 'servers_confirm_access'
SHOW_FOUND = 'servers_show_found'    # Set by Find: on the next run the page scrolls once to the Found panel.
FINDS = 'servers_finds'              # How many times Find answered in this session.
FOUND_BOX = 'servers_found'          # The Found panel's container key (Streamlit gives it the class st-key-<key>).
LOST = ('The connection to the server stopped answering (it may have restarted). Click **Disconnect** above, then '
        '**Connect** again under My servers.')
SECRETS = ('servers_password', 'servers_pair_password', 'servers_pair_sudo', 'servers_sudo')
JOB = 'servers_job_key'              # This browser session's key for its background network work (background.py).
FAILED = 'servers_failed'            # Why the last background Find or login failed, shown once.
WAIT_SECONDS = 3                     # Quick work shows its result at once; slower work shows as running.

# What a failed connection to a saved server most likely means, in the administrator's terms.
HINTS = {
    'disconnected': '',
    'connection_failed': 'Check the server is on and on the same network. If its address changed, start pairing on '
                         'the server and use Re-pair below.',
    'verification_failed': 'If the server got a new address, start pairing on the server and use Re-pair below.',
    'pending_change_elsewhere': '',
    'auth_failed': 'Check the account and password. On Ubuntu the account is the Linux user of the server, the name '
                   'before @ in its terminal prompt.',
    'unreachable': 'Check the server is on. Its address may have changed (pair again and use Re-pair below); on Windows, '
                   'access may have been reverted in the helper; on Ubuntu, check that the SSH service runs '
                   '(systemctl status ssh).',
    'slow_reply': 'The server is reachable but slow. Give it a minute (a VM may still be starting or short of memory), '
                  'then connect again.',
}


def _label(server):
    note = f' – {server.note}' if server.note else ''
    return f'{server.hostname} ({server.system_label}, {server.host}:{server.port}){note}'


def _when(value):
    """A time from the server, shown in Malaysia time; shown as it is if it cannot be read."""
    try:
        return myt(datetime.fromisoformat(value))
    except (TypeError, ValueError):
        return str(value)


def _clear_secrets():
    for key in SECRETS:
        st.session_state.pop(key, None)


def forget_connection(notice):
    """End this session with the server (nothing changes on it) and say so on the Servers page."""
    disconnect()
    st.session_state.pop(REPORT, None)
    st.session_state.pop(CONFIRM_ACCESS, None)
    st.session_state[NOTICE] = notice
    st.rerun()


# ------------------------------------------------------------------ network work in the background
# Streamlit restarts the page when a button is clicked again, and stops the run in progress at its next Streamlit
# call. A login done inside the page could then finish on the server and in the connection service while the page
# never recorded it: the next try failed ("Disconnect the active server first") and the code was used up. So Find,
# Log in and save, and Connect run in the background worker; no click can stop it, a repeated click is ignored while
# it runs, and the page applies its result afterwards (_collect). The work never touches st.session_state: it returns
# what the page must apply.
def _job_key():
    if JOB not in st.session_state:
        st.session_state[JOB] = 'servers:' + uuid4().hex
    return st.session_state[JOB]


def _working():
    return background.running(_job_key())


def _run(label, work):
    """Start network work for this page; a click while earlier work still runs changes nothing."""
    try:
        job = background.start(_job_key(), label, work)
    except ValueError:
        return  # Already working: this was a repeated click.
    with st.spinner(label + '…'):
        job.wait(WAIT_SECONDS)
    st.rerun()


def _fail(message):
    """What the page applies when the work failed: the reason (Markdown, data parts already escaped), shown once."""
    return lambda: st.session_state.__setitem__(FAILED, message)


def _collect():
    """Apply the finished work of this page once (it may rerun the page, for example to open the workspace)."""
    job = background.take_finished(_job_key())
    if job is None:
        return
    if job.error is not None:  # Unexpected: the work catches what it expects. Library text is never shown.
        st.session_state[FAILED] = f'{md_escape(job.label)} stopped ({type(job.error).__name__}). Nothing was saved.'
    elif callable(job.result):
        job.result()


@st.fragment(run_every=1)
def _watch(key):
    job = background.running(key)
    if job is None:
        st.rerun(scope='app')
    seconds = int((datetime.now(timezone.utc) - job.started_at).total_seconds())
    st.info(f':material/progress_activity: **{md_escape(job.label)}…** {seconds} s. Clicking again is not needed.')


def _request(platform, host, port, hostname, identity, username, *, password=None, key_path=None, sudo=None,
             fingerprint=None):
    """On the page: the connection request, with the credentials in the service's one-use vault (cleared whatever
    happens). Returns (service, request), or None after showing why not."""
    service = connection_service(st.session_state)
    try:
        reference = service.vault.put(Credentials(username.strip(), password or None, key_path or None, sudo or None,
                                                  fingerprint))
        return service, ConnectionRequest(Endpoint(host, port, 'ssh' if platform == 'ubuntu' else 'winrm'), hostname,
                                          identity, reference)
    except ValueError as exc:
        service.vault.clear()
        st.error('Not connected: ' + md_escape(exc))
        return None


def _login(service, request, platform, paired):
    """In the background: log in and verify. Returns (verified session, None) or (None, why not)."""
    result = service.connect(request, paired=paired)
    if result.state != 'connected':
        hint = result.remedy or HINTS.get(result.diagnostic_code, '')
        return None, f'Not connected ({result.diagnostic_code}): {md_escape(result.detail)} {md_escape(hint)}'
    session = service.session(result.connection_session_id)
    if session.identity.platform != platform:
        service.disconnect(result.connection_session_id)
        return None, 'Not connected: the server answered as another system than it was paired as. Pair it again.'
    return session, None


def _connected(session, platform, remembered):
    """On the page: hold the verified connection in this session."""
    st.session_state[CONNECTION_KEY] = session.connection_session_id
    st.session_state[LIVE_TARGET] = session.target if platform == 'windows' else None
    if platform == 'ubuntu':  # For the fresh login that confirms SSH and firewall changes (reconnect.py).
        remember(st.session_state, **remembered)


# ------------------------------------------------------------------ connecting to a saved server
def _connect(registry, server, password, sudo):
    password = password if server.auth == 'password' else None
    key_path = server.key_path if server.auth == 'key' else None
    prepared = _request(server.platform, server.host, server.port, server.hostname, server.machine_identity,
                        server.username, password=password, key_path=key_path, sudo=sudo)
    _clear_secrets()
    if prepared is None:
        return
    service, request = prepared
    remembered = dict(host=server.host, port=server.port, hostname=server.hostname, identity=server.machine_identity,
                      username=server.username.strip(), password=password or None, key_path=key_path or None,
                      sudo=sudo or None)

    def work():
        session, failure = _login(service, request, server.platform, False)
        if session is None:
            return _fail(failure)
        registry.connected(server.platform, server.machine_identity)

        def apply():
            _connected(session, server.platform, dict(remembered, hostname=session.identity.hostname))
            st.session_state.pop(REPORT, None)
            st.session_state[NOTICE] = f'Connected to {server.hostname}.'
            st.rerun()
        return apply
    _run(f'Connecting to {server.hostname}', work)


def _show_saved(registry, saved, connected, busy=False):
    rows = [{'Server': s.hostname, 'System': s.system_label, 'Address': f'{s.host}:{s.port}', 'Account': s.username,
             'Note': s.note,
             'Last connected': myt(s.last_connected_at) if s.last_connected_at else 'Never',
             'Connected now': connected is not None and connected.identity.platform == s.platform
             and connected.identity.machine_identity == s.machine_identity} for s in saved]
    st.dataframe(rows, hide_index=True)
    keys = [s.key for s in saved]
    if st.session_state.get(SELECT_NEXT) in keys:
        st.session_state[PICK] = st.session_state.pop(SELECT_NEXT)
    by_key = {s.key: s for s in saved}
    chosen = by_key[st.selectbox('Server', keys, format_func=lambda k: _label(by_key[k]), key=PICK)]
    is_connected = (connected is not None and connected.identity.platform == chosen.platform
                    and connected.identity.machine_identity == chosen.machine_identity)
    with st.container(border=True):
        st.markdown(f'**{md_escape(chosen.hostname)}** · {md_escape(chosen.os_caption)}  \n'
                    f'Address {md_escape(chosen.host)}:{chosen.port} ({chosen.transport.upper()}) · account '
                    f'{md_escape(chosen.username)} · '
                    f'{"UUID" if chosen.platform == "windows" else "machine-id"} {md_escape(chosen.machine_identity)}  \n'
                    f'Added {myt(chosen.added_at)} · last connected '
                    f'{myt(chosen.last_connected_at) if chosen.last_connected_at else "never"}'
                    + (f' · paired by code {myt(chosen.paired_at)}' if chosen.paired_at else ''))
        if is_connected:
            st.markdown(':green-badge[:material/lan: Connected now]')
        elif connected is not None:
            st.caption(f'Disconnect from {md_escape(connected.identity.hostname)} first to connect this server.')
        else:
            with st.container(horizontal=True, vertical_alignment='bottom'):
                password = ''
                if chosen.auth == 'password':
                    password = st.text_input(f'Password for {chosen.username}', type='password', key='servers_password')
                else:
                    st.caption('SSH key file: ' + md_escape(chosen.key_path))
                connect = st.button('Connect', key='servers_connect', type='primary', icon=':material/lan:',
                                    disabled=_working() is not None)
            if connect and _working():
                pass  # A repeated click while connecting.
            elif connect and chosen.auth == 'password' and not password:
                st.warning('Type the password first.')
            elif connect:
                _connect(registry, chosen, password, st.session_state.get('servers_sudo'))
            if chosen.platform == 'ubuntu':
                with st.expander('Separate sudo password (optional)'):
                    st.text_input('Sudo password', type='password', key='servers_sudo',
                                  help='Session-only. Does not authorize setup or elevated changes.')
        if chosen.platform == 'ubuntu':
            with st.expander('Manual alternative: build the helper bundle yourself'):
                st.caption('Normally not needed: the pairing helper (fyp-pair-ubuntu.py) sets the server up before it '
                           'shows the code. To do it yourself: build it on this laptop from the application folder, copy '
                           'it to the server and run `sudo bash setup.sh` there. Its scripts refuse any other machine, so '
                           'the values below come from this server itself, as found by pairing.')
                st.code(f'..\\.venv-integration\\Scripts\\python.exe -B -m tools.build_ubuntu_bundle '
                        f'--machine-id {chosen.machine_identity} --hostname {chosen.hostname} --user {chosen.username}',
                        language=None)
        with st.expander('Address changed, or access was reverted? Re-pair with a new code'):
            st.caption('On the server, start the pairing helper (**Start pairing** on Windows, '
                       '`sudo python3 fyp-pair-ubuntu.py` on Ubuntu), then type the code here. Only this same machine '
                       'is accepted.')
            with st.container(horizontal=True, vertical_alignment='bottom'):
                code = st.text_input('Pairing code', key='servers_repair_code', placeholder='482-913-075')
                find = st.button('Find', key='servers_repair', disabled=connected is not None or _working() is not None,
                                 icon=':material/wifi_find:')
            if find and _working():
                pass
            elif find and not code.strip():
                st.warning('Type the pairing code shown on the server.')
            elif find:
                _find(code, expected=chosen.key, username=chosen.username)
        with st.container(horizontal=True, vertical_alignment='bottom'):
            note = st.text_input('Note (only on this laptop)', value=chosen.note, max_chars=MAX_NOTE,
                                 key='servers_note_' + chosen.key)
            if st.button('Save note', key='servers_note_save'):
                registry.set_note(chosen.platform, chosen.machine_identity, note)
                st.rerun()
            locked = busy and is_connected
            if st.button('Remove from list', key='servers_remove', icon=':material/delete:', disabled=locked,
                         help=LOCKED if locked else None):
                st.session_state[REMOVING] = chosen.key
        if st.session_state.get(REMOVING) == chosen.key:
            st.warning(f'Remove **{md_escape(chosen.hostname)}** from this list? Its assessment history stays, and '
                       'nothing changes on the server. To add it again you need a new pairing code.')
            with st.container(horizontal=True):
                if st.button('Remove', key='servers_remove_confirm', type='primary'):
                    registry.remove(chosen.platform, chosen.machine_identity)
                    st.session_state.pop(REMOVING, None)
                    if is_connected:
                        disconnect()
                        st.session_state.pop(REPORT, None)
                    st.session_state[NOTICE] = f'Removed {chosen.hostname} from the list.'
                    st.rerun()
                if st.button('Cancel', key='servers_remove_cancel'):
                    st.session_state.pop(REMOVING, None)
                    st.rerun()


# ------------------------------------------------------------------ pairing by code
def _find(code, *, expected=None, username=None):
    """Step 1: find the server that shows this code (in the background). Nothing is saved yet."""
    def work():
        try:
            found = find_server(normalize_code(code))
        except (ValueError, PairingError) as exc:
            return _fail(md_escape(exc))
        if expected and (found.platform or found.os) + ':' + found.machine_identity != expected:
            return _fail(f'A different machine answered with this code ({md_escape(found.hostname)}, identity '
                         f'{md_escape(found.machine_identity)}). Nothing was saved. Check which server shows the code.')

        def apply():
            st.session_state[PENDING] = dict(found=asdict(found), expected=expected, username=username or (
                'Administrator' if found.platform == 'windows' else ''))
            st.session_state[FINDS] = st.session_state.get(FINDS, 0) + 1
            st.session_state[SHOW_FOUND] = st.session_state[FINDS]
            st.rerun()
        return apply
    _run('Looking for the server that shows this code', work)


def _pairing_confirmed(session, found):
    """Windows step 4: the server's own pairing record for this laptop. Returns the helper's report, or None."""
    report = paired_laptops(session.target)
    record = next((p for p in report['pairings'] if p['pairing_id'] == found.pairing_id), None)
    if record is None or record['laptop_address'] != found.laptop_address:
        return None
    return report


def _finish_pairing(registry, pending, username, password, key_path, sudo, note):
    """Steps 2 to 5: log in, check the identity (and on Windows the server's pairing record), then save."""
    found = FoundServer(**pending['found'])
    if not found.system.supported:  # The button is not offered then; this keeps the rule in one more place.
        st.error('Not paired: ' + md_escape(found.system.note))
        return
    prepared = _request(found.platform, found.address, found.port, found.hostname, found.machine_identity, username,
                        password=password, key_path=key_path, sudo=sudo, fingerprint=found.host_key)
    _clear_secrets()
    if prepared is None:
        return
    service, request = prepared
    remembered = dict(host=found.address, port=found.port, hostname=found.hostname, identity=found.machine_identity,
                      username=username.strip(), password=password or None, key_path=key_path or None,
                      sudo=sudo or None)

    def work():
        session, failure = _login(service, request, found.platform, True)
        if session is None:
            return _fail(failure)
        report = None
        try:
            if found.platform == 'windows':
                report = _pairing_confirmed(session, found)
                if report is None:
                    service.disconnect(session.connection_session_id)
                    return _fail('Not paired (pairing_not_confirmed): the server has no record of this pairing for '
                                 'this laptop. Start pairing on the server again and type the new code.')
            server, is_new = registry.add(found.platform, found.machine_identity, session.identity.hostname,
                                          found.system.reported or found.system.label, found.address, found.port,
                                          username, auth='key' if key_path else 'password', key_path=key_path or '',
                                          note=note)
            registry.paired(server.platform, server.machine_identity, found.pairing_id, found.laptop_address)
            registry.connected(server.platform, server.machine_identity)
        except ChannelError as exc:
            service.disconnect(session.connection_session_id)
            return _fail(f'Not paired ({exc.state}): {md_escape(exc.detail)}')
        except (ValueError, KeyError) as exc:
            service.disconnect(session.connection_session_id)
            return _fail('Not paired: ' + md_escape(exc))

        def apply():
            _connected(session, found.platform, dict(remembered, hostname=session.identity.hostname))
            st.session_state.pop(PENDING, None)
            if report is not None:
                st.session_state[REPORT] = dict(key=server.key, report=report)
            st.session_state[SELECT_NEXT] = server.key
            if is_new:  # First time on this laptop: Overview says so until the first scan (both systems).
                st.session_state[NEW_SERVER] = dict(key=server.key, hostname=server.hostname,
                                                    system=server.system_label)
            st.session_state[NOTICE] = (f'Paired and connected to {server.hostname}.' if is_new else
                                        f'Re-paired {server.hostname}: its address is now {server.host}:{server.port}. '
                                        'Connected.')
            st.rerun()
        return apply
    _run(f'Logging in to {found.hostname} and checking it', work)


def _show_pending(registry, connected):
    pending = st.session_state[PENDING]
    found = FoundServer(**pending['found'])
    system = found.system
    with st.container(border=True, key=FOUND_BOX):
        st.markdown(f':green-badge[:material/wifi_find: Found] **{md_escape(found.hostname)}** at '
                    f'{md_escape(found.address)}, answering with the right code.')
        # The system the server reported about itself: the administrator never has to say it.
        badge = ':green-badge[:material/check: Supported]' if system.supported else ':orange-badge[Not supported]'
        st.markdown(f'System: **{md_escape(system.label)}** {badge}  \n'
                    f'{md_escape(system.note)} *(Reported by the server: {md_escape(system.reported or "nothing")}.)*')
        if found.host_key:
            # Checked by pairing.read_found to be SHA256: and 43 base64 characters, so it is safe in a code span
            # (escaping it there would show the backslashes).
            st.caption(f'SSH host key reported by the server: `{found.host_key}`. The login must find exactly this '
                       'key.')
        if not system.supported or connected is not None:
            if not system.supported:
                st.caption('Nothing was saved on this laptop. On a Windows server, the helper may have recorded this '
                           'pairing: click **Revert changes** there to remove it.')
            else:
                st.caption(f'Disconnect from {md_escape(connected.identity.hostname)} first to finish pairing.')
            if st.button('Cancel', key='servers_pair_cancel'):
                st.session_state.pop(PENDING, None)
                st.rerun()
            return
        st.caption('Log in to finish. The program then checks that the machine you log in to is this one'
                   + (', and that the server recorded this pairing for this laptop' if found.platform == 'windows'
                      else '') + '. The password is never saved.')
        key_path = sudo = None
        if found.platform == 'windows':
            left, right = st.columns(2)
            username = left.text_input('Administrator account', value=pending['username'], key='servers_pair_user')
            password = right.text_input('Password', type='password', key='servers_pair_password')
        else:
            left, right = st.columns(2)
            username = left.text_input('Account on the server', value=pending['username'], key='servers_pair_user',
                                       help='The Linux user you log in with on the server: the name before @ in its '
                                            'terminal prompt. The Ubuntu helper bundle is installed for this account.')
            auth = right.radio('Log in with', ('Password', 'SSH key'), horizontal=True, key='servers_pair_auth')
            password = key_path = None
            if auth == 'Password':
                password = st.text_input('Password', type='password', key='servers_pair_password')
            else:
                key_path = st.text_input('SSH private key file on this laptop', key='servers_pair_key',
                                         help='Only this key is used. SSH agent and key searching are disabled.')
            with st.expander('Separate sudo password (optional)'):
                sudo = st.text_input('Sudo password', type='password', key='servers_pair_sudo',
                                     help='Session-only. Does not authorize setup or elevated changes.')
        note = '' if pending['expected'] else st.text_input(
            'Note (optional, only on this laptop)', max_chars=MAX_NOTE, key='servers_pair_note',
            placeholder='For example: finance server, room 3')
        with st.container(horizontal=True):
            working = _working() is not None
            finish = st.button('Log in and save', key='servers_pair_finish', type='primary', icon=':material/link:',
                               disabled=working)
            if st.button('Cancel', key='servers_pair_cancel', disabled=working):
                st.session_state.pop(PENDING, None)
                st.rerun()
        if finish and _working():
            pass  # A repeated click while logging in.
        elif finish and not ((password or (key_path or '').strip()) and username.strip()):
            st.warning('Type the account and its password' + ('' if found.platform == 'windows' else
                                                              ' (or the SSH key file)') + ' first.')
        elif finish:
            _finish_pairing(registry, pending, username, password, (key_path or '').strip() or None, sudo, note)


def _show_add_by_code(connected):
    st.caption('On the server, run its pairing helper (download it below): on Windows Server 2022 click **Start '
               'pairing** in the server access helper; on Ubuntu 22.04 run `sudo python3 fyp-pair-ubuntu.py`. It shows '
               'a one-time code. This laptop and the server must be on the same network. You do not need its address, '
               'name or identity: the program finds out by itself which server it is and which system it runs.')
    with st.container(horizontal=True, vertical_alignment='bottom'):
        code = st.text_input('Pairing code shown on the server', key='servers_code', placeholder='482-913-075')
        find = st.button('Find server', key='servers_find', type='primary', icon=':material/wifi_find:',
                         disabled=_working() is not None)
    if find and _working():
        pass  # A repeated click while looking.
    elif find and not code.strip():
        st.warning('Type the pairing code shown on the server.')
    elif find:
        _find(code)


# ------------------------------------------------------------------ Ubuntu: one-step setup
# ------------------------------------------------------------------ who has access to the connected server
def _show_access(registry, connected):
    """Windows only: the laptops the server access helper lets reach WinRM. (On Ubuntu, SSH access is the server's
    own accounts and keys; the pairing helper keeps no record.)"""
    target = connected.target
    saved = registry.get('windows', connected.identity.machine_identity)
    own = saved.pairing_id if saved else None
    key = 'windows:' + connected.identity.machine_identity
    held = st.session_state.get(REPORT)
    report = held['report'] if held and held['key'] == key else None
    st.caption('Laptops paired through the server access helper can reach WinRM on this server. You can disconnect '
               'any of them from here, for example one you do not recognise.')
    try:
        if st.button('Refresh paired laptops' if report else 'Show paired laptops', key='servers_access_refresh',
                     icon=':material/refresh:'):
            report = paired_laptops(target)
            st.session_state[REPORT] = dict(key=key, report=report)
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
                    report = disconnect_laptop(target, pick)
                    st.session_state[REPORT] = dict(key=key, report=report)
                    st.session_state[NOTICE] = (f"Disconnected {by_id[pick]['laptop_name']} "
                                                f"({by_id[pick]['laptop_address']}) from {target.hostname}.")
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
                        disconnect_laptop(target, own)
                        forget_connection(f'This laptop no longer has access to {target.hostname}.')
                    else:
                        final = close_access(target)
                        forget_connection(f'No laptop has access to {target.hostname} any more.' + (
                            ' The helper had turned PowerShell Remoting on: click Revert changes in the helper on the '
                            'server to turn it off.' if final['helper_enabled_remoting'] else ''))
                if st.button('Cancel', key='servers_access_cancel'):
                    st.session_state.pop(CONFIRM_ACCESS, None)
                    st.rerun()
    except ChannelError as exc:
        st.error(f'Could not reach the server access helper ({exc.state}): {md_escape(exc.detail)}')


def _show_helpers():
    with st.expander('Windows Server 2022: server access helper'):
        st.markdown('Run it **on the server**, as administrator, and click **Start pairing**. Only laptops that '
                    'typed its code can reach WinRM on that server, and **Revert changes** undoes everything when '
                    'you have finished.')
        st.download_button('Download helper (.zip)', helper_bundle(), file_name='FYP-ServerAccess.zip',
                           mime='application/zip', key='servers_helper', icon=':material/download:',
                           on_click='ignore')
        st.caption('Before running it, check on the server: `Get-FileHash .\\FYP-ServerAccess.ps1` must print '
                   f'`{helper_sha256().upper()}`.')
    with st.expander('Ubuntu 22.04: pairing helper'):
        st.markdown('Copy it **to the server** and run `sudo python3 fyp-pair-ubuntu.py`. It shows the code and the '
                    'SSH host key it will vouch for. While the code is shown it allows the pairing question (UDP '
                    '47815) from local networks through UFW, and removes that rule when it stops. It changes nothing '
                    'else. The server still needs the FYP helper bundle installed for assessment (docs: OPERATIONS.md).')
        st.download_button('Download pairing helper (.py)', ubuntu_helper(), file_name='fyp-pair-ubuntu.py',
                           mime='text/x-python', key='servers_ubuntu_helper', icon=':material/download:',
                           on_click='ignore')
        st.caption(f'Before running it, check on the server: `sha256sum fyp-pair-ubuntu.py` must print '
                   f'`{ubuntu_helper_sha256()}`.')


def _scroll_to_found(count):
    """Bring the Found panel into view once. The code is typed lower on the page (Add a server, or Re-pair), and
    Streamlit keeps the scroll position, so the panel would otherwise open out of sight above. Only fixed text goes into
    the script; the count makes each Find a new element, so a second Find scrolls again."""
    st.html(f'''<script>/* find {int(count)} */
(function () {{
  let tries = 0;
  (function go() {{
    const box = document.querySelector('.st-key-{FOUND_BOX}');
    if (box) {{ box.style.scrollMarginTop = '80px'; box.scrollIntoView({{behavior: 'smooth', block: 'start'}}); }}
    else if (++tries < 30) {{ setTimeout(go, 100); }}
  }})();
}})();
</script>''', unsafe_allow_javascript=True)


def render_servers(database_path: Path):
    st.title('Servers')
    st.caption(f'This program supports only {SUPPORTED_SYSTEMS}. Servers are added by their pairing code.')
    _collect()
    if NOTICE in st.session_state:
        st.success(md_escape(st.session_state.pop(NOTICE)))
    if FAILED in st.session_state:
        st.error(st.session_state.pop(FAILED))  # Markdown, its data parts escaped where it was written.
    if _working() is not None:
        _watch(_job_key())
    connected = connected_session()
    busy = connected is not None and running_job() is not None
    if connected is not None:
        with st.container(horizontal=True, vertical_alignment='center'):
            st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(connected.identity.hostname)}** · '
                        f'{md_escape(connected.host)}:{connected.port} via {connected.identity.transport.upper()}')
            if st.button('Disconnect', key='servers_disconnect', type='tertiary', disabled=busy,
                         help=LOCKED if busy else 'End this session with the server. Nothing changes on the server.'):
                forget_connection(f'Disconnected from {connected.identity.hostname}. Nothing changed on the server.')
    scroll = st.session_state.pop(SHOW_FOUND, None)
    try:
        registry = ServerRegistry(database_path)
        if PENDING in st.session_state:
            _show_pending(registry, connected)
            if scroll:
                _scroll_to_found(scroll)
        saved = registry.all()
        st.subheader('My servers')
        if busy:
            st.info(f'The agents are working on {md_escape(connected.identity.hostname)} (see **Agentic hardening**). '
                    'Disconnecting, access changes and setup wait until they have finished.')
        if saved:
            _show_saved(registry, saved, connected, busy)
        else:
            st.info('No saved servers yet. Add one below.')
        # Access changes what running work depends on, so it waits until it has finished. (Ubuntu setup is done by
        # the pairing helper itself since 13 November 2026, so this page no longer has a Set up section.)
        if (connected is not None and not busy and connected.identity.platform == 'windows'
                and connected.target is not None):
            st.subheader(f'Who can reach {md_escape(connected.identity.hostname)}')
            _show_access(registry, connected)
        st.subheader('Add a server')
        _show_add_by_code(connected)
    except (ValueError, OSError, sqlite3.Error) as exc:
        st.error('Servers: ' + md_escape(exc))
    _show_helpers()
