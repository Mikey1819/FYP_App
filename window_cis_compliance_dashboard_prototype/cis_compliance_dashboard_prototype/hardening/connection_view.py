"""Live VM connection: the agents reach the VM themselves over PowerShell Remoting."""
import streamlit as st

from .server_access import helper_bundle, helper_sha256
from .ui import md_escape
from .winrm_channel import DEFAULT_HOST, DEFAULT_PORT, LiveScanner, WinRmTarget

LIVE_TARGET = 'vm_live_target'


def render_connection(*, key):
    """Returns the verified target, or None. Once connected, the target itself is the registration: the form
    is not shown again until the administrator disconnects, so switching pages never drops the connection."""
    target = st.session_state.get(LIVE_TARGET)
    if target is not None:
        with st.container(horizontal=True, vertical_alignment='center'):
            st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(target.hostname)}** · '
                        f'{md_escape(target.username)} via {md_escape(target.host)}:{target.port} · '
                        f'UUID {md_escape(target.machine_uuid)}')
            if st.button('Disconnect', key=key + '_disconnect', type='tertiary'):
                del st.session_state[LIVE_TARGET]
                st.rerun()
        return target
    with st.container(border=True):
        st.markdown('**Connect to the VM**')
        left, right = st.columns(2)
        hostname = left.text_input('VM computer name', key=key + '_hostname', persist_state='session')
        machine_uuid = right.text_input('VM machine UUID', key=key + '_uuid', persist_state='session')
        left, middle, right = st.columns([2, 1, 2])
        host = left.text_input('WinRM host (127.0.0.1 for the lab port forward, or the server address)', value=DEFAULT_HOST,
                               key=key + '_host', persist_state='session')
        port = middle.number_input('Port', value=DEFAULT_PORT, min_value=1, max_value=65535, key=key + '_port',
                                   persist_state='session')
        username = right.text_input('Administrator account', value='Administrator', key=key + '_user',
                                    persist_state='session')
        # Not persisted: once connected, the password lives only inside the target in this session's memory.
        password = st.text_input('Password', type='password', key=key + '_password')
        st.caption('The password is never saved, logged or sent to the model. Setup: docs/vm/VM_CONNECTION_SETUP.md.')
        with st.expander('Scanning by network address? Optional server access helper'):
            st.markdown('**Not needed for the lab VM through the port forward** (`127.0.0.1:55985`): WinRM is '
                        'already set up inside it. Use the helper only to scan a server by its network address, '
                        'such as another server or the VM through a host-only adapter.')
            st.markdown('Run it **on that server**, as administrator: it shows the computer name, UUID and addresses '
                        'for this form, lets only your laptop’s address reach WinRM, and **Revert** undoes it after '
                        'scanning.')
            st.download_button('Download helper (.zip)', helper_bundle(), file_name='FYP-ServerAccess.zip',
                               mime='application/zip', key=key + '_helper', icon=':material/download:',
                               on_click='ignore')
            st.caption('Before running it, check on the server: `Get-FileHash .\\FYP-ServerAccess.ps1` must print '
                       f'`{helper_sha256().upper()}`.')
        ready = all(value.strip() for value in (hostname, machine_uuid, host, username, password))
        if st.button('Connect and check identity', key=key + '_connect', disabled=not ready, type='primary'):
            target = WinRmTarget(hostname.strip(), machine_uuid.strip(), username.strip(), password,
                                 host.strip(), int(port))
            status = LiveScanner(None, target).worker_status(target.hostname, target.machine_uuid)
            if status['state'] != 'ready':
                st.error('Not connected (' + status['state'] + '): ' + md_escape(status['detail']))
                return None
            st.session_state[LIVE_TARGET] = target
            st.rerun()
    return None
