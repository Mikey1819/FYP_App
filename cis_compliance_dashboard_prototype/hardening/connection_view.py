"""Live VM connection: the agents reach the VM themselves over PowerShell Remoting."""
import streamlit as st

from .server_access import helper_bundle, helper_sha256
from .ui import md_escape
from .winrm_channel import DEFAULT_HOST, DEFAULT_PORT, LiveScanner, WinRmTarget
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY, connection_service, bind_form, invalidate_changed_form
from system.contracts import ConnectionRequest, Endpoint
from system.session import Credentials, clear_target_state

LIVE_TARGET = 'vm_live_target'


def render_connection(*, key):
    """Returns the verified target, or None. Once connected, the target itself is the registration: the form
    is not shown again until the administrator disconnects, so switching pages never drops the connection."""
    if st.session_state.pop(key + '_clear_secrets', False):
        for secret in (key + '_password', key + '_sudo_password'):
            st.session_state.pop(secret, None)
    result = st.session_state.pop(key + '_connection_result', None)
    if result and result.state != 'connected':
        st.error('Not connected (' + result.diagnostic_code + '): ' + md_escape(result.detail))
    if invalidate_changed_form(st.session_state):
        st.info('Connection details changed. Connect again to verify this target.')
    target = st.session_state.get(LIVE_TARGET)
    service = st.session_state.get(SERVICE_KEY)
    connection_id = st.session_state.get(CONNECTION_KEY)
    if connection_id:
        verified = service.session(connection_id)
        with st.container(horizontal=True, vertical_alignment='center'):
            st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(verified.identity.hostname)}** · '
                        f'{md_escape(verified.identity.os_version)} via {verified.identity.transport.upper()} · '
                        f'{md_escape(verified.host)}:{verified.port}')
            if st.button('Disconnect', key=key + '_disconnect', type='tertiary'):
                service.disconnect(connection_id)
                clear_target_state(st.session_state)
                for secret in (key + '_password', key + '_sudo_password'):
                    st.session_state.pop(secret, None)
                st.rerun()
        return verified.target if verified.identity.platform == 'windows' else verified
    if target is not None:
        with st.container(horizontal=True, vertical_alignment='center'):
            st.markdown(f':green-badge[:material/lan: Connected] **{md_escape(target.hostname)}** · '
                        f'{md_escape(target.username)} via {md_escape(target.host)}:{target.port} · '
                        f'UUID {md_escape(target.machine_uuid)}')
            if st.button('Disconnect', key=key + '_disconnect', type='tertiary'):
                clear_target_state(st.session_state)
                st.rerun()
        return target
    with st.container(border=True):
        st.markdown('**Connect to the VM**')
        left, right = st.columns(2)
        hostname = left.text_input('VM computer name', key=key + '_hostname', persist_state='session')
        machine_uuid = right.text_input('VM machine identity', key=key + '_uuid', persist_state='session',
                                       help='Windows machine UUID or Ubuntu /etc/machine-id (32 hexadecimal characters).')
        left, middle, right = st.columns([2, 1, 2])
        host = left.text_input('VM IP address / host', value='',
                               key=key + '_host', persist_state='session')
        port = middle.number_input('Port', value=None, min_value=1, max_value=65535, key=key + '_port',
                                   persist_state='session')
        username = right.text_input('Username', value='', key=key + '_user',
                                    persist_state='session')
        # Not persisted: once connected, the password lives only inside the target in this session's memory.
        password = st.text_input('Password', type='password', key=key + '_password')
        with st.expander('Advanced settings'):
            method = st.selectbox('Transport', ('Auto', 'SSH', 'WinRM'), key=key + '_method')
            auth = st.selectbox('SSH authentication', ('Password', 'Selected key'), key=key + '_auth')
            key_path = st.text_input('Selected SSH private key path', key=key + '_key_path',
                                     disabled=auth != 'Selected key', help='Only this key is used. SSH agent and key searching are disabled.')
            sudo_password = st.text_input('Separate sudo password (optional)', type='password', key=key + '_sudo_password',
                                          help='Session-only. Does not authorize setup or elevated changes.')
            fingerprint = st.text_input('Independently verified SSH SHA256 fingerprint', key=key + '_fingerprint',
                                        help='Read this from the VM console. An unknown key is never accepted automatically.')
            st.caption('A changed host key requires deliberate re-enrolment; entering a replacement fingerprint here cannot override it.')
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
        ready = all(value.strip() for value in (hostname, machine_uuid, host, username)) and port is not None and bool(
            key_path.strip() if auth == 'Selected key' else password)
        if st.button('Connect and check identity', key=key + '_connect', disabled=not ready, type='primary'):
            service = connection_service(st.session_state)
            credential_ref = service.vault.put(Credentials(username.strip(), password if auth == 'Password' else None,
                key_path.strip() if auth == 'Selected key' else None, sudo_password or None, fingerprint.strip() or None))
            result = service.connect(ConnectionRequest(Endpoint(host.strip(), int(port), method.lower()),
                hostname.strip(), machine_uuid.strip(), credential_ref))
            # Widget secrets are removed on the next rerun, before the widgets are constructed.
            st.session_state[key + '_clear_secrets'] = True
            st.session_state[key + '_connection_result'] = result
            if result.state == 'connected':
                st.session_state[CONNECTION_KEY] = result.connection_session_id
                bind_form(st.session_state,key)
                session = service.session(result.connection_session_id)
                st.session_state[LIVE_TARGET] = session.target if session.identity.platform == 'windows' else None
            st.rerun()
    return None
