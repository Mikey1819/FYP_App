"""Live VM connection form: the agents reach the VM themselves over PowerShell Remoting."""
import streamlit as st

from .winrm_channel import DEFAULT_HOST, DEFAULT_PORT, LiveScanner, WinRmTarget

LIVE_TARGET = 'vm_live_target'


def render_connection(hostname, machine_uuid, *, key):
    """Connect form. Returns the verified target, or None."""
    st.caption('The agents reach the VM themselves over PowerShell Remoting (see VM_CONNECTION.md). '
               'The password stays in this browser session’s memory only; it is never saved, logged or sent to the model.')
    left, right = st.columns(2)
    host = left.text_input('WinRM host (laptop side of the port forward)', value=DEFAULT_HOST, key=key + '_host')
    port = right.number_input('WinRM port', value=DEFAULT_PORT, min_value=1, max_value=65535, key=key + '_port')
    username = st.text_input('VM administrator account', value='Administrator', key=key + '_user')
    password = st.text_input('Password', type='password', key=key + '_password')
    ready = all(value.strip() for value in (hostname, machine_uuid, host, username, password))
    if st.button('Connect and check identity', key=key + '_connect', disabled=not ready):
        target = WinRmTarget(hostname.strip(), machine_uuid.strip(), username.strip(), password,
                             host.strip(), int(port))
        status = LiveScanner(None, target).worker_status(target.hostname, target.machine_uuid)
        if status['state'] == 'ready':
            st.session_state[LIVE_TARGET] = target
        else:
            st.session_state.pop(LIVE_TARGET, None)
            st.error('Not connected (' + status['state'] + '): ' + status['detail'])
    target = st.session_state.get(LIVE_TARGET)
    if target is None:
        return None
    if (target.hostname.casefold() != hostname.strip().casefold()
            or target.machine_uuid.casefold() != machine_uuid.strip().casefold()):
        st.warning('The live connection belongs to a different VM registration. Connect again.')
        return None
    st.success('Connected to ' + target.hostname + ' as ' + target.username + ' via '
               + target.host + ':' + str(target.port) + '.')
    return target
