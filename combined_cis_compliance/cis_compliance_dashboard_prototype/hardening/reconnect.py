"""A fresh login to the connected Ubuntu server, made by the dashboard itself.

A "confirm after reconnect" change (SSH and firewall fixes, and the execution acceptance test) may be kept only when a
login that began after the server reported the change waiting has succeeded: that login is the proof the change did
not lock the management channel out (backends/ubuntu/adapter.py, confirm_change and confirm_acceptance). The dashboard
opens that login itself with the account the administrator logged in with, instead of asking for a disconnect and a
reconnect. If the new login fails, nothing is confirmed and the server's own timer restores the change.

The login is remembered in this browser session's memory only while connected (as the Windows target keeps its
password), never written anywhere, and forgotten on Disconnect (system/session.clear_target_state).
"""
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from system.contracts import ConnectionRequest, Endpoint
from system.session import Credentials, clear_target_state

RECONNECT = 'integration_reconnect'


def remember(state, *, host, port, hostname, identity, username, password=None, key_path=None, sudo=None):
    state[RECONNECT] = dict(host=host, port=port, hostname=hostname, identity=identity, username=username,
                            password=password, key_path=key_path, sudo=sudo)


def can_reconnect(state):
    return RECONNECT in state


def fresh_login(state):
    """End the current connection and log in again with the same account; returns the new connection's ID.
    Raises ValueError, with the connection closed, when the new login does not succeed."""
    login = state.get(RECONNECT)
    if login is None:
        raise ValueError('The login is not remembered for this connection: disconnect and connect again on Servers.')
    service = state[SERVICE_KEY]
    old = state.get(CONNECTION_KEY)
    if old:
        try:
            service.disconnect(old)
        except ValueError:
            pass  # Already closed.
    reference = service.vault.put(Credentials(login['username'], login['password'], login['key_path'], login['sudo']))
    result = service.connect(ConnectionRequest(Endpoint(login['host'], login['port'], 'ssh'), login['hostname'],
                                               login['identity'], reference))
    if result.state != 'connected':
        clear_target_state(state)
        raise ValueError(f'The fresh login failed ({result.diagnostic_code}), so nothing was confirmed; the server '
                         'restores the change by itself. Connect again on Servers to check it.')
    state[CONNECTION_KEY] = result.connection_session_id
    state[RECONNECT] = login
    return result.connection_session_id
