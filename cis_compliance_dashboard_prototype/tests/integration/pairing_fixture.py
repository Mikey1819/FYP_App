"""Connect a page test the way the Servers page does once a pairing code has found the server.

The connection form with typed hostname, machine identity and address is gone: servers are paired by code
(hardening/servers_view.py, tested on its own in test_servers_page.py). Page tests that start after the connection use
this helper, which gives the shared connection service exactly what a successful pairing gives it.
"""
from hardening.connection_view import LIVE_TARGET
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from system.contracts import ConnectionRequest, Endpoint
from system.session import Credentials

SECRET = 'FIXTURE-SECRET-SENTINEL'


def paired_connect(app, *, platform, hostname, identity, host='fixture.invalid', port=None, username='fixture-user',
                   password=SECRET, fingerprint=None, run=True):
    """Returns the connection result; on success the app holds the connection as the Servers page leaves it."""
    service = app.session_state[SERVICE_KEY]
    reference = service.vault.put(Credentials(username, password, None, None, fingerprint))
    transport = 'winrm' if platform == 'windows' else 'ssh'
    result = service.connect(ConnectionRequest(Endpoint(host, port or (5985 if platform == 'windows' else 22),
                                                        transport), hostname, identity, reference), paired=True)
    if result.state == 'connected':
        session = service.session(result.connection_session_id)
        app.session_state[CONNECTION_KEY] = result.connection_session_id
        app.session_state[LIVE_TARGET] = session.target if platform == 'windows' else None
    if run:
        app.run()
    return result
