"""The whole app (app.py): Servers comes first, and the connected server's system decides what the workspace shows.
No server or model is contacted: a connection is what the Servers page leaves in the session after pairing, through
the shared connection service with fixture channels. Data goes to a temporary folder, never the app's data folder."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from streamlit.util import calc_hash

from hardening.connection_view import LIVE_TARGET
from hardening.servers_view import NOTICE
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from system.config import IntegrationPaths
from system.connection import ConnectionService
from system.identity import VerifiedIdentity
from system.ledger import CoordinationLedger
from test_winrm_channel import target
from tests.integration.pairing_fixture import paired_connect

APP = Path(__file__).resolve().parents[1] / 'app.py'
WORKSPACE = ('overview', 'agentic', 'history')


class FixtureSsh:
    def verify_identity(self, request):
        return VerifiedIdentity('ubuntu', request.expected_hostname, request.expected_machine_identity, '22.04', 'ssh',
                                'SHA256:' + 'a' * 43)

    def close(self):
        pass


def text(app):
    return ' '.join(e.value.replace('\\', '') for kind in (app.markdown, app.info, app.caption, app.success)
                    for e in kind)


class AppNavigationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        data = Path(folder.name)
        self.paths = IntegrationPaths(APP.parent, data / 'windows' / 'imports.sqlite3', data / 'ubuntu' / 'imports.sqlite3',
                                      data / 'integration.sqlite3')
        patcher = patch('system.config.PATHS', self.paths)
        patcher.start(); self.addCleanup(patcher.stop)

    def open(self, page=None, app=None, **state):
        app = app or AppTest.from_file(str(APP), default_timeout=30).run()
        for key, value in state.items():
            app.session_state[key] = value
        if page:
            app._page_hash = calc_hash(page)  # As if the address /<page> was typed in the browser.
        app.run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        return app

    def test_the_app_opens_on_servers_until_a_server_is_connected(self):
        app = self.open()
        self.assertEqual(app.title[0].value, 'Servers')
        self.assertIn('No server connected', text(app))
        self.assertIn('Windows Server 2022 (stand-alone) and Ubuntu 22.04.5 LTS', text(app))
        self.assertNotIn('sidebar_disconnect', [b.key for b in app.button])

    def test_workspace_pages_cannot_be_opened_by_their_address_before_connecting(self):
        for page in WORKSPACE:
            with self.subTest(page=page):
                self.assertEqual(self.open(page).title[0].value, 'Servers')

    def test_connecting_opens_the_windows_workspace_on_overview(self):
        app = self.open()  # On Servers; the Servers page then connects and says so.
        app = self.open(app=app, **{LIVE_TARGET: target(), NOTICE: 'Connected to FIXTURE-SERVER.'})
        self.assertEqual(app.title[0].value, 'Overview')
        self.assertIn('Workspace: Windows Server 2022', text(app))
        self.assertIn('Connected to FIXTURE-SERVER.', [t.value.replace('\\', '') for t in app.toast])
        self.assertNotIn(NOTICE, app.session_state)  # Not shown again later on the Servers page.
        self.assertEqual(self.open('history', app=app).title[0].value, 'History and configuration drift')

    def test_the_servers_page_stays_reachable_once_connected(self):
        app = self.open(**{LIVE_TARGET: target()})
        self.assertEqual(self.open('servers', app=app).title[0].value, 'Servers')  # Moved there once only.

    def test_disconnecting_from_the_sidebar_returns_to_servers(self):
        app = self.open(**{LIVE_TARGET: target()})
        app.button(key='sidebar_disconnect').click().run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertNotIn(LIVE_TARGET, app.session_state)
        self.assertEqual(app.title[0].value, 'Servers')
        self.assertIn('Disconnected from FIXTURE-SERVER. Nothing changed on the server.', text(app))
        self.assertEqual(self.open('agentic', app=app).title[0].value, 'Servers')

    def test_a_paired_ubuntu_server_opens_its_workspace_in_the_same_three_places(self):
        app = AppTest.from_file(str(APP), default_timeout=30)
        app.session_state[SERVICE_KEY] = ConnectionService(CoordinationLedger(self.paths.coordination),
                                                           ssh_factory=lambda *a: FixtureSsh())
        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname='ubuntu-web01', identity='b' * 32).state,
                         'connected')
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertEqual(app.title[0].value, 'Overview')
        self.assertIn('Workspace: Ubuntu 22.04 LTS', text(app))
        for page, title in zip(WORKSPACE, ('Overview', 'Agentic hardening', 'History and configuration drift')):
            with self.subTest(page=page):
                shown = self.open(page, app=app)
                self.assertEqual(shown.title[0].value, title)
                self.assertIn('ubuntu-web01', text(shown))
        app.button(key='sidebar_disconnect').click().run()
        self.assertNotIn(CONNECTION_KEY, app.session_state)
        self.assertEqual(app.title[0].value, 'Servers')

    def test_overview_and_history_list_every_saved_server_and_show_another_one_read_only(self):
        from hardening.servers import ServerRegistry
        ServerRegistry(self.paths.servers).add('ubuntu', 'b' * 32, 'ubuntu-web01', 'Ubuntu 22.04.5 LTS', '192.168.56.20', 22,
                                               'fyp-admin')
        for page in ('overview', 'history'):
            with self.subTest(page=page):
                app = self.open(page, app=self.open(**{LIVE_TARGET: target()}))  # After the one move to Overview.
                box = app.selectbox(key=page + '_server')
                self.assertEqual(len(box.options), 2)
                self.assertTrue(box.options[0].endswith('(connected)'))  # The connected server comes first.
                self.assertIn('ubuntu-web01 · Ubuntu 22.04 LTS', box.options[1])
                box.select_index(1).run()
                self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
                self.assertIn('No records yet for ubuntu-web01', text(app))  # Never connected: nothing stored.


if __name__ == '__main__':
    unittest.main()
