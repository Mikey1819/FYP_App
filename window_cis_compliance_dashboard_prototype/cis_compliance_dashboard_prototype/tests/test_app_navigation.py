"""The whole app (app.py): Servers comes first, and the connected server's system decides which workspace opens.
No server or model is contacted: a connection is a target placed in the session, as the Servers page leaves it."""
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar
import os
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from streamlit.util import calc_hash

from hardening.connection_view import LIVE_TARGET
from hardening.servers_view import NOTICE
from test_winrm_channel import target

APP = Path(__file__).resolve().parents[1] / 'app.py'
WORKSPACE = ('overview', 'agentic', 'history')


@dataclass(frozen=True)
class UbuntuTarget:
    """Stands in for the Ubuntu connection that is not built yet: only what the pages read."""
    workspace: ClassVar[str] = 'ubuntu'
    hostname: str = 'ubuntu-web01'
    machine_uuid: str = '4c4c4544-0000-1000-8000-000000000001'
    username: str = 'admin'
    host: str = '192.168.56.20'
    port: int = 22


def text(app):
    return ' '.join(e.value.replace('\\', '') for kind in (app.markdown, app.info, app.caption, app.success)
                    for e in kind)


class AppNavigationTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        patcher = patch.dict(os.environ, {'CIS_DASHBOARD_DB': str(Path(folder.name) / 'preview.sqlite3')})
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

    def test_an_ubuntu_server_opens_the_ubuntu_workspace_in_the_same_three_places(self):
        app = self.open(**{LIVE_TARGET: UbuntuTarget()})
        self.assertEqual(app.title[0].value, 'Overview')
        self.assertIn('Workspace: Ubuntu Linux', text(app))
        for page, title in zip(WORKSPACE, ('Overview', 'Agentic hardening', 'History and configuration drift')):
            with self.subTest(page=page):
                shown = self.open(page, app=app)
                self.assertEqual(shown.title[0].value, title)
                self.assertIn('Checks for Ubuntu are not linked to this program yet', text(shown))
                self.assertNotIn('No assessments yet', text(shown))  # Not the Windows page.

    def test_a_target_with_no_workspace_stays_on_servers(self):
        @dataclass(frozen=True)
        class Unknown(UbuntuTarget):
            workspace: ClassVar[str] = 'solaris'
        self.assertEqual(self.open('overview', **{LIVE_TARGET: Unknown()}).title[0].value, 'Servers')


if __name__ == '__main__':
    unittest.main()
