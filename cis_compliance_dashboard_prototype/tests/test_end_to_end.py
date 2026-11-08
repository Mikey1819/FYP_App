"""The whole program as an administrator uses it, through app.py and the real connection service, ledger and Windows
backend: pair a Windows Server 2022 by its code on Servers, open the workspace, run an agentic round, approve, execute,
verify, read Overview and History, assess without AI, disconnect, reconnect from My servers and resume.

Only the edges are stand-ins: the server is a simulated VM behind a fake WinRM session (tests/test_agentic.FakeVm), the
local model is scripted, and the pairing answer is given (UDP pairing is tested in test_pairing_flow.py). All data goes
to a temporary folder. Nothing reaches a real server or model."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from streamlit.util import calc_hash

from hardening import agentic, servers_view, winrm_channel
from hardening.pairing_client import FoundServer
from hardening.server_control import HELPER
from system.bootstrap import CONNECTION_KEY, WORKFLOW_KEY
from system.config import IntegrationPaths
from test_agentic import FakeVm, TeamDouble, call, clients, plan
from test_agentic_view import ScriptedModel
from test_winrm_channel import MACHINE_UUID

APP = Path(__file__).resolve().parents[1] / 'app.py'
HELPER_TEXT = HELPER.read_text(encoding='utf-8-sig')
WS2022 = ('windows', 'Microsoft Windows Server 2022 Standard Evaluation', '10.0.20348')
FOUND = FoundServer('192.168.56.10', 'FIXTURE-SERVER', MACHINE_UUID, 5985, 'a' * 32, '192.168.56.1', *WS2022)


class PairedVm:
    """The simulated VM, plus the server access helper's pairing list (the only other script the Servers page sends)."""

    def __init__(self):
        self.vm = FakeVm()

    def __call__(self, login):
        self.inner = self.vm(login)
        return self

    def run(self, script, parameters=None):
        if script == HELPER_TEXT:
            return [json.dumps(dict(hostname='FIXTURE-SERVER', machine_uuid=MACHINE_UUID, helper_enabled_remoting=False,
                                    pairings=[dict(pairing_id='a' * 32, laptop_address='192.168.56.1',
                                                   laptop_name='DESKTOP-KHOO', paired_at='2026-11-08T10:00:00+00:00')]))], False, []
        return self.inner.run(script, parameters)


def text(app):
    return ' '.join(e.value.replace('\\', '') for kind in (app.markdown, app.info, app.caption, app.success, app.warning)
                    for e in kind)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        data = Path(folder.name)
        self.paths = IntegrationPaths(APP.parent, data / 'windows' / 'imports.sqlite3', data / 'ubuntu' / 'imports.sqlite3',
                                      data / 'integration.sqlite3')
        self.server = PairedVm()
        t = 'windows:' + MACHINE_UUID
        ScriptedModel.team = TeamDouble(clients(t, [
            call('delegate_scanner', t), call('delegate_analysis', t),
            plan(t, fixes=[('1.2.2', 'REM-1.2.2', 'high_risk'), ('1.1.1', 'REM-1.1.1', 'low_impact')],
                 skipped=[('2.3.10.3', 'needs_review'), ('1.1.3', 'lower_priority'), ('18.10.57.3.9.4', 'needs_review')])]))
        for patcher in (patch('system.config.PATHS', self.paths),
                        patch.object(winrm_channel, 'PsrpSession', self.server),
                        patch.object(servers_view, 'find_server', lambda code: FOUND),
                        patch.object(agentic, 'OllamaClient', ScriptedModel),
                        patch('hardening.ollama_client.model_available', lambda: True)):
            patcher.start(); self.addCleanup(patcher.stop)

    def ok(self, app):
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertFalse(list(app.error), [e.value for e in app.error])
        return app

    def go(self, app, page):
        app._page_hash = calc_hash(page)
        return self.ok(app.run())

    def test_pair_assess_approve_execute_verify_history_and_resume(self):
        app = self.ok(AppTest.from_file(str(APP), default_timeout=90).run())
        self.assertEqual(app.title[0].value, 'Servers')

        # Pair by code: only the code and the login are typed.
        app.text_input(key='servers_code').input('482-913-075').run()
        app = self.ok(app.button(key='servers_find').click().run())
        app.text_input(key='servers_pair_password').input('FIXTURE-SECRET-SENTINEL').run()
        app = self.ok(app.button(key='servers_pair_finish').click().run())
        self.assertEqual(app.title[0].value, 'Overview')  # The workspace opens once connected.
        self.assertIn('Workspace: Windows Server 2022', text(app))

        # Agentic round through the Windows backend: scan, analyse, plan; nothing is written yet.
        app = self.go(app, 'agentic')
        app = self.ok(app.button(key='agentic_run').click().run())
        self.assertEqual(self.server.vm.writes, [])
        self.assertTrue(any('Proposed for your approval, in order: 1.2.2' in c for c in
                            (c.value.replace('\\', '') for c in app.caption)))
        app.text_input(key='agentic_operator').input('admin01').run()
        approve = [b for b in app.button if b.key.startswith('agentic_approve_') and b.key != 'agentic_approve_all']
        app = self.ok(approve[0].click().run())
        reject = [b for b in app.button if b.key.startswith('agentic_reject_') and b.key != 'agentic_reject_all']
        app = self.ok(reject[0].click().run())

        # Execution needs the explicit confirmation listing the change; then verify by rescan.
        app = self.ok(app.button(key='agentic_execute_review').click().run())
        self.assertEqual(self.server.vm.writes, [])
        app = self.ok(app.button(key='agentic_execute').click().run())
        self.assertEqual(self.server.vm.writes, ['1.2.2'])
        verdicts = [row for frame in app.dataframe for row in frame.value.to_dict('records') if 'Verdict' in row]
        self.assertEqual([v['Verdict'] for v in verdicts], ['Verified compliant'])

        # Overview and History read the same records.
        overview = self.go(app, 'overview')
        metrics = {m.label: m.value for m in overview.metric}
        self.assertEqual(metrics['Fixes awaiting you'], '0')
        history = self.go(app, 'history')
        self.assertEqual(history.title[0].value, 'History and configuration drift')

        # Assess without AI: a deterministic scan with no proposals.
        app = self.go(app, 'agentic')
        app = self.ok(app.button(key='agentic_assess_without_ai').click().run())
        workflow = app.session_state[WORKFLOW_KEY]

        # Disconnect from the sidebar; reconnect from My servers with the password only; resume the session.
        app = self.ok(app.button(key='sidebar_disconnect').click().run())
        self.assertNotIn(CONNECTION_KEY, app.session_state)
        self.assertEqual(app.title[0].value, 'Servers')
        app = self.go(app, 'servers')  # The browser's address follows the redirect to /servers; AppTest's does not.
        app.text_input(key='servers_password').input('FIXTURE-SECRET-SENTINEL').run()
        app = self.ok(app.button(key='servers_connect').click().run())
        self.assertEqual(app.title[0].value, 'Overview')
        app = self.go(app, 'agentic')
        app = self.ok(app.button(key='agentic_resume').click().run())
        self.assertEqual(app.session_state[WORKFLOW_KEY], workflow)

        for database in Path(self.paths.coordination).parent.rglob('*.sqlite3'):
            self.assertNotIn(b'FIXTURE-SECRET-SENTINEL', database.read_bytes(), database.name)


if __name__ == '__main__':
    unittest.main()
