"""Check AI and the live validation register on the Windows pages (administrator, 14 November 2026: "implement it
inside the Windows site as well", the same words on both systems). A connected fake Windows server through the real
connection service and backend; Check AI is simulated, so no model is loaded and no server is changed."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from streamlit.testing.v1 import AppTest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_agentic import FakeVm
from test_winrm_channel import target
from hardening.winrm_channel import LiveScanner
from system.connection import ConnectionService
from system.ledger import CoordinationLedger
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY, WORKFLOW_KEY
from backends.windows.adapter import WindowsBackend
from tests.integration.pairing_fixture import paired_connect
from tests.integration.test_system_acceptance import existing_page


def overview_page():
    import streamlit as st
    from pathlib import Path
    from hardening.overview_view import render_overview
    render_overview(Path(st.session_state['fixture_database']))


def open_round_page():
    import streamlit as st
    from hardening.agentic_view import _windows_open_round
    from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
    connection = st.session_state[CONNECTION_KEY]
    _windows_open_round(st.session_state[SERVICE_KEY].backend_for(connection), connection, st.session_state['evidence'])


class WindowsPageModuleTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path, self.vm = Path(folder.name), FakeVm()
        ledger = CoordinationLedger(path / 'integration.sqlite3')
        factory = lambda runtime, t: LiveScanner(runtime, t, session_factory=self.vm)  # noqa: E731
        self.service = ConnectionService(ledger, windows_scanner_factory=factory, ssh_factory=None,
                                         backend_factory=lambda session: WindowsBackend(
                                             path / 'windows' / 'imports.sqlite3', session=session, ledger=ledger,
                                             scanner_factory=factory))
        self.app = AppTest.from_function(existing_page, default_timeout=30)
        self.app.session_state['fixture_database'] = str(path / 'windows' / 'imports.sqlite3')
        self.app.session_state[SERVICE_KEY] = self.service
        self.app.run()
        t = target()
        paired_connect(self.app, platform='windows', hostname=t.hostname, identity=t.machine_uuid)
        self.assertFalse(list(self.app.error), [e.value for e in self.app.error])

    def scan(self):
        """A read-only deterministic scan through the backend (as test_system_acceptance does)."""
        from hardening.agentic_view import SESSION
        connection = self.app.session_state[CONNECTION_KEY]
        handle = self.service.backend_for(connection).start_round(connection, None, None, 'deterministic', 'op-scan')
        self.app.session_state[WORKFLOW_KEY] = handle.binding.workflow_session_id
        self.app.session_state[SESSION] = handle.binding.backend_session_id
        self.app.run()
        return handle

    def other(self, page, **extra):
        """Another page in the same browser session."""
        app = AppTest.from_function(page, default_timeout=30)
        for key in ('fixture_database', SERVICE_KEY, CONNECTION_KEY, WORKFLOW_KEY):
            if key in self.app.session_state:
                app.session_state[key] = self.app.session_state[key]
        for key, value in extra.items():
            app.session_state[key] = value
        app.run()
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertFalse(list(app.error), [e.value for e in app.error])
        return app

    # ---- Check AI ------------------------------------------------------------------------------------------------
    def check_ai(self, state):
        from backends.ubuntu.ai_readiness import Readiness
        checks = []

        def fake_check():
            checks.append(1)
            return Readiness(state, 1.0, 6.0, '100% GPU', (), f'AI {state}: TEST-ONLY.')
        with mock.patch('backends.ubuntu.ai_readiness.check', side_effect=fake_check):
            self.assertFalse(self.app.button(key='agentic_run').disabled)
            self.assertEqual(checks, [])  # never by itself
            self.assertIn('Optional: Check AI loads the local model and shows whether it is fast enough.',
                          [c.value for c in self.app.caption])
            self.app.button(key='agentic_ai_check').click().run()
            self.assertEqual(checks, [1])
        return self.app

    def test_check_ai_before_the_first_round_and_not_answering_keeps_start_disabled(self):
        app = self.check_ai('down')
        self.assertEqual(app.button(key='agentic_run').label, 'Start agentic round')
        self.assertTrue(app.button(key='agentic_run').disabled)
        self.assertIn('AI down: TEST-ONLY.', [e.value.replace('\\', '') for e in app.error])
        self.assertEqual(self.vm.writes, [])  # Check AI never contacts the server

    def test_check_ai_before_the_next_round_and_ready_leaves_it_enabled(self):
        self.scan()
        app = self.check_ai('ready')
        self.assertEqual(app.button(key='agentic_run').label, 'Run next round')
        self.assertFalse(app.button(key='agentic_run').disabled)
        self.assertTrue(any('check took' in m.value for m in app.markdown))

    # ---- Live validation register --------------------------------------------------------------------------------
    def register(self, app):
        return {r['Control']: r for frame in app.dataframe for r in frame.value.to_dict('records')
                if 'Proven (MYT)' in r}

    def test_overview_shows_the_register_once_there_is_an_assessment_in_the_ubuntu_words(self):
        from tools.live_validation_register import NOTE
        REGISTER_NOTE = NOTE + ' From the stored records only; nothing here can be edited.'
        self.assertEqual(self.register(self.other(overview_page)), {})  # nothing scanned yet: no register
        self.scan()
        self.assertEqual(self.register(self.app), {})  # on Overview, not on Agentic hardening (as Ubuntu)
        over = self.other(overview_page)
        rows = self.register(over)
        self.assertEqual(len(rows), 32)
        self.assertEqual({c for c, r in rows.items() if r['Status'] == 'Manual on the server'},
                         {'9.2.1', '9.2.2', '9.3.1', '9.3.2'})
        self.assertEqual(rows['1.1.4']['Title'], 'Minimum password length')
        self.assertTrue(any(e.label.replace('\\', '') == f'Live validation register: 0 of 32 validated live on '
                                                         f'{target().hostname}'
                            for e in over.expander), [e.label for e in over.expander])
        self.assertIn(REGISTER_NOTE, [c.value for c in over.caption])
        self.assertEqual(self.vm.writes, [])

    def report(self, **extra):
        from hardening.round_report import round_report
        from tools.live_validation_register import NOTE
        handle = self.scan()
        connection = self.app.session_state[CONNECTION_KEY]
        backend = self.service.backend_for(connection)
        rounds = backend.store.rounds(handle.binding.backend_session_id)
        latest = [r for r in rounds if r['kind'] == 'assessment'][-1]
        html = round_report(backend.engine, rounds, latest, register=backend.live_validation(connection), **extra)
        self.assertIn(NOTE.replace('"', '&quot;'), html)  # the Ubuntu report's words
        self.assertIn('0 of 32 validated live on this server', html)
        self.assertIn('Manual on the server', html)
        return html, backend.engine, rounds, latest

    def test_the_round_report_ends_with_the_register_as_on_ubuntu(self):
        from hardening.round_report import round_report
        html, engine, rounds, latest = self.report()
        self.assertIn('<h2>7. Live validation register</h2>', html)
        self.assertNotIn('Live validation register', round_report(engine, rounds, latest))  # without a connection
        self.assertTrue(self.app.get('download_button'))  # the page's Round report builds with it (no exception)

    def test_the_completion_report_has_it_after_the_completion_section(self):
        completion = dict(operator='kk', completed_at='2026-11-14T01:00:00+00:00', final_run_id='run', compliant=28,
                          total=32, exceptions=[])
        html, *_ = self.report(completion=completion)
        self.assertLess(html.index('<h2>7. Completion</h2>'), html.index('<h2>8. Live validation register</h2>'))

    def test_open_the_round_resumes_that_session_and_round(self):
        from hardening.agentic_view import ROUND_VIEW, SESSION
        handle = self.scan()
        connection = self.app.session_state[CONNECTION_KEY]
        backend = self.service.backend_for(connection)
        round_id = backend.store.rounds(handle.binding.backend_session_id)[0]['round_id']
        page = self.other(open_round_page, evidence={'workflow': handle.binding.workflow_session_id,
                                                     'round_id': round_id})
        self.assertEqual(page.session_state[WORKFLOW_KEY], handle.binding.workflow_session_id)
        self.assertEqual(page.session_state[SESSION], handle.binding.backend_session_id)
        self.assertEqual(page.session_state[ROUND_VIEW], round_id)


if __name__ == '__main__':
    unittest.main()
