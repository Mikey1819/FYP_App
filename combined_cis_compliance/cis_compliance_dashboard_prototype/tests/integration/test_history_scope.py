"""Managed pages must never read another platform's store (synthetic backend)."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
from system.bootstrap import SERVICE_KEY, CONNECTION_KEY


def history_page():
    import streamlit as st
    from pathlib import Path
    from hardening.history_view import render_history
    render_history(Path(st.session_state['fixture_database']))


def overview_page():
    import streamlit as st
    from pathlib import Path
    from hardening.overview_view import render_overview
    render_overview(Path(st.session_state['fixture_database']))


class FixtureBackend:
    session = SimpleNamespace(target_id='ubuntu:fixture', identity=SimpleNamespace(platform='ubuntu', hostname='UBUNTU-FIXTURE'))

    def history(self, target_id=None, limit=50):
        assert target_id == self.session.target_id
        return ()


class FixtureService:
    def backend_for(self, connection):
        assert connection == 'fixture-connection'
        return FixtureBackend()


class HistoryScopeTests(unittest.TestCase):
    def test_ubuntu_pages_do_not_open_windows_evidence_store(self):
        with tempfile.TemporaryDirectory() as folder:
            for page, module in ((overview_page, 'overview_view'), (history_page, 'history_view')):
                with self.subTest(page=module), patch('hardening.' + module + '.ImportedEvidenceStore',
                        side_effect=AssertionError('Cross-platform store read')):
                    app = AppTest.from_function(page, default_timeout=30)
                    app.session_state[SERVICE_KEY] = FixtureService()
                    app.session_state[CONNECTION_KEY] = 'fixture-connection'
                    app.session_state['fixture_database'] = str(Path(folder) / 'windows.sqlite3')
                    app.run()
                    self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
                    self.assertTrue(any('start the first round' in s.value for s in app.success))  # 2026-11-13
                    self.assertFalse(any('No assessments' in i.value for i in app.info))
            self.assertFalse(list(Path(folder).glob('*.sqlite3')))
