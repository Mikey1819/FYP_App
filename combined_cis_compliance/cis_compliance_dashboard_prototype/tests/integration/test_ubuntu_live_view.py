"""The live agent view on the Ubuntu page shows the agent at work one at a time, as on Windows (user report,
13 November 2026: all three Ubuntu cards glowed at once). The view had no log to read for Ubuntu, so it marked every
agent "working…". It now reads the Ubuntu agents' own log, with their role names shown as the names the view knows.
No VM, no model: a temporary store and the unchanged InvestigationLog."""
from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as N
from unittest import mock


class Tools:
    def __init__(self, store, role):
        self.store, self.agent_role, self.assessment_id, self.team_id = store, role, 'a', 't'
        self.target_id = 'ubuntu:fixture'
        self.scenario, self.evidence_mode, self.proposal_id = 'ubuntu-agentic-round', 'Live (SSH)', None


class UbuntuLiveViewTests(unittest.TestCase):
    def setUp(self):
        from backends.ubuntu.storage import UbuntuStore
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / 'ubuntu.sqlite3'
        self.store = UbuntuStore(self.path)

    def run_of(self, role, finished):
        from hardening.investigation import InvestigationLog, Limits
        log = InvestigationLog(self.store.agent_log())
        run_id = log.start(Tools(self.store.agent_log(), role), N(model='qwen3:8b', provenance='Local Ollama'), Limits())
        log.append(run_id, 'tool', {'name': 'scan_target', 'arguments': {}, 'result': {}})
        if finished:
            log.append(run_id, 'finished', {'status': 'Completed', 'summary': 'done'})

    def backend(self):
        from backends.ubuntu.adapter import UbuntuBackend
        backend = UbuntuBackend.__new__(UbuntuBackend)
        backend.database_path = self.path
        backend.session = N(identity=N(platform='ubuntu'))
        return backend

    def test_only_the_agent_at_work_is_active_under_the_names_the_view_knows(self):
        from hardening import live_progress
        from hardening.agentic import ANALYSIS, SCANNER
        from hardening.agentic_view import _live_store
        since = datetime.now(timezone.utc) - timedelta(seconds=5)
        self.run_of('orchestrator', finished=False)
        self.run_of('scanner', finished=True)
        self.run_of('analysis', finished=False)
        with mock.patch('hardening.agentic_view.active_backend', return_value=self.backend()):
            store = _live_store(None, None)
        self.assertIsNotNone(store)  # before: None, so every card read "working…"
        state = live_progress.progress(store, since)
        self.assertEqual((state['active'], state['done']), (ANALYSIS, {SCANNER}))
        html = live_progress.stage_html(live_progress.phase_roles('Agentic round'), state)
        self.assertEqual(html.count('class="fyp-agent fyp-active"'), 1)  # one card glows, not three
        self.assertEqual(html.count('class="fyp-agent fyp-done"'), 1)

    def test_before_the_first_round_there_is_simply_nothing_running_yet(self):
        from hardening import live_progress
        from hardening.agentic_view import _live_store
        backend = self.backend()
        backend.database_path = self.path.with_name('not-created-yet.sqlite3')
        with mock.patch('hardening.agentic_view.active_backend', return_value=backend):
            store = _live_store(None, None)
        state = live_progress.progress(store, datetime.now(timezone.utc))
        self.assertEqual((state['active'], state['done']), (None, set()))
        self.assertFalse(backend.database_path.exists())  # reading never creates the Ubuntu store


if __name__ == '__main__':
    unittest.main()
