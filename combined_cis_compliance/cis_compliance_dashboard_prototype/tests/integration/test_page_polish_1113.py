"""Page changes of 13 November 2026 (administrator):
- the Ubuntu page says how long each phase took, as the Windows page does ("Assessment took 42 s (Scanner 11 s ·
  Analysis 10 s · Orchestrator planning 21 s), within the 10-minute limit per phase.");
- History and drift shows the same first-pairing message as Overview, for Ubuntu and Windows servers, instead of
  "No assessments yet" while a newly paired server has no scan.
Fakes only: no VM, no model.
"""
import unittest
from types import SimpleNamespace as N
from unittest import mock

from system.contracts import AgentEvent


def finished(role, seconds, phase='Assessment phase'):
    return AgentEvent('run-' + role, role, 'finished', '', '', 'Completed: done', '', 't', 'Local Ollama', phase,
                      1, seconds)


class PhaseLineTests(unittest.TestCase):
    def test_the_assessment_line_reads_as_on_windows(self):
        from hardening.agentic_view import _ubuntu_phase_lines
        events = [finished('scanner', 11), finished('analysis', 10), finished('orchestrator', 42)]
        self.assertEqual(_ubuntu_phase_lines(events),
                         ['Assessment took 42 s (Scanner 11 s · Analysis 10 s · Orchestrator planning 21 s), within '
                          'the 10-minute limit per phase.'])

    def test_the_remediation_phase_and_the_limit(self):
        from hardening.agentic_view import _ubuntu_phase_lines
        events = [finished('remediation', 30, 'Remediation phase'), finished('scanner', 400, 'Remediation phase'),
                  finished('orchestrator (review)', 700, 'Remediation phase')]
        [line] = _ubuntu_phase_lines(events)
        self.assertTrue(line.startswith('Remediation took 11 min 40 s (Remediation 30 s · Scanner 6 min 40 s · '
                                        'Orchestrator review 4 min 30 s)'), line)
        self.assertTrue(line.endswith('over the 10-minute limit per phase.'), line)

    def test_no_line_without_the_orchestrators_run(self):
        from hardening.agentic_view import _ubuntu_phase_lines
        self.assertEqual(_ubuntu_phase_lines([finished('scanner', 11)]), [])


def history_page():
    import streamlit as st
    from pathlib import Path
    from hardening.history_view import render_history
    render_history(Path(st.session_state['fixture_database']))


class HistoryFirstPairingTests(unittest.TestCase):
    def run_history(self, platform, machine, rows=(), new_machine=None):
        import tempfile
        from pathlib import Path
        from streamlit.testing.v1 import AppTest
        from hardening.overview_view import NEW_SERVER
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        reader = N(session=N(target_id=platform + ':' + machine), history=lambda target, limit: list(rows))
        choice = N(platform=platform, machine_identity=machine, hostname='Ubuntu2204', connected=False, reader=reader)
        app = AppTest.from_function(history_page, default_timeout=30)
        app.session_state['fixture_database'] = str(Path(folder.name) / 'windows' / 'imports.sqlite3')
        app.session_state[NEW_SERVER] = dict(key=platform + ':' + (new_machine or machine), hostname='Ubuntu2204',
                                             system='Ubuntu 22.04 LTS' if platform == 'ubuntu' else 'Windows Server 2022')
        with mock.patch('hardening.history_view.choose_server', return_value=choice):
            app.run()
        self.assertFalse(list(app.exception), [e.value for e in app.exception])
        return ' '.join(e.value for kind in (app.success, app.info) for e in kind)

    def test_ubuntu_shows_the_overview_message(self):
        text = self.run_history('ubuntu', 'c4afe0d58e35425789b24b5401bcf899')
        self.assertIn('New server paired: Ubuntu2204', text)
        self.assertIn('first time it has been paired', text)
        self.assertNotIn('No assessments yet', text)

    def test_windows_shows_the_overview_message(self):
        text = self.run_history('windows', '0dc5a44f-7386-48b5-bb43-1e937208b3bf')
        self.assertIn('New server paired', text)
        self.assertNotIn('No assessments yet', text)

    def test_a_re_pair_with_a_new_host_key_reads_as_a_new_server_too(self):
        """User report, 13 November: re-pairing the saved Ubuntu2204 with its new SSH host key started a new
        registration with no scan, yet History and Overview said "No assessments yet". They now show the new-server
        message, saying why it is new, read from the ledger (no pairing flag is set for a saved server)."""
        import tempfile
        from pathlib import Path
        from streamlit.testing.v1 import AppTest
        from system.bootstrap import SERVICE_KEY
        from system.contracts import Endpoint
        from system.identity import VerifiedIdentity
        from system.ledger import CoordinationLedger
        machine = 'c4afe0d58e35425789b24b5401bcf899'
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        ledger = CoordinationLedger(Path(folder.name) / 'ledger.sqlite3')
        ledger.register(VerifiedIdentity('ubuntu', 'Ubuntu2204', machine, '22.04', 'ssh', 'SHA256:' + 'C' * 43),
                        Endpoint('192.168.56.104', 22))
        texts = []
        for changed in (False, True):
            if changed:
                ledger.register(VerifiedIdentity('ubuntu', 'Ubuntu2204', machine, '22.04', 'ssh', 'SHA256:' + 'N' * 43),
                                Endpoint('192.168.56.105', 22), readdress=True, key_confirmed=True)
            reader = N(session=N(target_id='ubuntu:x'), history=lambda target, limit: [])
            choice = N(platform='ubuntu', machine_identity=machine, hostname='Ubuntu2204', connected=False, reader=reader)
            app = AppTest.from_function(history_page, default_timeout=30)
            app.session_state['fixture_database'] = str(Path(folder.name) / 'windows' / 'imports.sqlite3')
            app.session_state[SERVICE_KEY] = N(ledger=ledger)
            with mock.patch('hardening.history_view.choose_server', return_value=choice):
                app.run()
            texts.append(' '.join(e.value for kind in (app.success, app.info) for e in kind))
        self.assertIn('New server paired: Ubuntu2204', texts[0])  # never "No assessments yet" (2026-11-13)
        self.assertNotIn('new SSH host key', texts[0])  # the same key as before: no re-pair to mention
        self.assertIn('New server paired: Ubuntu2204', texts[1])
        self.assertIn('new SSH host key', texts[1])
        self.assertIn('start the first round', texts[1])
        self.assertNotIn('No assessments yet', texts[1])

    def test_any_other_server_without_a_scan_gets_the_new_server_message_too(self):
        # Administrator, 13 November 2026: "No assessments yet" is gone everywhere; a server that was not just paired
        # gets the same message without the claim of a first pairing.
        for platform, machine in (('ubuntu', 'c4afe0d58e35425789b24b5401bcf899'),
                                  ('windows', '0dc5a44f-7386-48b5-bb43-1e937208b3bf')):
            with self.subTest(platform=platform):
                text = self.run_history(platform, machine, new_machine='0' * 32)
                self.assertIn('New server paired: Ubuntu2204', text)
                self.assertIn('start the first round', text)
                self.assertNotIn('first time it has been paired', text)
                self.assertNotIn('No assessments yet', text)

    def test_the_old_message_is_gone_from_every_page(self):
        import re
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        for name in ('hardening/overview_view.py', 'hardening/history_view.py', 'system/ui/components.py'):
            source = (root / name).read_text(encoding='utf-8')
            self.assertFalse(re.search(r"st\.info\([^)]*No assessments yet", source), name)

if __name__ == '__main__':
    unittest.main()
