"""The live agent view (live_progress.py): read from the agents' own log, drawn as cards."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from hardening import live_progress
from hardening.agentic import ANALYSIS, ORCHESTRATOR, REMEDIATION, SCANNER
from hardening.import_storage import ImportedEvidenceStore
from hardening.remediation import RemediationStore

START = datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc)


class ProgressTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        imports = ImportedEvidenceStore(Path(folder.name) / 'imports.sqlite3')
        self.store = RemediationStore(Path(folder.name) / 'agentic.sqlite3', imports)
        self.n = 0

    def run_of(self, role, events, seconds=0):
        """One agent run, as the Coordinator logs it: its role, then its events."""
        self.n += 1
        run_id, stamp = f'run{self.n}', (START + timedelta(seconds=seconds)).isoformat()
        with self.store._connection() as db:
            db.execute('INSERT INTO investigation_runs VALUES (?,?,?,?)',
                       (run_id, 'a', stamp, json.dumps(dict(agent_role=role, team_id='round'))))
            for kind, payload in events:
                db.execute('INSERT INTO investigation_events (run_id, kind, created_at, payload) VALUES (?,?,?,?)',
                           (run_id, kind, stamp, json.dumps(payload)))

    def test_the_working_agent_its_last_step_and_who_has_finished(self):
        self.run_of(ORCHESTRATOR, [('request', {}), ('tool', dict(name='delegate_scanner'))], seconds=-30)  # Older.
        self.run_of(ORCHESTRATOR, [('request', {})], seconds=1)
        self.assertEqual(live_progress.progress(self.store, START),
                         dict(active=ORCHESTRATOR, done=set(), words='working on its first step'))
        self.run_of(SCANNER, [('request', {}), ('tool', dict(name='scan_target')), ('finished', {})], seconds=2)
        self.run_of(ANALYSIS, [('request', {}), ('tool', dict(name='score_findings')), ('request', {})], seconds=3)
        state = live_progress.progress(self.store, START)
        self.assertEqual((state['active'], state['done']), (ANALYSIS, {SCANNER}))
        self.assertEqual(state['words'], 'working · last step: read the risk ranking')

    def test_the_agents_of_each_kind_of_work(self):
        self.assertEqual(live_progress.phase_roles('Round: Orchestrator → Scanner → Analysis → plan'),
                         (ORCHESTRATOR, SCANNER, ANALYSIS))
        self.assertEqual(live_progress.phase_roles('Remediation Agent executing the approved fixes, then Scanner '
                                                   'verifying'), (ORCHESTRATOR, REMEDIATION, SCANNER))
        self.assertEqual(live_progress.phase_roles('Executing the approved fixes in rank order without AI, then '
                                                   'verifying'), (REMEDIATION, SCANNER))
        self.assertEqual(live_progress.phase_roles('Final scan before completing (read-only)'), (SCANNER,))


class StageTests(unittest.TestCase):
    def test_the_working_agent_is_animated_and_work_travels_towards_it(self):
        page = live_progress.stage_html((ORCHESTRATOR, SCANNER, ANALYSIS),
                                        dict(active=ANALYSIS, done={SCANNER}, words=''))
        self.assertIn('class="fyp-agent fyp-active"><span class="fyp-icon fyp-i-analysis"></span>Analysis', page)
        self.assertIn('class="fyp-agent fyp-done"><span class="fyp-icon fyp-i-scanner"></span>Scanner', page)
        self.assertIn('class="fyp-agent "><span class="fyp-icon fyp-i-orchestrator"></span>Orchestrator', page)
        # Drawn line icons (no emoji), as background images: the page's HTML filter removes inline SVG.
        self.assertTrue(all(icon.startswith('<svg') for icon in live_progress.ICONS.values()))
        self.assertEqual(page.count('url("data:image/svg+xml,%3Csvg'), 4)
        self.assertNotIn('<svg', page)
        self.assertEqual(page.count('fyp-track fyp-live'), 1)
        self.assertIn('prefers-reduced-motion', page)  # No motion for those who turned animation off.

    def test_results_travel_back_when_the_orchestrator_works_again(self):
        page = live_progress.stage_html((ORCHESTRATOR, SCANNER, ANALYSIS),
                                        dict(active=ORCHESTRATOR, done={SCANNER, ANALYSIS}, words=''))
        self.assertEqual(page.count('fyp-track fyp-back'), 2)
        self.assertNotIn('fyp-track fyp-live', page)


if __name__ == '__main__':
    unittest.main()
