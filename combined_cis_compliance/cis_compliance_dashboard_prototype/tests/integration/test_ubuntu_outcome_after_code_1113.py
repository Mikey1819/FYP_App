"""The outcome after the batched execution, and the Scanner card during the final scan (administrator, 13 Nov 2026).

- Round 22:12 MYT: the Remediation Agent applied 11 fixes, started 1.3.1.1 (a supervised job) and stopped, as it
  must while a job runs; the Orchestrator recorded "remediation_incomplete" (the rest "not attempted, waiting"). The
  dashboard then ran the other 6 by code, and all 18 verified Compliant, yet the page said "Executed without AI after
  the agents stopped early" with that badge. Since the batched execution that continuation is the design, so the
  outcome is decided again by code from the final scan (here: Finished). A real early stop keeps the old wording.
- The final scan before completing showed a single Scanner card "waiting": the Ubuntu scan is run by code, not by an
  agent the live view can follow. On the Ubuntu page a code scan now shows the Scanner at work. Windows is unchanged.
Fakes only.
"""
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace as N
from unittest import mock


class OutcomeTests(unittest.TestCase):
    def backend(self, results):
        from backends.ubuntu.adapter import UbuntuBackend
        from backends.ubuntu.remediation_agents import REMEDIATION, REVIEW_ROLE
        from system.contracts import ComplianceStatus
        backend = UbuntuBackend.__new__(UbuntuBackend)
        latest = N(round_id='r', kind='assessment', evidence_sha256='e', details={})
        check = N(round_id='v', kind='verification', evidence_sha256='v', details={'verifies_round': 'r'})
        proposals = [N(decision='approved', receipts=({'outcome': 'applied', 'request_id': 'q-' + c},),
                       payload={'action': {'action_id': 'ubuntu.%s.v1' % c}, 'fields': {'control_id': c}})
                     for c in ('5.2.3', '1.3.1.1', '4.1.3')]
        store = N(rounds=lambda binding: [latest, check], proposals=lambda binding, round_id: proposals)
        review = {'outcome': 'remediation_review', 'reason_code': 'remediation_incomplete',
                  'reason': 'Applied: 5.2.3. Waiting for confirmation or reboot: 1.3.1.1. Not attempted: 4.1.3.'}
        runs = [{'agent_role': REVIEW_ROLE, 'events': [{'kind': 'finished', 'data': {'outcome': review}}]},
                {'agent_role': REMEDIATION, 'events': [{'kind': 'tool', 'data': {'name': 'execute_fixes', 'result': {
                    'results': results}}}]}]
        evidence = N(assessments=[N(control_id=c, status=ComplianceStatus.COMPLIANT) for c in ('5.2.3', '1.3.1.1', '4.1.3')])
        patches = mock.patch.multiple(backend, create=True, check=lambda *a: 'binding', _store=lambda: store,
                                      _phase_runs=lambda store_, round_id: runs, _unverified=lambda *a: [],
                                      _eligible=lambda evidence_: {}, _evidence=lambda store_, digest: evidence)
        return backend, patches

    def test_after_a_waiting_fix_the_rest_by_code_is_the_design_not_an_early_stop(self):
        backend, patches = self.backend([{'control_id': '5.2.3', 'result': 'applied'},
                                         {'control_id': '1.3.1.1', 'result': 'running'}])
        with patches:
            review = backend.remediation_review('c', 'w')
        self.assertEqual((review['next_step'], review['reason_code']), ('finish', 'all_verified'))  # before: fallback
        self.assertNotIn('without AI', review['reason'])

    def test_a_real_early_stop_still_says_executed_without_ai(self):
        backend, patches = self.backend([{'control_id': '5.2.3', 'result': 'applied'}])  # nothing waited
        with patches:
            review = backend.remediation_review('c', 'w')
        self.assertEqual(review['next_step'], 'fallback')


class ScannerCardTests(unittest.TestCase):
    def test_a_code_scan_on_the_ubuntu_page_shows_the_scanner_at_work(self):
        from hardening import live_progress
        from hardening.agentic_view import FINAL_LABEL, _UbuntuLiveLog, _stage_for
        job = N(label=FINAL_LABEL, started_at=datetime.now(timezone.utc))
        idle = dict(active=None, done=set(), words='finishing up')  # no agent run to follow: a scan by code
        with mock.patch.object(live_progress, 'progress', return_value=idle):
            roles, state = _stage_for(job, _UbuntuLiveLog.__new__(_UbuntuLiveLog))
            self.assertEqual(roles, (live_progress.SCANNER,))
            self.assertEqual(state['active'], live_progress.SCANNER)  # before: "waiting"
            _, windows = _stage_for(job, object())  # the Windows store: unchanged
            self.assertIsNone(windows['active'])


if __name__ == '__main__':
    unittest.main()
