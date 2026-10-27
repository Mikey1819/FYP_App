"""Downloadable round report from stored records. Simulated VM and scripted agents; no real VM or model."""
import re
import unittest

from hardening.round_report import round_report
from test_agentic import AgenticTestCase, FakeVm


class RoundReportTests(AgenticTestCase):
    def test_report_follows_the_round_from_proposal_to_verification(self):
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        rounds = self.store.rounds(result['session_id'])
        page = round_report(hardening, rounds, rounds[0])
        for text in ('FIXTURE-SERVER', 'CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0',
                     'Live (WinRM, collected by the Scanner Agent)', 'Awaiting decision', 'Not run yet.',
                     'Deferred by the Orchestrator', 'AI Agent Orchestrator', 'Analysis Agent'):
            self.assertIn(text, page)
        controls = page.split('6. All assessed controls')[1]
        self.assertEqual(len(re.findall('<tr><td>', controls)), 32)

        first, second = self.store.for_run(result['framework_run_id'])
        self.store.decide(first['proposal']['request_id'], approve=True, operator='admin01')
        self.store.decide(second['proposal']['request_id'], approve=False, operator='admin01')
        hardening.execute_approved(result['session_id'])
        rounds = self.store.rounds(result['session_id'])
        page = round_report(hardening, rounds, rounds[0])
        self.assertNotIn('Not run yet.', page)
        self.assertRegex(page, r'<td>1\.2\.2</td><td>Account lockout threshold: 5</td><td>0 → 5</td>'
                               r'<td>\d+</td><td>[^<]+</td><td>Approved</td><td>admin01, [0-9-]+ [0-9:]+ UTC</td>'
                               r'<td>Verified compliant</td>')
        self.assertIn('<td>Rejected</td>', page)
        self.assertIn('Configuration changes found by the verification rescan', page)
        self.assertIn('<td>Improvement</td>', page)
        self.assertIn('Remediation Agent', page)


if __name__ == '__main__':
    unittest.main()
