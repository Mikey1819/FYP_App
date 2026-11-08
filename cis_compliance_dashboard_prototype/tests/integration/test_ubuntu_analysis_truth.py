"""Analysis output that cannot be true or cannot matter (live 2026-11-08 05:48, the 2.4.1.2 round). The Analysis agent
flagged 2.4.1.2 as `persistent_failure`, a control assessed for the first time, and triaged it as a gap although the
ranking listed no gaps. The submission was refused, resubmitted identically, blocked, and the Analyse step stayed red.
Triage entries for controls that are not gaps are ignored; flags are kept only when the deterministic facts make them
true (highest_risk: risk rank <= 3; persistent_failure: history factor D >= 3; affects_remote_access: SSH and UFW
controls). Both are recorded. Scripted models; no VM."""
import unittest
from types import SimpleNamespace as N

from tests.integration import test_ubuntu_agents as base  # module import: base tests are not collected twice
from tests.integration.test_ubuntu_agents import call, team, scanner_ok


def finding(cid, rank, D=1):
    return N(control_id=cid, rank=rank, D=D, score=60, level='High')


class AnalysisTruthTests(base.AgentRoundTests):
    def analysis(self, flags, triage):
        return [call('read_ranking'), call('submit_analysis', flags=flags, gap_triage=triage)]

    def run_with(self, flags, triage, ranking):
        clients = team([call('delegate_scanner'), call('delegate_analysis')], scanner_ok(), self.analysis(flags, triage))
        result = self.run_round(clients, collect=self.collect_with(failing=('1.5.1', '5.1.20')),
                                rank=lambda run_id, ev: ranking)
        return result, self.events(result['children']['analysis'])

    def test_the_live_submission_is_accepted_without_the_untrue_flag_or_the_non_gap_triage(self):
        # 2.4.1.2 is the fixture's standing gap; 1.5.1 is failing but not a gap, and has no earlier failure (D=1).
        flags = [{'control_id': '1.5.1', 'flag_code': 'persistent_failure'}, {'control_id': '5.1.20', 'flag_code': 'highest_risk'}]
        triage = [{'control_id': '2.4.1.2', 'triage_code': 'manual_review'},
                  {'control_id': '1.5.1', 'triage_code': 'unresolved_effective_state'}]
        result, events = self.run_with(flags, triage, [finding('5.1.20', 1), finding('1.5.1', 2)])
        self.assertEqual([e for e in events if e['kind'] == 'tool_rejected'], [])
        self.assertEqual(result['analysis']['flags'], [{'control_id': '5.1.20', 'flag_code': 'highest_risk'}])
        self.assertEqual(result['analysis']['triage'], [{'control_id': '2.4.1.2', 'triage_code': 'manual_review'}])
        finished = next(e['data'] for e in events if e['kind'] == 'finished')
        self.assertEqual(finished['outcome']['ignored'], {
            'flags': [{'control_id': '1.5.1', 'flag_code': 'persistent_failure'}],
            'gap_triage': [{'control_id': '1.5.1', 'triage_code': 'unresolved_effective_state'}]})

    def test_true_flags_are_kept(self):
        flags = [{'control_id': '1.5.1', 'flag_code': 'persistent_failure'}, {'control_id': '5.1.20', 'flag_code': 'affects_remote_access'}]
        triage = [{'control_id': '2.4.1.2', 'triage_code': 'manual_review'}]
        result, _ = self.run_with(flags, triage, [finding('5.1.20', 1), finding('1.5.1', 2, D=3)])
        self.assertEqual(result['analysis']['flags'], flags)

    def test_risk_flags_are_dropped_while_risk_is_withheld(self):
        flags = [{'control_id': '1.5.1', 'flag_code': 'highest_risk'}, {'control_id': '5.1.20', 'flag_code': 'affects_remote_access'}]
        triage = [{'control_id': '2.4.1.2', 'triage_code': 'manual_review'}]
        result, _ = self.run_with(flags, triage, None)
        self.assertEqual(result['analysis']['flags'], [{'control_id': '5.1.20', 'flag_code': 'affects_remote_access'}])

    def test_a_missing_gap_is_still_refused(self):
        result, events = self.run_with([], [], [finding('5.1.20', 1), finding('1.5.1', 2)])
        self.assertIn('Triage exactly every unresolved control',
                      [e['data'].get('error') for e in events if e['kind'] == 'tool_rejected'])


for _name in [n for n in dir(base.AgentRoundTests) if n.startswith('test')]:
    setattr(AnalysisTruthTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
