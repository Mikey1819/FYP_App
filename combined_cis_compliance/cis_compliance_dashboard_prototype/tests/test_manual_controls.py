"""Windows controls this program assesses but never changes: which they are, the steps, and the administrator's choice."""
from pathlib import Path
import tempfile
import unittest

from hardening.manual_controls import (AUTOMATED, CHOICES, NOT_AUTOMATED, WITHDRAWN, ManualDecisionStore, setting,
                                       steps)
from hardening.round_report import round_report
from test_agentic import AgenticTestCase, FakeVm

SERVER = 'windows:4c4c4544-0000-1000-8000-000000000001'


class NotAutomatedTests(unittest.TestCase):
    def test_exactly_the_firewall_on_and_inbound_block_controls_have_no_library_action(self):
        self.assertEqual(NOT_AUTOMATED, ('9.2.1', '9.2.2', '9.3.1', '9.3.2'))
        self.assertFalse(set(NOT_AUTOMATED) & AUTOMATED)
        self.assertEqual(len(AUTOMATED) + len(NOT_AUTOMATED), 32)

    def test_scanned_values_are_shown_in_the_words_of_the_dialog(self):
        from hardening.manual_controls import in_words
        self.assertEqual((in_words('9.2.1', 1), in_words('9.3.1', 0)), ('On (1)', 'Off (0)'))
        self.assertEqual((in_words('9.2.2', 1), in_words('9.3.2', 0)), ('Block (1)', 'Allow (0)'))
        self.assertIsNone(in_words('9.3.1', None))  # Not configured is shown as it is.
        self.assertIsNone(in_words('9.2.1', 7))

    def test_each_one_says_which_setting_and_how_to_set_it_on_the_server(self):
        self.assertEqual(setting('9.2.1'), 'Private Profile tab: Firewall state = On (recommended)')
        self.assertEqual(setting('9.3.2'), 'Public Profile tab: Inbound connections = Block (default)')
        for control in NOT_AUTOMATED:
            text = ' '.join(steps(control))
            for needed in ('its own screen, not over the network', 'gpedit.msc', 'gpupdate /force', 'next round'):
                self.assertIn(needed, text)


class ManualDecisionStoreTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.store = ManualDecisionStore(Path(folder.name) / 'manual_decisions.sqlite3')

    def test_the_latest_choice_counts_and_withdrawing_leaves_it_undecided(self):
        self.store.record(SERVER, '9.3.1', 'manual_fix', operator='admin01', round_id='r1')
        self.assertEqual(self.store.latest(SERVER)['9.3.1']['choice'], 'manual_fix')
        self.store.record(SERVER, '9.3.1', 'exception', operator='admin02', reason='Firewall run by the network team')
        latest = self.store.latest(SERVER)['9.3.1']
        self.assertEqual((latest['choice'], latest['operator'], latest['reason']),
                         ('exception', 'admin02', 'Firewall run by the network team'))
        self.store.record(SERVER, '9.3.1', WITHDRAWN, operator='admin02')
        self.assertEqual(self.store.latest(SERVER), {})
        self.assertEqual(self.store.latest('windows:another-server'), {})

    def test_a_choice_needs_a_name_an_exception_needs_a_reason_and_only_these_controls_are_fixed_by_hand(self):
        with self.assertRaisesRegex(ValueError, 'Your name'):
            self.store.record(SERVER, '9.3.1', 'manual_fix', operator=' ')
        with self.assertRaisesRegex(ValueError, 'needs a reason'):
            self.store.record(SERVER, '9.3.1', 'exception', operator='admin01', reason='  ')
        with self.assertRaisesRegex(ValueError, 'has a program fix'):
            self.store.record(SERVER, '1.1.1', 'manual_fix', operator='admin01')
        with self.assertRaisesRegex(ValueError, 'Unknown control'):
            self.store.record(SERVER, '99.9', 'exception', operator='admin01', reason='x')
        with self.assertRaisesRegex(ValueError, 'Unknown choice'):
            self.store.record(SERVER, '9.3.1', 'ignore', operator='admin01')
        self.assertEqual(self.store.latest(SERVER), {})


    def test_choices_belong_to_one_session_and_a_new_session_starts_fresh(self):
        # Live 9 Nov: choices made in an earlier session (15:05) showed again in a new one, comment and all.
        self.store.record(SERVER, '9.3.1', 'exception', operator='mikey', reason='im lazy', session_id='s1')
        self.store.record(SERVER, '9.2.1', 'manual_fix', operator='mikey', session_id='s1')
        self.assertEqual(set(self.store.latest(SERVER, 's1')), {'9.3.1', '9.2.1'})
        self.assertEqual(self.store.latest(SERVER, 's2'), {})
        # Any open control can be accepted as an exception when completing (a rejected fix, an Unknown result).
        self.store.record(SERVER, '1.1.1', 'exception', operator='kk', reason='Legacy app needs it', session_id='s2')
        self.assertEqual(self.store.latest(SERVER, 's2')['1.1.1']['reason'], 'Legacy app needs it')

    def test_a_session_is_completed_once(self):
        self.assertIsNone(self.store.completion(SERVER, 's1'))
        self.store.complete(SERVER, 's1', operator='kk', final_run_id='run', compliant=31, total=32,
                            exceptions=[dict(control_id='9.3.1', title='t', status='Non-Compliant', reason='r',
                                             operator='kk')])
        done = self.store.completion(SERVER, 's1')
        self.assertEqual((done['operator'], done['compliant'], done['total'], done['exceptions'][0]['control_id']),
                         ('kk', 31, 32, '9.3.1'))
        with self.assertRaisesRegex(ValueError, 'already completed'):
            self.store.complete(SERVER, 's1', operator='kk', final_run_id='run2', compliant=32, total=32, exceptions=[])
        with self.assertRaisesRegex(ValueError, 'Your name'):
            self.store.complete(SERVER, 's2', operator=' ', final_run_id='run', compliant=32, total=32, exceptions=[])
        self.assertIsNone(self.store.completion(SERVER, 's2'))


class OpenItemTests(unittest.TestCase):
    """What keeps a session from completing, in the administrator's terms."""

    def test_only_compliant_or_accepted_controls_let_a_session_complete(self):
        from types import SimpleNamespace
        from hardening.domain import Status
        from hardening.manual_controls import open_items

        def result(control, status):
            return SimpleNamespace(control=SimpleNamespace(control_id=control, title='T ' + control), status=status)
        results = [result('1.1.4', Status.COMPLIANT), result('9.2.1', Status.NON_COMPLIANT),
                   result('9.3.1', Status.NON_COMPLIANT), result('9.3.2', Status.NON_COMPLIANT),
                   result('1.1.1', Status.NON_COMPLIANT), result('1.2.1', Status.UNKNOWN)]
        choices = {'9.2.1': dict(choice='manual_fix'), '9.3.1': dict(choice='exception')}
        items = {i['control_id']: i['why'] for i in open_items(results, choices)}
        self.assertEqual(set(items), {'9.2.1', '9.3.2', '1.1.1', '1.2.1'})
        self.assertIn('You chose to fix it manually on the server, but the scan still finds it Non-Compliant', items['9.2.1'])
        self.assertIn('Not fixed by this program', items['9.3.2'])
        self.assertIn('approve and execute its fix', items['1.1.1'])
        self.assertIn('Unknown: no value could be judged', items['1.2.1'])
        self.assertEqual(open_items(results[:1], {}), [])

    def test_each_open_control_says_how_to_close_it_from_the_completion_panel(self):
        from hardening.manual_controls import completion_steps
        firewall = ' '.join(completion_steps('9.2.1', 'Non-Compliant'))
        for needed in ('gpedit.msc', 'gpupdate /force', 'click Run final scan and complete'):
            self.assertIn(needed, firewall)
        self.assertIn('approve the fix, then Execute it', ' '.join(completion_steps('1.1.1', 'Non-Compliant')))
        self.assertIn('accept it as an exception', ' '.join(completion_steps('1.2.1', 'Unknown')))
        self.assertIn('run the next round', ' '.join(steps('9.2.1')))  # Fixes keeps its own last step.


class ReportTests(AgenticTestCase):
    def test_the_report_lists_them_with_the_administrators_choice(self):
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        rounds = self.store.rounds(result['session_id'])
        page = round_report(hardening, rounds, rounds[0])
        section = page.split('<h3>Not fixed by this program</h3>')[1].split('<h2>')[0]
        self.assertEqual(section.count('<tr><td>9.'), 4)
        self.assertIn('<td>9.3.1</td>', section)
        self.assertEqual(section.count('No choice recorded'), 4)
        page = round_report(hardening, rounds, rounds[0], manual={'9.3.1': dict(
            choice='exception', operator='admin01', reason='Firewall run by the network team', round_id=None,
            decided_at='2026-11-09T06:00:00+00:00')})
        section = page.split('<h3>Not fixed by this program</h3>')[1].split('<h2>')[0]
        self.assertIn(f"<td>{CHOICES['exception']}</td><td>admin01</td><td>2026-11-09 14:00:00</td>"
                      '<td>Firewall run by the network team</td>', section)


    def test_the_completion_report_adds_who_completed_it_and_each_accepted_exception(self):
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        rounds = self.store.rounds(result['session_id'])
        self.assertNotIn('7. Completion', round_report(hardening, rounds, rounds[0]))
        page = round_report(hardening, rounds, rounds[0], completion=dict(
            operator='kk', final_run_id='run-final', compliant=31, total=32, completed_at='2026-11-09T15:00:00+00:00',
            exceptions=[dict(control_id='9.3.1', title='Public firewall', status='Non-Compliant',
                             reason='Firewall run by the network team', operator='kk')]))
        section = page.split('<h2>7. Completion</h2>')[1]
        self.assertIn('<td>kk</td><td>2026-11-09 23:00:00</td><td>run-final</td><td>31 of 32</td><td>1</td>', section)
        self.assertIn('<td>9.3.1</td><td>Public firewall</td><td>Non-Compliant</td>'
                      '<td>Firewall run by the network team</td><td>kk</td>', section)



class PhaseTimeTests(AgenticTestCase):
    """How long each phase took (user request 9 Nov): from the recorded start, else the Orchestrator's own run time."""

    def test_each_phase_says_how_long_it_took_and_whether_it_kept_the_limit(self):
        from hardening.round_report import duration_text, phase_line
        hardening = self.standard_round(FakeVm())
        result = hardening.run_round()
        row = self.store.rounds(result['session_id'])[0]
        self.assertIn('started_at', row)
        line = phase_line(hardening, row, 'Assessment')
        self.assertRegex(line, r'^Assessment took \d+ s \(Scanner \d+ s · Analysis \d+ s\), within the 10-minute limit')
        self.assertIn('Assessment took', round_report(hardening, [row], row))
        # A round from before starts were recorded: the Orchestrator's run covers the agents it delegated.
        old = {k: v for k, v in row.items() if k != 'started_at'}
        self.assertTrue(phase_line(hardening, old, 'Assessment').startswith('Assessment took'))
        self.assertEqual((duration_text(42), duration_text(293.4), duration_text(601)), ('42 s', '4 min 53 s', '10 min 01 s'))
        late = dict(row, started_at='2026-11-09T00:00:00+00:00', created_at='2026-11-09T00:11:00+00:00')
        self.assertIn('Assessment took 11 min 00 s', phase_line(hardening, late, 'Assessment'))
        self.assertIn('over the 10-minute limit per phase', phase_line(hardening, late, 'Assessment'))


if __name__ == '__main__':
    unittest.main()
