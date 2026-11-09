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

    def test_a_choice_needs_a_name_an_exception_needs_a_reason_and_only_these_controls_take_one(self):
        with self.assertRaisesRegex(ValueError, 'Your name'):
            self.store.record(SERVER, '9.3.1', 'manual_fix', operator=' ')
        with self.assertRaisesRegex(ValueError, 'needs a reason'):
            self.store.record(SERVER, '9.3.1', 'exception', operator='admin01', reason='  ')
        with self.assertRaisesRegex(ValueError, 'does not fix'):
            self.store.record(SERVER, '1.1.1', 'exception', operator='admin01', reason='x')
        with self.assertRaisesRegex(ValueError, 'Unknown choice'):
            self.store.record(SERVER, '9.3.1', 'ignore', operator='admin01')
        self.assertEqual(self.store.latest(SERVER), {})


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


if __name__ == '__main__':
    unittest.main()
