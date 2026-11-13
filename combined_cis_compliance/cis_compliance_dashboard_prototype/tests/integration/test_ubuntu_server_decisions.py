"""Group 1 of the 12 November round (user report, 13 November): on a new VM, 2.1.2, 4.1.4 and 4.1.7 could never be
planned, because two reviewed decisions were registered in code only for the old VM's machine ID:
which firewall manager the server uses (UFW), and the 2.1.2 avahi-daemon choice (keep the package, mask it).

Now the administrator records them once per server on the Ubuntu page (the connected server's verified machine ID,
their name, the time); the code registrations still count for the old VM. Each decision still reaches only the
places it did before: the collector's registered firewall manager (it still checks competing managers on every scan),
and the 2.1.2 planner and predicate. A temporary decisions store; no VM.
"""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.integration import test_ubuntu_avahi_mask as avahi
from tests.integration import test_ubuntu_maintenance_ui as maintenance_ui

NEW = 'c4afe0d58e35425789b24b5401bcf899'


class DecisionsCase(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / 'ubuntu_server_decisions.sqlite3'
        patch = mock.patch('backends.ubuntu.server_decisions.store_path', return_value=self.path)
        patch.start()
        self.addCleanup(patch.stop)


class StoreTests(DecisionsCase):
    def test_a_recorded_decision_counts_for_its_machine_only(self):
        from backends.ubuntu import server_decisions as d
        self.assertIsNone(d.decision(NEW, 'firewall_manager'))
        self.assertFalse(self.path.exists())  # reading never creates the store
        d.ServerDecisions(self.path).record(NEW, 'firewall_manager', 'ufw', operator='fixture-operator')
        self.assertEqual(d.decision(NEW, 'firewall_manager'), 'ufw')
        self.assertIsNone(d.decision('0' * 32, 'firewall_manager'))
        self.assertEqual(d.decision(avahi.MACHINE, 'firewall_manager'), 'ufw')  # the old VM's code registration
        record = d.ServerDecisions(self.path).latest(NEW)['firewall_manager']
        self.assertEqual((record['value'], record['operator']), ('ufw', 'fixture-operator'))

    def test_only_known_decisions_with_a_name(self):
        from backends.ubuntu import server_decisions as d
        store = d.ServerDecisions(self.path)
        for args, kwargs in ((('firewall_manager', 'nftables'), {'operator': 'x'}),
                             (('something_else', 'ufw'), {'operator': 'x'}),
                             (('avahi_2_1_2', 'mask'), {'operator': '  '})):
            with self.subTest(args=args), self.assertRaises(ValueError):
                store.record(NEW, *args, **kwargs)


class ConsumerTests(DecisionsCase):
    def test_the_avahi_choice_reaches_the_2_1_2_planner_and_predicate(self):
        from backends.ubuntu import server_decisions as d
        from backends.ubuntu.actions import FAMILIES
        from backends.ubuntu.envelope import _avahi_retention
        spec, evidence = FAMILIES['ubuntu.2.1.2.v1'], avahi.AvahiHostSpecTests.evidence(None, machine=NEW)
        self.assertIsNone(spec.propose('2.1.2', evidence))
        self.assertFalse(_avahi_retention({'machine_id': NEW}))
        d.ServerDecisions(self.path).record(NEW, 'avahi_2_1_2', 'mask', operator='fixture-operator')
        self.assertEqual(spec.propose('2.1.2', evidence), avahi.PARAMS)
        self.assertTrue(_avahi_retention({'machine_id': NEW}))

    def test_the_firewall_manager_reaches_the_collector_request(self):
        from types import SimpleNamespace as N
        from backends.ubuntu import server_decisions as d
        from backends.ubuntu.adapter import UbuntuBackend
        backend = UbuntuBackend.__new__(UbuntuBackend)
        backend.registered_firewall_manager = None
        backend.session = N(identity=N(machine_identity=NEW))
        self.assertIsNone(backend.firewall_manager())
        d.ServerDecisions(self.path).record(NEW, 'firewall_manager', 'ufw', operator='fixture-operator')
        self.assertEqual(backend.firewall_manager(), 'ufw')
        d.ServerDecisions(self.path).record(NEW, 'firewall_manager', 'none', operator='fixture-operator')
        self.assertIsNone(backend.firewall_manager())  # "not UFW": no firewall fix is planned


class PanelTests(maintenance_ui.MaintenanceUiTests):
    """The fake page's server is 'a'*32 (no code registration): both decisions are open there."""

    def setUp(self):
        super().setUp()
        patch = mock.patch('backends.ubuntu.server_decisions.store_path', return_value=self.root / 'decisions.sqlite3')
        patch.start()
        self.addCleanup(patch.stop)

    def test_record_both_decisions_once_with_a_name(self):
        from tests.integration.test_ubuntu_live_path import open_gate
        from backends.ubuntu import server_decisions as d
        with open_gate():
            app, _ = self.page()
            labels = [e.label for e in app.expander if 'Server decisions' in e.label]
            self.assertEqual(len(labels), 1)
            self.assertIn('2 to make', labels[0])
            self.assertTrue(app.button(key='ubuntu_decide_firewall_manager_ufw').disabled)  # name first
            app.text_input(key='ubuntu_decisions_operator').input('fixture-operator').run()
            app.button(key='ubuntu_decide_firewall_manager_ufw').click().run()
            app.button(key='ubuntu_decide_avahi_2_1_2_mask').click().run()
            self.assertFalse(list(app.error), [e.value for e in app.error])
            machine = 'a' * 32
            self.assertEqual((d.decision(machine, 'firewall_manager'), d.decision(machine, 'avahi_2_1_2')),
                             ('ufw', 'mask'))
            self.assertFalse(any('to make' in e.label for e in app.expander if 'Server decisions' in e.label))


for _name in [n for n in dir(maintenance_ui.MaintenanceUiTests) if n.startswith('test')]:
    setattr(PanelTests, _name, None)  # only the harness is inherited


if __name__ == '__main__':
    unittest.main()
