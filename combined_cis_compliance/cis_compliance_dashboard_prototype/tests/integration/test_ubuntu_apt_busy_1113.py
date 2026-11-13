"""Package fixes while apt is busy (administrator, 13 November 2026, evening round 12:58 UTC).

1.3.1.1 ran 13:00:17-13:15:31 and 6.3.1.1 13:15:38-13:30:52, each exactly the 15-minute wait for apt's lock, and both
ended not applied with nothing changed: the lock was held for over 30 minutes in a row (most likely Ubuntu's own
automatic updates after the snapshot restore), and everything behind them waited too. Waiting longer does not help.
Now the server checks apt's lock before a package fix or a package-list refresh starts (and in its preview): while it
is held, the fix is refused at once with the reason, nothing is written, and the rest of the execution goes on. The
wait for a lock taken in between is 5 minutes.
Fakes only; the VM is never contacted.
"""
import sys
import unittest
from types import SimpleNamespace as N
from unittest import mock

from tests.integration.test_ubuntu_package_families import FakeApt
from tests.integration.test_ubuntu_maintenance_target import FakeMaintenance

HOLDER = "Ubuntu's automatic updates (apt-daily-upgrade)"


class BusyApt(FakeApt):
    busy = None

    def apt_busy(self, kind='install'):
        return self.busy


class BusyMaintenance(FakeMaintenance):
    busy = None

    def apt_busy(self, kind='install'):
        return self.busy


class RefusedWhileBusyTests(unittest.TestCase):
    def test_a_package_fix_is_refused_at_once_while_apt_is_busy(self):
        from vm.ubuntu.family_package import PackageFamily
        system = BusyApt()
        family = PackageFamily('6.3.1.1', system)
        params = {'packages': ['auditd', 'audispd-plugins']}
        family.check_eligible(params)  # free: eligible as before
        system.busy = HOLDER
        with self.assertRaisesRegex(ValueError, 'automatic updates') as refused:
            family.check_eligible(params)  # before: started, then waited 15 minutes for the lock
        self.assertIn('next round', str(refused.exception))
        self.assertLessEqual(len(str(refused.exception)), 200)  # the runner passes at most 200 characters on

    def test_a_package_list_refresh_is_refused_while_apt_is_busy(self):
        from vm.ubuntu.family_maintenance import AptRefreshFamily
        system = BusyMaintenance()
        family = AptRefreshFamily(system)
        family.check_eligible({'nonce': 'a' * 32})
        system.busy = HOLDER
        with self.assertRaisesRegex(ValueError, 'automatic updates'):
            family.check_eligible({'nonce': 'a' * 32})

    def test_the_lock_wait_is_five_minutes(self):
        from vm.ubuntu.family_package import LinuxPackageIO
        self.assertIn('DPkg::Lock::Timeout=300', LinuxPackageIO._APT)  # before: 900


class PageWordingTests(unittest.TestCase):
    def test_no_refresh_is_offered_while_apt_was_busy(self):
        from hardening.agentic_view import _ubuntu_maintenance_needs
        from system.ui.components import NO_PLAN
        busy = {'control_id': '6.3.1.1', 'state': NO_PLAN, 'proposals': [],
                'reason': 'The server refused its read-only check · apt is busy: ' + HOLDER + ' holds the package lock.'}
        self.assertEqual(_ubuntu_maintenance_needs([busy], set()), ((), ()))  # a refresh would be refused too
        stale = dict(busy, reason='The server refused its read-only check · a target package is unavailable')
        self.assertEqual(_ubuntu_maintenance_needs([stale], set()), (('6.3.1.1',), ()))

    def test_a_refusal_just_before_writing_says_why(self):
        from backends.ubuntu.adapter import refusal_detail
        words = refusal_detail('not_eligible')
        self.assertNotIn('(not_eligible)', words)
        self.assertIn('apt busy', words)

# The lock probe itself: test_ubuntu_apt_probe_1113 (the locks per operation, the holder, the short wait).


if __name__ == '__main__':
    unittest.main()
