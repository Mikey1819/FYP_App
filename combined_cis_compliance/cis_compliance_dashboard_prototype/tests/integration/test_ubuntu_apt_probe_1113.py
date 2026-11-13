"""The apt lock probe, after a false "apt is busy" (administrator, 13 November 2026, round 22:57 MYT).

The server refused 1.3.1.1 and 6.3.1.1 with "apt is busy: another apt or dpkg process holds the package lock", while
the administrator found apt-daily-upgrade.service inactive. Three faults in the probe:
- it also tried apt's package-list lock (/var/lib/apt/lists/lock), which an install does not take: the automatic
  package-list download (apt-daily.service, a few minutes after boot) holds it, so installs were refused needlessly;
- it named the holder from `systemctl is-active`, which is false for a oneshot unit while it runs ("activating"),
  so every holder read as "another apt or dpkg process";
- a holder of a few seconds sank the fix for the whole round.
Now an install or purge tries only dpkg's locks and apt's download lock, a package-list refresh only the list lock;
the holder is named from the kernel's own lock table (/proc/locks) with its process name; and a held lock is tried
again for up to 30 seconds before the fix is refused. Fakes only; the VM is never contacted.
"""
import sys
import unittest
from types import SimpleNamespace as N
from unittest import mock

INSTALL = ('/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock', '/var/cache/apt/archives/lock')
LISTS = ('/var/lib/apt/lists/lock',)


class Server:
    """Which lock files are held, by which process (pid -> name), and what /proc/locks says."""
    def __init__(self, held=(), holder=('4242', 'unattended-upgr'), free_after=None):
        self.held, self.holder, self.free_after, self.tries = set(held), holder, free_after, 0
        self.fds = {}

    def open(self, path, flags):
        fd = 100 + len(self.fds)
        self.fds[fd] = path
        return fd

    def lockf(self, fd, flags):
        if flags & 8:  # LOCK_UN
            return
        self.tries += 1
        if self.fds[fd] in self.held and (self.free_after is None or self.tries <= self.free_after):
            raise OSError(11, 'Resource temporarily unavailable')

    def stat(self, path):
        return N(st_ino=1000 + INSTALL.index(path) if path in INSTALL else 2000)

    def proc(self, path):
        pid, name = self.holder
        if path == '/proc/locks':
            inode = 1000 if '/var/lib/dpkg/lock-frontend' in self.held else 2000
            return ('1: POSIX  ADVISORY  WRITE %s 08:02:%d 0 EOF\n'
                    '1: -> POSIX  ADVISORY  WRITE 99 08:02:%d 0 EOF\n' % (pid, inode, inode))
        if path == '/proc/%s/comm' % pid:
            return name + '\n'
        raise FileNotFoundError(path)


def probe(server, kind='install', active=()):
    from vm.ubuntu.family_package import LinuxPackageIO
    io = LinuxPackageIO()
    io._exec = lambda argv, seconds: (0, ('activating' if argv[-1] in active else 'inactive') + '\n')
    io._proc = server.proc
    io._pause = lambda seconds: None
    fake_fcntl = N(LOCK_EX=2, LOCK_NB=4, LOCK_UN=8, lockf=server.lockf)
    with mock.patch.dict(sys.modules, {'fcntl': fake_fcntl}), \
            mock.patch('vm.ubuntu.family_package.os.open', side_effect=server.open), \
            mock.patch('vm.ubuntu.family_package.os.close'), \
            mock.patch('vm.ubuntu.family_package.os.stat', side_effect=server.stat):
        return io.apt_busy(kind)


class ProbeTests(unittest.TestCase):
    def test_an_install_ignores_the_package_list_download(self):
        self.assertIsNone(probe(Server(held=LISTS)))  # before: "apt is busy" while apt-daily downloaded lists
        self.assertIsNotNone(probe(Server(held=LISTS), kind='lists'))  # a refresh does need that lock

    def test_the_holder_is_named_from_the_kernel_lock_table(self):
        self.assertEqual(probe(Server(held=INSTALL[:1])), "Ubuntu's automatic updates (unattended-upgrades, pid 4242)")
        self.assertEqual(probe(Server(held=INSTALL[:1], holder=('77', 'packagekitd'))), 'PackageKit (packagekitd, pid 77)')
        self.assertEqual(probe(Server(held=INSTALL[:1], holder=('5', 'apt-get'))), 'the process apt-get (pid 5)')

    def test_a_running_oneshot_unit_counts_when_the_lock_table_says_nothing(self):
        server = Server(held=INSTALL[:1])
        server.proc = lambda path: ''  # no readable entry
        self.assertEqual(probe(server, active=('apt-daily-upgrade.service',)),
                         "Ubuntu's automatic updates (apt-daily-upgrade)")  # before: "activating" was not counted
        self.assertEqual(probe(server), 'another apt or dpkg process')

    def test_a_short_holder_is_waited_out(self):
        self.assertIsNone(probe(Server(held=INSTALL[:1], free_after=3)))  # free on the 4th try, within 30 s
        self.assertIsNotNone(probe(Server(held=INSTALL[:1])))  # held throughout: refused after the wait

    def test_the_fix_and_the_refresh_ask_for_their_own_locks(self):
        from vm.ubuntu.family_package import PackageFamily, refuse_while_apt_busy
        from vm.ubuntu.family_maintenance import AptRefreshFamily
        asked = []
        system = N(apt_busy=lambda kind='install': asked.append(kind))
        refuse_while_apt_busy(system)
        refuse_while_apt_busy(system, 'lists')
        self.assertEqual(asked, ['install', 'lists'])
        self.assertIn('lists', AptRefreshFamily.check_eligible.__code__.co_consts)


if __name__ == '__main__':
    unittest.main()
