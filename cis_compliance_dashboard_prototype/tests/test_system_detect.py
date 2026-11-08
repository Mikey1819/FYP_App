"""Which operating system a server runs (hardening/system_detect.py), from what the server reports about itself."""
import unittest

from hardening.system_detect import detect


class DetectSystemTests(unittest.TestCase):
    def test_windows_server_2022_is_the_supported_system(self):
        for name in ('Microsoft Windows Server 2022 Standard Evaluation', 'Microsoft Windows Server 2022 Datacenter'):
            found = detect('windows', name, '10.0.20348')
            self.assertEqual((found.kind, found.label, found.supported), ('windows_server_2022', 'Windows Server 2022', True))
            self.assertEqual(found.reported, name)

    def test_other_windows_systems_are_recognised_but_not_supported(self):
        cases = (('Microsoft Windows Server 2019 Standard', '10.0.17763', 'windows_server'),
                 ('Microsoft Windows Server 2025 Standard', '10.0.26100', 'windows_server'),
                 ('Microsoft Windows Server 2022 Standard', '10.0.17763', 'windows_server'),  # Name and build disagree.
                 ('Microsoft Windows 11 Pro', '10.0.26200', 'windows_desktop'))
        for name, version, kind in cases:
            found = detect('windows', name, version)
            self.assertEqual((found.kind, found.supported), (kind, False), name)
            self.assertTrue(found.note)

    def test_ubuntu_2204_is_the_supported_linux_system(self):
        for name in ('Ubuntu 22.04.5 LTS', 'Ubuntu 22.04.4 LTS'):  # Every 22.04 point release: VERSION_ID is 22.04.
            found = detect('ubuntu', name, '22.04')
            self.assertEqual((found.kind, found.label, found.supported), ('ubuntu_2204', 'Ubuntu 22.04 LTS', True))
            self.assertEqual(found.reported, name)
        other = detect('UBUNTU', 'Ubuntu 24.04 LTS', '24.04')
        self.assertEqual((other.kind, other.supported), ('ubuntu', False))
        self.assertIn('Windows Server 2022 (stand-alone) and Ubuntu 22.04.5 LTS', other.note)

    def test_anything_else_is_other_or_unknown(self):
        found = detect('debian', 'Debian GNU/Linux 12 (bookworm)', '12')
        self.assertEqual((found.kind, found.label, found.supported), ('other', 'Debian GNU/Linux 12 (bookworm)', False))
        for empty in (('', '', ''), (None, None, None)):
            found = detect(*empty)
            self.assertEqual((found.kind, found.supported), ('unknown', False))


if __name__ == '__main__':
    unittest.main()
