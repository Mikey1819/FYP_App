"""The apt simulation parser (shared by the package families). Found while diagnosing the 1.2.2.1 preview refusals
(live 2026-11-07): `apt-get -s` often appends a related-package list ("... [amd64]) [python3.10:amd64 ]" or "... []"),
which raised "Unrecognised apt simulation line". 1.2.2.1 was replaced by 2.4.1.2 on 2026-11-08; the fix stays. No VM."""
import json
import unittest

PLAIN = 'Inst base-files [12ubuntu4.3] (12ubuntu4.6 Ubuntu:22.04/jammy-updates [amd64])'
TRAILING = ('Inst libpython3.10 [3.10.12-1~22.04.2] (3.10.12-1~22.04.3 Ubuntu:22.04/jammy-updates [amd64]) '
            '[python3.10:amd64 ]')
EMPTY = 'Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-security [amd64]) []'


class SimulationParserTests(unittest.TestCase):
    def test_inst_lines_with_a_trailing_package_list_are_read(self):
        from vm.ubuntu.family_package import parse_simulation
        self.assertEqual(parse_simulation('\n'.join([PLAIN, TRAILING, EMPTY, 'Conf base-files (12ubuntu4.6 Ubuntu)'])), [
            ('Inst', 'base-files', '12ubuntu4.6', '12ubuntu4.3'),
            ('Inst', 'libpython3.10', '3.10.12-1~22.04.3', '3.10.12-1~22.04.2'),
            ('Inst', 'libssl3', '3.0.2-0ubuntu1.12', '3.0.2-0ubuntu1.10')])

    def test_anything_after_the_list_is_still_refused(self):
        from vm.ubuntu.family_package import parse_simulation
        for line in (TRAILING + ' extra', PLAIN + ' trailing words', 'Inst ../evil [1] (2 x)'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_simulation(line)


if __name__ == '__main__':
    unittest.main()
