"""1.2.2.1 preview diagnosis (administrator, 2026-11-08: diagnose the refusal first; defer installing updates).
Live 05:08-07:19: the read-only preview was refused every round. The apt simulation parser required each Inst line to
end at its closing bracket; `apt-get -s upgrade` often appends a related-package list ("... [amd64]) [python3.10:amd64 ]"
or "... [amd64]) []"), which raised "Unrecognised apt simulation line". The parser now accepts that optional list.
Installing updates stays deferred: the current family runs apt-get update inside the job and a full upgrade without
exact package versions, while the plan requires a separately approved metadata refresh and exact package/version
approval. No VM."""
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


class PatchDeferredTests(unittest.TestCase):
    def test_the_update_job_is_not_proposed_while_deferred(self):
        from backends.ubuntu.actions import FAMILIES
        from tests.integration.test_ubuntu_risk import evidence
        from tests.integration.ubuntu_fixtures import cases, observation, FAILURES
        ev = evidence(['1.2.2.1'])
        obs = cases()
        key, value = FAILURES['1.2.2.1']
        obs['1.2.2.1'][key] = observation(value)
        ev.raw = json.dumps({'observations': obs}).encode()
        self.assertIsNone(FAMILIES['ubuntu.1.2.2.1.v1'].propose('1.2.2.1', ev))


if __name__ == '__main__':
    unittest.main()
