"""The task 17 fault-scenario matrix must name real tests, so a rename cannot leave a scenario silently uncovered."""
import unittest


class FaultScenarioMatrixTests(unittest.TestCase):
    def test_every_listed_test_exists_and_every_required_scenario_is_listed(self):
        from tools.fault_scenarios import SCENARIOS, _locate
        missing = [(m, t) for _, _, tests in SCENARIOS for m, t in tests if _locate(m, t) is None]
        self.assertEqual(missing, [])
        self.assertEqual([s for s, _, _ in SCENARIOS], [
            'Wrong OS or identity', 'Model offline', 'Stale, rejected or duplicate requests', 'Partial collection',
            'Host crash', 'Channel loss', 'Lost receipt', 'Package timeout', 'Immutable audit configuration', 'Reboot',
            'Snapshot and registration epoch'])
        self.assertTrue(all(tests for _, _, tests in SCENARIOS))


if __name__ == '__main__':
    unittest.main()
