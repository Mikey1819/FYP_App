"""The default Ubuntu model clients must have room to answer. Live 2026-11-07: with every agent capped at 384
output tokens, qwen3:8b's submit_plan for 22 failing controls was truncated, returned empty, and the round
ended "Unavailable" with no proposals. No model or VM is contacted here."""
import json
import unittest
from pathlib import Path

CHARS_PER_TOKEN = 2.5  # conservative for JSON made of IDs, dots and digits


class UbuntuModelBudgetTests(unittest.TestCase):
    def backend(self):
        from backends.ubuntu.adapter import UbuntuBackend
        return UbuntuBackend(Path('unused.sqlite3'), session=None, ledger=None, model_probe=lambda: False)

    def test_orchestrator_budget_covers_a_plan_that_fixes_every_registered_control(self):
        from backends.ubuntu.actions import FAMILIES
        from backends.ubuntu.agents import ORCHESTRATOR
        cis = sorted(a for a in FAMILIES if a.startswith('ubuntu.'))
        self.assertEqual(len(cis), 30)
        plan = {'name': 'submit_plan', 'arguments': {
            'target_id': 'ubuntu:00000000-0000-0000-0000-000000000000',
            'decisions': [{'control_id': a[len('ubuntu.'):-len('.v1')], 'decision': 'fix',
                           'reason_code': 'unblocks_other', 'action_id': a} for a in cis]}}
        needed = len(json.dumps(plan)) / CHARS_PER_TOKEN
        self.assertGreaterEqual(self.backend().model_client_factory(ORCHESTRATOR).num_predict, needed)

    def test_role_budgets_never_shrink_below_the_windows_engine(self):
        from backends.ubuntu.agents import ANALYSIS, ORCHESTRATOR, SCANNER
        factory = self.backend().model_client_factory
        self.assertGreaterEqual(factory(ANALYSIS).num_predict, 768)
        self.assertGreaterEqual(factory(SCANNER).num_predict, 512)
        self.assertGreaterEqual(factory(ORCHESTRATOR).num_predict, 1024)


if __name__ == '__main__':
    unittest.main()
