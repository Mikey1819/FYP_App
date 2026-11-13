"""Executing several approved fixes at once (live 2026-11-07 13:44-13:47, stage 1). 1.5.1 applied; 1.5.3, 3.3.1 and 3.3.8
were refused `stale_read_set` because 1.5.1 had just changed the same managed sysctl file their plans were bound to (a
correct refusal: nothing was written). Execution stopped at the first refusal, so 5.2.3 (sudoers, independent) never ran,
and the cards only said "Not applied (stale_read_set)". A refusal is a definite not-applied outcome, so execution goes
on; only an uncertain outcome (unresolved, running) stops it. Fakes stand in for the store and the runner."""
import json
import unittest
from types import SimpleNamespace as N
from unittest import mock


def proposal(request_id, action_id):
    return N(proposal_id='p-' + request_id, decision='approved', receipts=(),
             payload={'action': {'action_id': action_id}}, approved_raw=json.dumps({'request_id': request_id}).encode())


BATCH = [proposal('a151', 'ubuntu.1.5.1.v1'), proposal('a153', 'ubuntu.1.5.3.v1'), proposal('a331', 'ubuntu.3.3.1.v1'),
         proposal('a523', 'ubuntu.5.2.3.v1')]


class ExecutionBatchTests(unittest.TestCase):
    def run_batch(self, outcomes):
        from backends.ubuntu.adapter import UbuntuBackend
        backend = UbuntuBackend.__new__(UbuntuBackend)
        dispatched, verified, applied = [], [], []
        store = N(proposals=lambda binding, round_id: BATCH)

        def dispatch(store_, binding, p, operation_id, **_):
            rid = json.loads(p.approved_raw)['request_id']
            dispatched.append(rid)
            if outcomes[rid] == 'completed':
                applied.append(rid)
            return N(state=outcomes[rid])

        def verify(store_, binding, latest, applied, state):
            verified.append(list(applied))
            return state
        with mock.patch.multiple(backend, check=lambda *a: 'binding', _store=lambda: store, create=True,
                                 _latest=lambda *a: N(round_id='r'), _dispatch_one=dispatch, _verify=verify,
                                 _agent_skipped=lambda *a: {}, _waits=lambda p: None, _refuse_completed=lambda b: None,
                                 _continuable=lambda *a: ({}, ()), _unverified=lambda *a: list(applied),
                                 ledger=mock.Mock(**{'claim.return_value': (False, None)})), \
                mock.patch('backends.ubuntu.adapter.execution_gate', return_value=()):
            handle = backend.execute_approved('c', 'w', 'round', tuple(outcomes), True, 'op')
        return handle.state, dispatched, verified

    def test_the_live_batch_goes_on_past_stale_refusals_to_the_independent_fix(self):
        state, dispatched, verified = self.run_batch(
            {'a151': 'completed', 'a153': 'refused', 'a331': 'refused', 'a523': 'completed'})
        self.assertEqual(dispatched, ['a151', 'a153', 'a331', 'a523'])
        self.assertEqual(verified, [['a151', 'a523']])  # one fresh scan for everything that applied
        self.assertEqual(state, 'refused')  # the page still says that not everything applied

    def test_an_uncertain_outcome_still_stops_the_batch(self):
        # Unresolved stops for a person: the scan covers what applied. Running waits: the one scan of the execution
        # follows once it has settled (13 November 2026).
        for uncertain, scans in (('unresolved', [['a151']]), ('running', [])):
            with self.subTest(outcome=uncertain):
                state, dispatched, verified = self.run_batch(
                    {'a151': 'completed', 'a153': uncertain, 'a331': 'completed', 'a523': 'completed'})
                self.assertEqual(dispatched, ['a151', 'a153'])
                self.assertEqual((state, verified), (uncertain, scans))


class StaleRefusalWordingTests(unittest.TestCase):
    def test_a_stale_read_set_refusal_explains_itself_and_what_to_do(self):
        from backends.ubuntu.adapter import refusal_detail
        text = refusal_detail('stale_read_set')
        self.assertIn('changed since', text)
        self.assertIn('same file', text)
        self.assertIn('new round', text)
        self.assertEqual(refusal_detail('identity_mismatch'), 'Not applied (identity_mismatch).')


if __name__ == '__main__':
    unittest.main()
