"""The live-validation register on the Windows page (administrator, 14 November 2026: as on Ubuntu, the same words).

One row per Windows catalogue control (32), from the stored approvals, verdicts and verification scans of this server's
registration only. A fix verified Compliant is "Validated live"; the four firewall controls the program never changes
are "Manual on the server". A real backend after a deterministic round; the proposals are simulated, no VM is changed.
"""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_agentic import FakeVm
from test_winrm_channel import target
from hardening.winrm_channel import LiveScanner
from system.identity import VerifiedIdentity
from system.connection import VerifiedSession
from system.ledger import CoordinationLedger
from system.contracts import AssessmentMode


def record(request, control, verdict, *, approver='admin01', approved_at='2026-11-14T01:00:00+00:00',
           decision='approved'):
    return dict(proposal=dict(request_id=request, control_id=control, action_id='REM-' + control), decision=decision,
                decision_record=dict(approved_by=approver, approved_at=approved_at), verdict=verdict)


class WindowsRegisterTests(unittest.TestCase):
    def setUp(self):
        from backends.windows.adapter import WindowsBackend
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.path, self.vm, t = Path(folder.name), FakeVm(), target()
        self.session = VerifiedSession('connection', VerifiedIdentity('windows', t.hostname, t.machine_uuid, 'Server 2022',
                                                                      'winrm'),
                                       'windows:' + t.machine_uuid, 'epoch', t.username, t.host, t.port, None, t)
        self.ledger = CoordinationLedger(self.path / 'integration.db')
        self.backend = WindowsBackend(self.path / 'windows' / 'imports.sqlite3', session=self.session, ledger=self.ledger,
                                      scanner_factory=lambda runtime, t: LiveScanner(runtime, t,
                                                                                     session_factory=self.vm))
        handle = self.backend.start_round('connection', None, None, AssessmentMode.DETERMINISTIC, 'scan')
        self.workflow = handle.binding.workflow_session_id
        real = self.real = self.backend.store
        self.session_id = handle.binding.backend_session_id
        self.round = next(r for r in real.rounds(self.session_id) if r['kind'] == 'assessment')
        self.records = {}
        self.backend.store = SimpleNamespace(rounds=real.rounds, for_run=lambda run_id: list(self.records.values()),
                                             get=lambda identifier: self.records[identifier])

    def verified(self, *requests, at=None):
        """A verification scan of the round, with the verdict of each request (as the engine records it)."""
        run = self.round['framework_run_id']
        self.real.add_round(self.session_id, 'verification_scan', run, remediated_run_id=run,
                            verdicts=[dict(proposal_id=r, control_id=self.records[r]['proposal']['control_id'],
                                           verdict=self.records[r]['verdict']) for r in requests])

    def rows(self):
        return {r['control_id']: r for r in self.backend.live_validation('connection')}

    def test_one_row_per_windows_control_and_the_four_firewall_controls_are_manual_on_the_server(self):
        rows = self.rows()
        self.assertEqual(len(rows), 32)
        self.assertEqual({c for c, r in rows.items() if r['status'] == 'Manual on the server'},
                         {'9.2.1', '9.2.2', '9.3.1', '9.3.2'})
        self.assertEqual({r['status'] for c, r in rows.items() if c not in ('9.2.1', '9.2.2', '9.3.1', '9.3.2')},
                         {'Fixture-tested only'})
        self.assertEqual(self.vm.writes, [])

    def test_a_fix_verified_compliant_is_validated_live_with_its_evidence(self):
        self.records['r1'] = record('r1', '1.2.2', 'Verified compliant')
        self.verified('r1')
        row = self.rows()['1.2.2']
        self.assertEqual(row['status'], 'Validated live')
        self.assertEqual((row['evidence']['approver'], row['evidence']['request_id'], row['evidence']['round_id'],
                          row['evidence']['workflow']), ('admin01', 'r1', self.round['round_id'], self.workflow))
        self.assertTrue(row['evidence']['time'])  # when the verification scan recorded it

    def test_each_other_verdict_reads_as_on_ubuntu(self):
        self.records = {'a': record('a', '1.1.1', 'Verification failed'),
                        'b': record('b', '1.1.2', 'Refused before execution: approval expired'),
                        'c': record('c', '1.1.3', 'Unresolved: outcome uncertain (channel lost); rescan to observe'),
                        'd': record('d', '1.1.4', 'Unresolved: execution_failed (Access is denied.)'),
                        'e': record('e', '1.1.5', None),  # approved, never executed
                        'f': record('f', '1.1.7', None, decision='rejected')}
        self.verified('a', 'b', 'c', 'd')
        rows = self.rows()
        self.assertEqual({c: rows[c]['status'] for c in ('1.1.1', '1.1.2', '1.1.3', '1.1.4', '1.1.5', '1.1.7')},
                         {'1.1.1': 'Applied, not verified', '1.1.2': 'Refused', '1.1.3': 'Applied, not verified',
                          '1.1.4': 'Refused', '1.1.5': 'Fixture-tested only', '1.1.7': 'Fixture-tested only'})

    def test_a_later_failed_attempt_never_hides_the_earlier_proof(self):
        self.records['r1'] = record('r1', '1.2.2', 'Verified compliant')
        self.verified('r1')
        self.records['r2'] = record('r2', '1.2.2', 'Refused before execution: value changed')
        self.verified('r2')
        row = self.rows()['1.2.2']
        self.assertEqual((row['status'], row['evidence']['request_id'], row['attempts']), ('Validated live', 'r1', 2))

    def test_another_registration_of_the_same_server_sees_none_of_these_records(self):
        from dataclasses import replace
        from backends.windows.adapter import WindowsBackend
        self.records['r1'] = record('r1', '1.2.2', 'Verified compliant')
        self.verified('r1')
        other = WindowsBackend(self.path / 'windows' / 'imports.sqlite3', ledger=self.ledger,
                               session=replace(self.session, registration_epoch='new-epoch'),
                               scanner_factory=lambda runtime, t: LiveScanner(runtime, t, session_factory=self.vm))
        rows = {r['control_id']: r for r in other.live_validation('connection')}
        self.assertEqual(rows['1.2.2']['status'], 'Fixture-tested only')

    def test_refused_for_another_connection(self):
        with self.assertRaises(ValueError):
            self.backend.live_validation('wrong')


if __name__ == '__main__':
    unittest.main()
