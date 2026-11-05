import importlib.util
from pathlib import Path
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
from system.contracts import WorkflowBinding

class CoordinationTests(unittest.TestCase):
    def test_independent_process_claim_survives_owner_exit_without_replay(self):
        from system.ledger import CoordinationLedger
        from system.contracts import encode_record
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'coord.sqlite3'
            ledger = CoordinationLedger(path)
            binding = WorkflowBinding('w','ubuntu','ubuntu:fixture','epoch','b','2026-11-05T00:00:00+00:00')
            ledger.add_binding(binding)
            code = ('import sys; from system.ledger import CoordinationLedger; '
                    'from system.contracts import decode_record,WorkflowBinding; '
                    'ledger=CoordinationLedger(sys.argv[1]); binding=decode_record(WorkflowBinding,sys.argv[2]); '
                    "print(int(ledger.claim(binding,sys.argv[3],'execute',{'requests':['same']},mutation=True)[0]))")
            children = [subprocess.Popen([sys.executable,'-B','-c',code,str(path),encode_record(binding),op],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for op in ('one','two')]
            outputs = [p.communicate(timeout=20) for p in children]
            self.assertEqual([p.returncode for p in children], [0,0], outputs)
            self.assertEqual(sorted(out.strip() for out, err in outputs), ['0','1'])
            # The winning process has exited: even a new operation ID cannot replay the same write.
            self.assertFalse(CoordinationLedger(path).claim(binding,'three','execute',{'requests':['same']},mutation=True)[0])
            with self.assertRaises(ValueError):
                CoordinationLedger(path).claim(binding,'four','execute',{'requests':['other']},mutation=True)

    def test_two_connections_different_operation_ids_dispatch_once(self):
        self.assertIsNotNone(importlib.util.find_spec('system.ledger'))
        from system.ledger import CoordinationLedger
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'integration.sqlite3'
            ledger=CoordinationLedger(path)
            binding=WorkflowBinding('workflow','ubuntu','ubuntu:fixture','epoch','backend-session','2026-11-05T00:00:00+00:00')
            ledger.add_binding(binding)
            def claim(op):
                try:return CoordinationLedger(path).claim(binding,op,'execute',{'round':'r','approved':['a']},mutation=True)[0]
                except ValueError:return False
            with ThreadPoolExecutor(2) as workers:results=list(workers.map(claim,['one','two']))
            self.assertEqual(results.count(True),1)
            with self.assertRaises(ValueError):ledger.claim(binding,'three','execute',{'round':'r2','approved':['b']},mutation=True)
            owner='one' if results[0] else 'two'
            ledger.transition(owner,'unresolved')
            with self.assertRaises(ValueError):ledger.claim(binding,'four','execute',{'round':'r2','approved':['b']},mutation=True)

    def test_matching_replay_conflict_binding_and_append_only_audit(self):
        self.assertIsNotNone(importlib.util.find_spec('system.ledger'))
        from system.ledger import CoordinationLedger
        import sqlite3
        with tempfile.TemporaryDirectory() as folder:
            ledger=CoordinationLedger(Path(folder)/'coord.sqlite3')
            binding=WorkflowBinding('w','windows','windows:fixture','e','engine','2026-11-05T00:00:00+00:00')
            ledger.add_binding(binding)
            self.assertTrue(ledger.claim(binding,'op','assess',{'intent':'a'})[0])
            self.assertFalse(ledger.claim(binding,'op','assess',{'intent':'a'})[0])
            with self.assertRaises(ValueError):ledger.claim(binding,'op','assess',{'intent':'b'})
            with self.assertRaises(ValueError):ledger.resume('w','windows','windows:other','e')
            self.assertEqual(ledger.resume('w','windows','windows:fixture','e').backend_session_id,'engine')
            with closing(sqlite3.connect(ledger.path)) as db:
                with self.assertRaises(sqlite3.IntegrityError):db.execute('DELETE FROM operation_events')
