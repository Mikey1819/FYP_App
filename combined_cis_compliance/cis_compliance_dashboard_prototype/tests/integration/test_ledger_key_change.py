"""A changed SSH host key, accepted only through a re-pair by code (administrator, 13 November 2026).

Live: a VM restored from a snapshot came back with another SSH host key (and a new address), and the laptop refused
it for good ("This laptop recorded another SSH host key ... A changed host key is never accepted from this page").
A re-pair proves the new key: the pairing answer, signed with the one-time code read on the server's own console,
names the key, and the login must find exactly that key. Then, and only then, the laptop records the new key under a
new registration epoch (earlier approvals and sessions no longer count; the history stays). A plain reconnect from
My servers still refuses a changed key, as does a re-pair whose signed answer names another key, or a change while a
fix is still open on that server. Records stay append-only. Fakes only; nothing reaches a server.
"""
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as N

from system.contracts import ConnectionRequest, Endpoint, VerificationRefused
from system.identity import VerifiedIdentity

MACHINE = 'c4afe0d58e35425789b24b5401bcf899'
OLD, NEW = 'SHA256:' + 'C' * 43, 'SHA256:' + 'N' * 43
HERE, THERE = Endpoint('192.168.56.104', 22), Endpoint('192.168.56.105', 22)


def ubuntu(key, hostname='Ubuntu2204'):
    return VerifiedIdentity('ubuntu', hostname, MACHINE, '22.04', 'ssh', key)


class LedgerKeyChangeTests(unittest.TestCase):
    def setUp(self):
        from system.ledger import CoordinationLedger
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.ledger = CoordinationLedger(Path(folder.name) / 'ledger.sqlite3')
        self.target, self.epoch = self.ledger.register(ubuntu(OLD), HERE)

    def test_a_re_pair_that_proved_the_new_key_records_it_under_a_new_epoch(self):
        target, epoch = self.ledger.register(ubuntu(NEW), HERE, readdress=True, key_confirmed=True)
        self.assertEqual(target, self.target)
        self.assertNotEqual(epoch, self.epoch)
        record = self.ledger.registration('ubuntu', MACHINE)
        self.assertEqual((record['fingerprint'], record['epoch']), (NEW, epoch))
        self.assertEqual(self.ledger.known_fingerprint(HERE), NEW)
        self.assertEqual(self.ledger.register(ubuntu(NEW), HERE), (target, epoch))  # from now on, the new key

    def test_a_new_address_and_a_new_key_together(self):
        target, epoch = self.ledger.register(ubuntu(NEW), THERE, readdress=True, key_confirmed=True)
        record = self.ledger.registration('ubuntu', MACHINE)
        self.assertEqual((record['endpoint'], record['fingerprint']), ('192.168.56.105:22', NEW))

    def test_without_the_pairing_proof_a_changed_key_is_still_refused(self):
        for kwargs in ({}, {'readdress': True}, {'readdress': True, 'key_confirmed': False}):
            with self.subTest(**kwargs), self.assertRaisesRegex(VerificationRefused, 'another SSH host key'):
                self.ledger.register(ubuntu(NEW), HERE, **kwargs)
        self.assertEqual(self.ledger.registration('ubuntu', MACHINE)['fingerprint'], OLD)

    def test_a_renamed_server_is_still_refused(self):
        with self.assertRaises(VerificationRefused):
            self.ledger.register(ubuntu(NEW, hostname='Other'), HERE, readdress=True, key_confirmed=True)

    def test_not_while_a_fix_is_still_open_on_that_server(self):
        from system.contracts import WorkflowBinding
        binding = WorkflowBinding('w' * 32, 'ubuntu', self.target, self.epoch, 'b', '2026-11-13T00:00:00+00:00')
        self.ledger.add_binding(binding)
        self.ledger.claim(binding, 'op-open', 'execution', {'request_sha256': 'f' * 64}, mutation=True)
        with self.assertRaisesRegex(VerificationRefused, 'still open'):
            self.ledger.register(ubuntu(NEW), HERE, readdress=True, key_confirmed=True)

    def test_key_changes_are_append_only(self):
        self.ledger.register(ubuntu(NEW), HERE, readdress=True, key_confirmed=True)
        from contextlib import closing
        with closing(sqlite3.connect(self.ledger.path)) as db:
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('UPDATE key_changes SET fingerprint=?', (OLD,))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('DELETE FROM key_changes')


class ConnectionKeyChangeTests(unittest.TestCase):
    """The whole connect: the SSH login's key check, then the ledger."""

    def setUp(self):
        from system.connection import ConnectionService
        from system.ledger import CoordinationLedger
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.ledger = CoordinationLedger(Path(folder.name) / 'ledger.sqlite3')
        self.ledger.register(ubuntu(OLD), HERE)
        self.server_key = NEW  # the restored VM now offers another key

        def ssh(request, credentials, known):
            from system.identity import verify_fingerprint
            verify_fingerprint(self.server_key, known, credentials.confirmed_fingerprint)  # as SshChannel.connect
            return N(verify_identity=lambda req: ubuntu(self.server_key), close=lambda: None, alive=lambda: True)
        self.service = ConnectionService(self.ledger, ssh_factory=ssh, backend_factory=lambda session: N(),
                                         discover=lambda endpoint: N(transport='ssh', code=None, detail=None))

    def connect(self, *, paired, signed_key):
        from system.session import Credentials
        reference = self.service.vault.put(Credentials('vboxuser', 'TEST-ONLY', None, None, signed_key))
        return self.service.connect(ConnectionRequest(HERE, 'Ubuntu2204', MACHINE, reference), paired=paired)

    def test_a_re_pair_whose_signed_answer_names_the_new_key_connects(self):
        result = self.connect(paired=True, signed_key=NEW)
        self.assertEqual(result.state, 'connected', result)
        self.assertEqual(self.ledger.registration('ubuntu', MACHINE)['fingerprint'], NEW)

    def test_a_plain_reconnect_still_refuses_the_changed_key(self):
        result = self.connect(paired=False, signed_key=None)
        self.assertNotEqual(result.state, 'connected')
        self.assertEqual(self.ledger.registration('ubuntu', MACHINE)['fingerprint'], OLD)

    def test_the_ledger_checks_the_signed_key_itself_even_if_the_login_did_not(self):
        """Second layer: if a channel ever let a different key through, the ledger still refuses to record it."""
        self.service._ssh_factory = lambda request, credentials, known: N(
            verify_identity=lambda req: ubuntu(NEW), close=lambda: None, alive=lambda: True)  # no key check at all
        result = self.connect(paired=True, signed_key='SHA256:' + 'M' * 43)
        self.assertNotEqual(result.state, 'connected')
        self.assertEqual(self.ledger.registration('ubuntu', MACHINE)['fingerprint'], OLD)

    def test_a_re_pair_whose_signed_answer_names_another_key_is_refused(self):
        result = self.connect(paired=True, signed_key='SHA256:' + 'M' * 43)
        self.assertNotEqual(result.state, 'connected')
        self.assertEqual(self.ledger.registration('ubuntu', MACHINE)['fingerprint'], OLD)


if __name__ == '__main__':
    unittest.main()
