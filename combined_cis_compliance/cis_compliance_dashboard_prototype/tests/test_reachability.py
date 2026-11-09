"""Whether the connected Windows server still answers (reachability.py): a TCP connect to its WinRM port only."""
from datetime import datetime, timedelta, timezone
import socket
import unittest

from hardening import reachability


class AnswersTests(unittest.TestCase):
    def test_a_listening_port_answers_and_a_closed_one_does_not(self):
        server = socket.socket()
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            self.assertTrue(reachability.answers('127.0.0.1', port))
        finally:
            server.close()
        self.assertFalse(reachability.answers('127.0.0.1', port, timeout=0.5))


class CheckTests(unittest.TestCase):
    NOW = datetime(2026, 11, 10, 1, 0, tzinfo=timezone.utc)

    def check(self, previous, ok, seconds_later=0, key='server-1'):
        calls = []

        def probe(host, port):
            calls.append((host, port))
            return ok
        state = reachability.check(previous, key, 'host', 5985, now=self.NOW + timedelta(seconds=seconds_later),
                                   probe=probe)
        return state, calls

    def test_it_says_when_the_server_stops_and_starts_answering_and_reuses_a_recent_check(self):
        first, calls = self.check(None, True)
        self.assertTrue(first['ok'] and first['changed'] and not first['back'])
        self.assertEqual(calls, [('host', 5985)])
        reused, calls = self.check(first, False, seconds_later=5)  # Younger than the interval: no new connection.
        self.assertEqual((reused['ok'], reused['changed'], calls), (True, False, []))
        down, _ = self.check(first, False, seconds_later=reachability.CHECK_EVERY_SECONDS)
        self.assertEqual((down['ok'], down['changed'], down['since']),
                         (False, True, self.NOW + timedelta(seconds=reachability.CHECK_EVERY_SECONDS)))
        still, _ = self.check(down, False, seconds_later=2 * reachability.CHECK_EVERY_SECONDS)
        self.assertEqual((still['ok'], still['changed'], still['since']), (False, False, down['since']))
        back, _ = self.check(still, True, seconds_later=3 * reachability.CHECK_EVERY_SECONDS)
        self.assertTrue(back['ok'] and back['changed'] and back['back'])

    def test_another_server_is_checked_afresh(self):
        first, _ = self.check(None, False)
        other, calls = self.check(first, True, seconds_later=1, key='server-2')
        self.assertEqual((other['ok'], other['changed'], other['back'], len(calls)), (True, True, False, 1))


if __name__ == '__main__':
    unittest.main()
