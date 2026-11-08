"""The Ubuntu pairing helper (scripts/server_access/fyp-pair-ubuntu.py) against the dashboard's own pairing code.
Its functions run here with fakes for the server's files, sshd and UFW; the live test pairs over UDP on this
computer's own address. Nothing is installed and no firewall is touched."""
import ast
import base64
import importlib.util
import json
from pathlib import Path
import socket
import threading
import unittest
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import paramiko

from backends.ubuntu.ssh_channel import fingerprint as channel_fingerprint
from hardening import pairing
from hardening.pairing import PairingError
from hardening.pairing_client import find_server, local_addresses

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'server_access' / 'fyp-pair-ubuntu.py'
spec = importlib.util.spec_from_file_location('fyp_pair_ubuntu', SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

OWN = (local_addresses() or [None])[0]
CODE = '482913075'
MACHINE_ID = '0123456789abcdef0123456789abcdef'


def ed25519_pub():
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    return key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + ' root@vm'


def files(pub, os_release='ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.5 LTS"\n'):
    content = {'/etc/os-release': os_release, '/etc/machine-id': MACHINE_ID + '\n',
               '/etc/ssh/ssh_host_ed25519_key.pub': pub}

    def read(path):
        if path not in content:
            raise FileNotFoundError(path)
        return content[path]
    return read


def facts(**overrides):
    values = dict(hostname='ubuntu-web01', machine_uuid=str(UUID(MACHINE_ID)), port=22, os_name='Ubuntu 22.04.5 LTS',
                  os_version='22.04', host_key='SHA256:' + 'K' * 43)
    values.update(overrides)
    return values


class Run:
    """Stands in for subprocess.run: records commands, answers with fixed output."""

    def __init__(self, outputs=None, fail_on=None):
        self.calls, self.outputs, self.fail_on = [], outputs or {}, fail_on

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        failed = self.fail_on is not None and self.fail_on in ' '.join(command)
        return type('Result', (), dict(returncode=1 if failed else 0, stdout=self.outputs.get(command[0], ''),
                                       stderr='ERROR: fixture' if failed else ''))()


class HelperMessageTests(unittest.TestCase):
    def test_it_runs_on_the_python_of_ubuntu_2204(self):
        ast.parse(SCRIPT.read_text(encoding='utf-8'), feature_version=(3, 10))

    def test_its_answer_is_accepted_by_the_dashboard_and_names_the_host_key(self):
        question, nonce = pairing.make_find(CODE, 'DESKTOP-KHOO')
        verdict, message = helper.check_find(question, CODE)
        self.assertEqual((verdict, message['laptop_name']), ('ok', 'DESKTOP-KHOO'))
        answer = pairing.read_found(helper.make_found(CODE, nonce, facts(), 'd' * 32), CODE, nonce)
        self.assertEqual((answer['os'], answer['os_version'], answer['host_key']), ('ubuntu', '22.04', 'SHA256:' + 'K' * 43))
        self.assertEqual(UUID(answer['machine_uuid']).hex, MACHINE_ID)

    def test_a_changed_host_key_or_another_code_does_not_pass(self):
        question, nonce = pairing.make_find(CODE, 'DESKTOP-KHOO')
        raw = json.loads(helper.make_found(CODE, nonce, facts(), 'd' * 32))
        raw['host_key'] = 'SHA256:' + 'M' * 43
        with self.assertRaisesRegex(PairingError, 'wrong pairing code'):
            pairing.read_found(json.dumps(raw).encode(), CODE, nonce)
        with self.assertRaisesRegex(PairingError, 'wrong pairing code'):
            pairing.read_found(helper.make_found('111111111', nonce, facts(), 'd' * 32), CODE, nonce)
        del raw['host_key']  # An Ubuntu answer without a host key is not accepted at all.
        with self.assertRaises(PairingError):
            pairing.read_found(json.dumps(raw).encode(), CODE, nonce)

    def test_questions_are_sorted_into_ok_wrong_and_not_ours(self):
        question, _ = pairing.make_find('000000001', 'DESKTOP-KHOO')
        self.assertEqual(helper.check_find(question, CODE)[0], 'wrong')
        for raw in (b'', b'hello', b'{}', b'x' * 2000, json.dumps({'type': 'find'}).encode(),
                    pairing.make_found(CODE, 'a' * 32, 'WIN', str(UUID(MACHINE_ID)), 5985, 'a' * 32, os='windows',
                                       os_name='Windows', os_version='10.0.20348')):
            self.assertEqual(helper.check_find(raw, CODE), ('ignore', None), raw[:40])


class HelperFactsTests(unittest.TestCase):
    def test_the_fingerprint_is_the_one_the_ssh_library_computes(self):
        pub = ed25519_pub()
        kind, value = helper.fingerprint_of_pub(pub)
        blob = base64.b64decode(pub.split()[1])
        self.assertEqual((kind, value), ('ssh-ed25519', channel_fingerprint(paramiko.Ed25519Key(data=blob))))

    def test_facts_come_from_the_server_itself(self):
        pub = ed25519_pub()
        found = helper.server_facts(read=files(pub), settings={'hostkey': [], 'port': ['2222']}, hostname='ubuntu-web01')
        self.assertEqual((found['machine_uuid'], found['port'], found['os_name'], found['os_version']),
                         (str(UUID(MACHINE_ID)), 2222, 'Ubuntu 22.04.5 LTS', '22.04'))
        self.assertEqual(found['host_key'], helper.fingerprint_of_pub(pub)[1])
        with self.assertRaisesRegex(helper.HelperError, 'for Ubuntu'):
            helper.server_facts(read=files(pub, 'ID=debian\nVERSION_ID="12"\n'), settings={}, hostname='x')
        with self.assertRaisesRegex(helper.HelperError, 'hostname'):
            helper.server_facts(read=files(pub), settings={}, hostname='bad name')

    def test_the_host_key_offered_first_to_the_dashboard_is_chosen(self):
        ed, rsa = ed25519_pub(), 'ssh-rsa ' + base64.b64encode(b'\x00\x00\x00\x07ssh-rsa-fixture').decode()
        keys = {'/k/ed.pub': ed, '/k/rsa.pub': rsa}

        def read(path):
            if path not in keys:
                raise FileNotFoundError(path)
            return keys[path]
        settings = {'hostkey': ['/k/rsa', '/k/ed'], 'hostkeyalgorithms': ['ssh-ed25519', 'rsa-sha2-512']}
        self.assertEqual(helper.host_key(settings, read), helper.fingerprint_of_pub(ed)[1])
        settings['hostkeyalgorithms'] = ['rsa-sha2-512', 'rsa-sha2-256']  # sshd offers RSA only.
        self.assertEqual(helper.host_key(settings, read), helper.fingerprint_of_pub(rsa)[1])
        with self.assertRaisesRegex(helper.HelperError, 'No SSH host key'):
            helper.host_key({'hostkey': ['/k/missing']}, read)


class HelperSessionTests(unittest.TestCase):
    def setUp(self):
        self.now = [0.0]
        self.pairing = helper.Pairing(CODE, facts(), clock=lambda: self.now[0], minutes=10)

    def test_one_laptop_pairs_and_only_its_repeated_question_is_answered_again(self):
        question, nonce = pairing.make_find(CODE, 'DESKTOP-KHOO')
        answer, line = self.pairing.handle(question, '192.168.56.1')
        self.assertIn('Paired with DESKTOP-KHOO (192.168.56.1)', line)
        self.assertEqual(self.pairing.handle(question, '192.168.56.1')[0], answer)  # Lost answer: same bytes again.
        other, _ = pairing.make_find(CODE, 'OTHER-PC')
        self.assertEqual(self.pairing.handle(other, '192.168.56.9'), (None, None))  # One use only.
        self.assertFalse(self.pairing.finished)
        self.now[0] += helper.REPEAT_SECONDS + 1
        self.assertTrue(self.pairing.finished)
        self.assertEqual(self.pairing.state, 'paired')

    def test_wrong_codes_stop_pairing(self):
        guess = lambda n: pairing.make_find(f'{n:09d}', 'GUESSER')[0]  # Each new guess is a new question.
        for n in range(1, helper.WRONG_PER_ADDRESS):
            self.assertIn(f'({n} of 5)', self.pairing.handle(guess(n), '192.168.56.66')[1])
        self.assertIn('Too many wrong codes', self.pairing.handle(guess(5), '192.168.56.66')[1])
        self.assertEqual(self.pairing.state, 'locked')
        self.assertTrue(self.pairing.finished)
        right, _ = pairing.make_find(CODE, 'DESKTOP-KHOO')
        self.assertTrue(self.pairing.finished)

    def test_a_repeated_wrong_question_is_one_attempt_but_every_new_guess_counts(self):
        wrong, _ = pairing.make_find('000000001', 'DESKTOP-KHOO')
        self.assertIn('(1 of 5)', self.pairing.handle(wrong, '192.168.56.1')[1])
        for _ in range(2):  # The dashboard's two repeats of the same question.
            self.assertEqual(self.pairing.handle(wrong, '192.168.56.1'), (None, None))
        guess, _ = pairing.make_find('000000002', 'DESKTOP-KHOO')
        self.assertIn('(2 of 5)', self.pairing.handle(guess, '192.168.56.1')[1])
        right, _ = pairing.make_find(CODE, 'DESKTOP-KHOO')
        self.assertIn('Paired with', self.pairing.handle(right, '192.168.56.1')[1])

    def test_the_code_expires(self):
        self.now[0] += 10 * 60 + 1
        question, _ = pairing.make_find(CODE, 'DESKTOP-KHOO')
        self.assertEqual(self.pairing.handle(question, '192.168.56.1'), (None, None))
        self.assertEqual(self.pairing.state, 'expired')


class HelperFirewallTests(unittest.TestCase):
    def test_the_rules_are_local_networks_only_and_removed_afterwards(self):
        run = Run({'ufw': 'Status: active\n'})
        self.assertTrue(helper.ufw_active(run))
        rules = helper.open_firewall(47815, run)
        self.assertEqual([c[5] for c in run.calls[1:]], ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
        self.assertTrue(all(c[-2:] == ['comment', 'fyp-pairing'] and 'udp' in c for c in run.calls[1:]))
        helper.close_firewall(rules, run)
        self.assertEqual([c[:2] for c in run.calls[-3:]], [['ufw', 'delete']] * 3)
        self.assertEqual(rules, [])

    def test_a_failed_rule_leaves_nothing_behind(self):
        run = Run(fail_on='172.16.0.0/12')
        with self.assertRaisesRegex(helper.HelperError, 'temporary UFW rule'):
            helper.open_firewall(47815, run)
        self.assertEqual(run.calls[-1][:2], ['ufw', 'delete'])
        self.assertIn('10.0.0.0/8', run.calls[-1])

    def test_inactive_or_missing_ufw_adds_nothing(self):
        self.assertFalse(helper.ufw_active(Run({'ufw': 'Status: inactive\n'})))

        def missing(*a, **k):
            raise FileNotFoundError('ufw')
        self.assertFalse(helper.ufw_active(missing))


@unittest.skipUnless(OWN, 'needs an IPv4 network address')
class HelperLiveTests(unittest.TestCase):
    def test_the_dashboard_finds_the_ubuntu_helper_by_its_code(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((OWN, 0)); self.addCleanup(sock.close)
        session = helper.Pairing(CODE, facts(), minutes=1)
        lines = []
        thread = threading.Thread(target=helper.serve, args=(session, sock, lines.append), daemon=True)
        thread.start()
        found = find_server(CODE, name='DESKTOP-KHOO', sources=[OWN], targets=[(OWN, sock.getsockname()[1])], timeout=4)
        self.assertEqual((found.platform, found.transport, found.machine_identity, found.port, found.host_key),
                         ('ubuntu', 'ssh', MACHINE_ID, 22, 'SHA256:' + 'K' * 43))
        self.assertEqual((found.system.kind, found.system.supported), ('ubuntu_2204', True))
        thread.join(helper.REPEAT_SECONDS + 5)
        self.assertEqual(session.state, 'paired')
        self.assertIn(f'Paired with DESKTOP-KHOO ({OWN})', lines[0])


if __name__ == '__main__':
    unittest.main()
