#!/usr/bin/env python3
"""FYP pairing helper for Ubuntu 22.04: lets the dashboard find this server by a one-time code.

Run it on the Ubuntu server, as root:

    sudo python3 fyp-pair-ubuntu.py

It shows a 9-digit code. Type that code on the dashboard's Servers page (Add a server). The dashboard asks the local
network for the server with that code; this helper answers with the server's name, machine identity
(/etc/machine-id), Ubuntu version and the fingerprint of the SSH host key the dashboard will meet when it logs in.
The answer is signed with the code, so the code itself never travels on the network and the administrator does not
have to type the fingerprint. Logging in still needs the server account and password (or key), over SSH as before.

What it changes, and undoes:
  - While the code is shown, if UFW is active, it allows UDP port 47815 from local (private-range) networks only,
    with the rule comment "fyp-pairing". The rules are deleted when the helper stops, however it stops.
  - Nothing else. It does not touch SSH, users, keys or any CIS setting, and it keeps no record on the server.
It stops after one laptop has paired (answering that laptop's repeats for a few seconds), after 10 minutes, after 5
wrong codes from one address or 20 in total, or on Ctrl+C.

The messages are those of the dashboard's hardening/pairing.py (version 1). An Ubuntu answer adds `host_key`.
Python 3.10 standard library only.
"""
import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import sys
import time
import uuid

PAIRING_PORT = 47815
VERSION = 1
MAX_MESSAGE = 1024
CODE_DIGITS = 9
MINUTES = 10
WRONG_PER_ADDRESS, WRONG_TOTAL = 5, 20
REPEAT_SECONDS = 15  # After pairing, the same laptop's repeated question is answered again for this long.
PRIVATE_NETWORKS = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
RULE_COMMENT = 'fyp-pairing'

_HEX32 = re.compile(r'[0-9a-f]{32}')
_HEX64 = re.compile(r'[0-9a-f]{64}')
_NAME = re.compile(r'[A-Za-z0-9._-]{1,63}')
_OS_NAME = re.compile(r'[ -~]{1,100}')
_OS_VERSION = re.compile(r'[A-Za-z0-9._-]{1,32}')
FIND_KEYS = {'v', 'type', 'nonce_l', 'laptop_name', 'mac'}
# The dashboard's SSH library tries host key types in this order; the first one sshd offers is the one it will see.
KEY_PREFERENCE = (('ssh-ed25519', 'ssh-ed25519'), ('ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp256'),
                  ('ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp384'), ('ecdsa-sha2-nistp521', 'ecdsa-sha2-nistp521'),
                  ('rsa-sha2-512', 'ssh-rsa'), ('rsa-sha2-256', 'ssh-rsa'))


class HelperError(Exception):
    """A plain reason the helper cannot run; printed as it is."""


# ------------------------------------------------------------------ messages (same as hardening/pairing.py)
def _key(code):
    return ('FYP-PAIR-v1:' + code).encode('ascii')


def _mac(code, *fields):
    return hmac.new(_key(code), '\n'.join(str(f) for f in fields).encode('utf-8'), hashlib.sha256).hexdigest()


def check_find(raw, code):
    """('ok', message) for the right code; ('wrong', message) for a well-formed question with another code;
    ('ignore', None) for anything that is not a pairing question."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_MESSAGE:
        return 'ignore', None
    try:
        m = json.loads(bytes(raw).decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return 'ignore', None
    if (type(m) is not dict or set(m) != FIND_KEYS or m.get('type') != 'find' or type(m.get('v')) is not int
            or m['v'] != VERSION or type(m.get('mac')) is not str or not _HEX64.fullmatch(m['mac'])
            or type(m.get('nonce_l')) is not str or not _HEX32.fullmatch(m['nonce_l'])
            or type(m.get('laptop_name')) is not str or not _NAME.fullmatch(m['laptop_name'])):
        return 'ignore', None
    expected = _mac(code, 'find', VERSION, m['nonce_l'], m['laptop_name'])
    return ('ok' if hmac.compare_digest(expected, m['mac']) else 'wrong'), m


def make_found(code, nonce_l, facts, pairing_id, nonce_s=None):
    message = dict(v=VERSION, type='found', nonce_l=nonce_l, nonce_s=nonce_s or secrets.token_hex(16),
                   hostname=facts['hostname'], machine_uuid=facts['machine_uuid'], port=facts['port'],
                   pairing_id=pairing_id, os='ubuntu', os_name=facts['os_name'], os_version=facts['os_version'],
                   host_key=facts['host_key'])
    message['mac'] = _mac(code, 'found', VERSION, message['nonce_l'], message['nonce_s'], message['hostname'],
                          message['machine_uuid'], message['port'], message['pairing_id'], message['os'],
                          message['os_name'], message['os_version'], message['host_key'])
    raw = json.dumps(message, separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_MESSAGE:
        raise HelperError('The pairing answer would be too large.')
    return raw


def format_code(code):
    return f'{code[:3]}-{code[3:6]}-{code[6:]}'


# ------------------------------------------------------------------ what this server says about itself
def read_os_release(text):
    values = {}
    for line in text.splitlines():
        name, sep, value = line.partition('=')
        if sep and re.fullmatch(r'[A-Z][A-Z0-9_]*', name):
            values[name] = value.strip().strip('"').strip("'")
    return values


def fingerprint_of_pub(line):
    """('key type', 'SHA256:...') from one line of an OpenSSH .pub file: the hash of the key blob, as ssh-keygen -l
    and the dashboard's SSH library both compute it."""
    parts = line.split()
    if len(parts) < 2:
        raise HelperError('Unreadable SSH host public key.')
    blob = base64.b64decode(parts[1], validate=True)
    return parts[0], 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode('ascii').rstrip('=')


def sshd_settings(run=subprocess.run):
    """sshd's effective settings (sshd -T): host key files, offered host key algorithms and the port."""
    try:
        result = run(['sshd', '-T'], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return {}
    if result.returncode != 0:
        return {}
    settings = {'hostkey': [], 'port': []}
    for line in result.stdout.splitlines():
        name, _, value = line.partition(' ')
        if name in ('hostkey', 'port'):
            settings[name].append(value.strip())
        elif name == 'hostkeyalgorithms':
            settings[name] = value.strip().split(',')
    return settings


def host_key(settings, read=lambda path: open(path, encoding='ascii').read()):
    """The fingerprint of the host key the dashboard will be shown: the first type in its preference order that sshd
    both has a key for and offers."""
    files = settings.get('hostkey') or ['/etc/ssh/ssh_host_ed25519_key', '/etc/ssh/ssh_host_ecdsa_key',
                                        '/etc/ssh/ssh_host_rsa_key']
    keys = {}
    for path in files:
        try:
            kind, value = fingerprint_of_pub(read(path + '.pub').strip())
        except (OSError, ValueError, HelperError):
            continue
        keys.setdefault(kind, value)
    offered = settings.get('hostkeyalgorithms')
    for algorithm, kind in KEY_PREFERENCE:
        if kind in keys and (offered is None or algorithm in offered):
            return keys[kind]
    raise HelperError('No SSH host key found that the dashboard can use. Is openssh-server installed?')


def server_facts(*, ssh_port=None, read=lambda path: open(path, encoding='ascii').read(), settings=None,
                 hostname=None):
    os_release = read_os_release(read('/etc/os-release'))
    if os_release.get('ID') != 'ubuntu':
        raise HelperError('This helper is for Ubuntu. On Windows Server 2022 use FYP-ServerAccess.ps1.')
    machine_id = read('/etc/machine-id').strip()
    if not _HEX32.fullmatch(machine_id) or machine_id == '0' * 32:
        raise HelperError('/etc/machine-id is missing or invalid.')
    name = hostname or socket.gethostname()
    if not _NAME.fullmatch(name):
        raise HelperError('The hostname has characters the dashboard does not accept: ' + repr(name))
    os_name = os_release.get('PRETTY_NAME', 'Ubuntu')
    os_version = os_release.get('VERSION_ID', '')
    if not _OS_NAME.fullmatch(os_name) or not _OS_VERSION.fullmatch(os_version):
        raise HelperError('/etc/os-release has an unexpected name or version.')
    settings = sshd_settings() if settings is None else settings
    port = ssh_port or int((settings.get('port') or ['22'])[0])
    if not 1 <= port <= 65535:
        raise HelperError('Invalid SSH port.')
    return dict(hostname=name, machine_uuid=str(uuid.UUID(machine_id)), port=port, os_name=os_name,
                os_version=os_version, host_key=host_key(settings, read))


# ------------------------------------------------------------------ the temporary firewall opening
def ufw_active(run=subprocess.run):
    try:
        result = run(['ufw', 'status'], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout.splitlines()[:1] == ['Status: active']


def _rule(network, port):
    return ['allow', 'proto', 'udp', 'from', network, 'to', 'any', 'port', str(port)]


def open_firewall(port, run=subprocess.run):
    """Allow the pairing question in from local networks; returns the rules added, for close_firewall()."""
    added = []
    for network in PRIVATE_NETWORKS:
        rule = _rule(network, port)
        result = run(['ufw'] + rule + ['comment', RULE_COMMENT], capture_output=True, text=True, timeout=30,
                     check=False)
        if result.returncode != 0:
            close_firewall(added, run)
            raise HelperError('Could not add the temporary UFW rule: ' + (result.stderr or result.stdout).strip()[:200])
        added.append(rule)
    return added


def close_firewall(rules, run=subprocess.run):
    for rule in reversed(rules):
        run(['ufw', 'delete'] + rule, capture_output=True, text=True, timeout=30, check=False)
    rules.clear()


# ------------------------------------------------------------------ listening
class Pairing:
    """One pairing session: one code, one laptop. Decides what to do with each question; sends nothing itself."""

    def __init__(self, code, facts, *, clock=time.monotonic, minutes=MINUTES):
        self.code, self.facts = code, facts
        self.pairing_id = secrets.token_hex(16)
        self.clock = clock
        self.expires = clock() + minutes * 60
        self.wrong, self.wrong_total = {}, 0
        # The dashboard sends each question 3 times in case one is lost. A byte-identical repeat from the same address
        # is one attempt, not three; a different guess has a different signature, so it always counts.
        self.wrong_seen = set()
        self.paired = None  # (nonce_l, laptop address, laptop name, answer bytes, until)
        self.state = 'waiting'  # waiting | paired | expired | locked

    def handle(self, raw, address):
        """The bytes to send back to `address`, or None. Updates `state` and returns a line to print, if any."""
        now = self.clock()
        if self.paired:
            nonce, laptop, _, answer, until = self.paired
            if now > until:
                self.state = 'paired'
                return None, None
            verdict, message = check_find(raw, self.code)
            if verdict == 'ok' and message['nonce_l'] == nonce and address == laptop:
                return answer, None  # The answer was lost on the way: send it again.
            return None, None
        if now > self.expires:
            self.state = 'expired'
            return None, None
        verdict, message = check_find(raw, self.code)
        if verdict == 'ignore':
            return None, None
        if verdict == 'wrong':
            attempt = (address, hashlib.sha256(bytes(raw)).hexdigest())
            if attempt in self.wrong_seen:
                return None, None
            self.wrong_seen.add(attempt)
            self.wrong[address] = self.wrong.get(address, 0) + 1
            self.wrong_total += 1
            if self.wrong[address] >= WRONG_PER_ADDRESS or self.wrong_total >= WRONG_TOTAL:
                self.state = 'locked'
                return None, f'Wrong code from {address}. Too many wrong codes: pairing stopped.'
            return None, f'Wrong code from {address} ({self.wrong[address]} of {WRONG_PER_ADDRESS}).'
        answer = make_found(self.code, message['nonce_l'], self.facts, self.pairing_id)
        self.paired = (message['nonce_l'], address, message['laptop_name'], answer, now + REPEAT_SECONDS)
        return answer, f'Paired with {message["laptop_name"]} ({address}). It can now log in over SSH.'

    @property
    def finished(self):
        if self.paired and self.clock() > self.paired[4]:
            self.state = 'paired'
        elif not self.paired and self.clock() > self.expires:
            self.state = 'expired'
        return self.state != 'waiting'


def serve(pairing, sock, out=print):
    """Answer questions on `sock` until the pairing finishes."""
    while not pairing.finished:
        sock.settimeout(0.5)
        try:
            raw, (address, port) = sock.recvfrom(MAX_MESSAGE + 1)
        except socket.timeout:
            continue
        except OSError:
            continue
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            continue
        answer, line = pairing.handle(raw, address)
        if line:
            out(line)
        if answer:
            try:
                sock.sendto(answer, (address, port))
            except OSError:
                pass
    return pairing.state


def main(argv=None):
    parser = argparse.ArgumentParser(description='Show a one-time code so the FYP dashboard can find this server.')
    parser.add_argument('--ssh-port', type=int, default=None, help='SSH port to report (default: sshd -T, else 22)')
    parser.add_argument('--minutes', type=int, default=MINUTES, help='how long the code is valid (default 10)')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print('Run as root: sudo python3 fyp-pair-ubuntu.py  (needed for sshd -T and the temporary UFW rule)')
        return 2
    try:
        facts = server_facts(ssh_port=args.ssh_port)
    except HelperError as exc:
        print('Cannot pair:', exc)
        return 2
    code = ''.join(secrets.choice('0123456789') for _ in range(CODE_DIGITS))
    pairing = Pairing(code, facts, minutes=max(1, min(args.minutes, 30)))
    rules = []

    def stop(signum, frame):  # A terminated helper still removes its firewall rules (the finally below).
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', PAIRING_PORT))
        if ufw_active():
            rules = open_firewall(PAIRING_PORT)
            print(f'UFW: temporarily allowing UDP {PAIRING_PORT} from local networks (removed when this stops).')
        print()
        print(f'  Server        {facts["hostname"]}  ({facts["os_name"]})')
        print(f'  SSH           port {facts["port"]}, host key {facts["host_key"]}')
        print()
        print(f'  Pairing code  {format_code(code)}')
        print()
        print(f'Type this code on the dashboard: Servers > Add a server. Valid for {args.minutes} minutes, one use.')
        print('Waiting... (Ctrl+C to stop)')
        state = serve(pairing, sock)
        print({'paired': 'Done.', 'expired': 'The code expired. Run the helper again for a new code.',
               'locked': 'Stopped after too many wrong codes. Run the helper again for a new code.'}[state])
        return 0 if state == 'paired' else 1
    except KeyboardInterrupt:
        print('\nStopped. No laptop was paired.' if not pairing.paired else '\nStopped.')
        return 1
    except HelperError as exc:
        print('Cannot pair:', exc)
        return 2
    except OSError as exc:
        print(f'Cannot listen on UDP port {PAIRING_PORT}: {exc.strerror or exc}')
        return 2
    finally:
        sock.close()
        if rules:
            close_firewall(rules)
            print('UFW: temporary pairing rules removed.')


if __name__ == '__main__':
    sys.exit(main())
