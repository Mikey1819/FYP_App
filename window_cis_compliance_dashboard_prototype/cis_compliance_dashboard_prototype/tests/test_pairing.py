"""Pairing messages (hardening/pairing.py) against the shared examples, plus a live round trip with the PowerShell
helper's own functions. No network is used."""
import base64
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from hardening import pairing
from hardening.pairing import PairingError

HELPER = Path(__file__).resolve().parents[2] / 'scripts' / 'server_access'
VECTORS = json.loads((HELPER / 'pairing_vectors.json').read_text(encoding='utf-8'))
CODE, F, G = VECTORS['code'], VECTORS['find'], VECTORS['found']


def found_args(**overrides):
    values = dict(nonce_l=G['nonce_l'], hostname=G['hostname'], machine_uuid=G['machine_uuid'], port=G['port'],
                  pairing_id=G['pairing_id'], nonce_s=G['nonce_s'], os=G['os'], os_name=G['os_name'],
                  os_version=G['os_version'])
    values.update(overrides)
    return values


class PairingMessageTests(unittest.TestCase):
    def test_the_shared_examples_are_reproduced_byte_for_byte(self):
        raw, nonce = pairing.make_find(CODE, F['laptop_name'], nonce_l=F['nonce_l'])
        self.assertEqual((raw.decode(), nonce), (F['raw'], F['nonce_l']))
        self.assertEqual(pairing.make_found(CODE, **found_args()).decode(), G['raw'])

    def test_the_server_accepts_a_question_only_with_the_right_code(self):
        self.assertEqual(pairing.read_find(F['raw'].encode(), CODE)['laptop_name'], 'DESKTOP-KHOO')
        with self.assertRaisesRegex(PairingError, 'wrong pairing code'):
            pairing.read_find(F['raw'].encode(), VECTORS['wrong_code'])
        with self.assertRaisesRegex(PairingError, 'wrong pairing code'):
            pairing.read_find(F['raw'].replace('DESKTOP-KHOO', 'DESKTOP-EVIL').encode(), CODE)

    def test_the_laptop_accepts_only_an_answer_to_its_own_question_with_the_right_code(self):
        self.assertEqual(pairing.read_found(G['raw'].encode(), CODE, G['nonce_l'])['hostname'], 'WIN-VFT30DUDRHQ')
        with self.assertRaisesRegex(PairingError, 'another question'):
            pairing.read_found(G['raw'].encode(), CODE, 'f' * 32)  # A replayed answer to an earlier question.
        with self.assertRaisesRegex(PairingError, 'wrong pairing code'):
            pairing.read_found(G['raw'].encode(), VECTORS['wrong_code'], G['nonce_l'])
        for field, value in (('hostname', 'IMPOSTOR'), ('port', 5986), ('machine_uuid', '11111111-2222-3333-4444-555555555555'),
                             ('os', 'ubuntu'), ('os_name', 'Ubuntu 22.04.4 LTS'), ('os_version', '22.04')):
            changed = json.loads(G['raw']); changed[field] = value
            with self.assertRaisesRegex(PairingError, 'wrong pairing code'):
                pairing.read_found(json.dumps(changed).encode(), CODE, G['nonce_l'])

    def test_anything_else_on_the_network_is_refused_as_not_ours(self):
        good = json.loads(G['raw'])
        bad = [b'', b'hello', b'{}', b'[]', b'null', b'\xc3\x28', b'x' * 2000, F['raw'].encode()]
        for change in ({'v': 2}, {'v': True}, {'extra': 1}, {'port': '5985'}, {'port': 0}, {'port': True},
                       {'hostname': 'WIN SERVER'}, {'machine_uuid': G['machine_uuid'].upper()},
                       {'pairing_id': 'xyz'}, {'mac': 'A' * 64}, {'os': 'Windows'}, {'os': ''}, {'os': 7},
                       {'os_name': ''}, {'os_name': 'line\nbreak'}, {'os_name': 'x' * 101}, {'os_name': 'Café'},
                       {'os_version': '22 04'}, {'os_version': None}):
            bad.append(json.dumps({**good, **change}).encode())
        missing = dict(good); del missing['nonce_s']
        bad.append(json.dumps(missing).encode())
        for raw in bad:
            with self.assertRaises(PairingError, msg=raw[:60]):
                pairing.read_found(raw, CODE, G['nonce_l'])

    def test_codes_are_typed_loosely_but_must_be_nine_digits(self):
        for typed in ('482913075', '482-913-075', ' 482 913 075 '):
            self.assertEqual(pairing.normalize_code(typed), '482913075')
        for typed in ('', '48291307', '4829130755', '48291307a', '482_913_075'):
            with self.assertRaises(ValueError):
                pairing.normalize_code(typed)
        self.assertEqual(pairing.format_code('482913075'), '482-913-075')
        codes = {pairing.new_code() for _ in range(50)}
        self.assertTrue(all(len(c) == 9 and c.isdigit() for c in codes) and len(codes) > 45)

    def test_laptop_name_is_reduced_to_safe_characters(self):
        self.assertEqual(pairing.laptop_name('DESKTOP-KHOO'), 'DESKTOP-KHOO')
        self.assertEqual(pairing.laptop_name('Khoo\'s <laptop>\n'), 'Khooslaptop')
        self.assertEqual(pairing.laptop_name('???'), 'laptop')
        self.assertEqual(len(pairing.laptop_name('A' * 100)), 63)


@unittest.skipUnless(shutil.which('powershell.exe'), 'Windows PowerShell is needed for the cross-language check')
class PowerShellRoundTripTests(unittest.TestCase):
    """Python asks, the helper's PowerShell functions check and answer, Python checks the answer: with a fresh random
    code and fresh nonces, so this is more than the fixed examples."""

    def test_python_and_the_helper_understand_each_other(self):
        code = pairing.new_code()
        find, nonce_l = pairing.make_find(code, 'DESKTOP-KHOO')
        script = (f'. "{HELPER / "FYP-ServerAccess.ps1"}" -FunctionsOnly\n'
                  f'$q = Read-PairFind ([Convert]::FromBase64String("{base64.b64encode(find).decode()}")) "{code}"\n'
                  f'$a = New-PairFound "{code}" $q.nonce_l "WIN-TEST" "E5D10741-F200-4292-A099-E6BE76032F4E" 5985 '
                  f'(New-Nonce) (New-Nonce) "windows" "Microsoft Windows Server 2022 Datacenter" "10.0.20348"\n'
                  '[Convert]::ToBase64String($a)\n'
                  'try { $null = Read-PairFind ([Convert]::FromBase64String("'
                  + base64.b64encode(find).decode() + '")) "000000000"; "accepted" } catch { $_.Exception.Message }\n')
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                 '-Command', script], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        answer_b64, wrong = result.stdout.split()
        answer = pairing.read_found(base64.b64decode(answer_b64), code, nonce_l)
        self.assertEqual((answer['hostname'], answer['machine_uuid'], answer['port']),
                         ('WIN-TEST', 'e5d10741-f200-4292-a099-e6be76032f4e', 5985))
        self.assertEqual((answer['os'], answer['os_name'], answer['os_version']),
                         ('windows', 'Microsoft Windows Server 2022 Datacenter', '10.0.20348'))
        self.assertEqual(wrong, 'wrong_code')


if __name__ == '__main__':
    unittest.main()
