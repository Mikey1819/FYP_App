"""Pairing by code from the dashboard's side: finding the server over UDP, reading and changing its paired laptops
over WinRM, and the Servers page flow. UDP runs on this computer's own address; WinRM is a fake session; the
PowerShell listener test runs the helper's own functions with record saving stubbed (no firewall rule, no file)."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from hardening import pairing, servers_view, winrm_channel
from hardening.connection_view import LIVE_TARGET
from hardening.pairing import PairingError
from hardening.pairing_client import FoundServer, find_server, local_addresses
from hardening.server_control import HELPER, close_access, disconnect_laptop, paired_laptops
from hardening.servers import ServerRegistry
from hardening.winrm_channel import IDENTITY_SCRIPT, ChannelError
from test_winrm_channel import IDENTITY, MACHINE_UUID, target

OWN = (local_addresses() or [None])[0]
OTHER_UUID = '11111111-2222-3333-4444-555555555555'
HELPER_TEXT = HELPER.read_text(encoding='utf-8-sig')
SERVER_DIR = HELPER.parent


class FakeServer(threading.Thread):
    """A pairing server in Python (pairing.py's server half) on this computer's own address."""

    def __init__(self, code, junk_first=False):
        super().__init__(daemon=True)
        self.code, self.junk_first, self.questions = code, junk_first, 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((OWN, 0))
        self.sock.settimeout(5)
        self.port = self.sock.getsockname()[1]

    def run(self):
        try:
            while True:
                raw, sender = self.sock.recvfrom(2048)
                self.questions += 1
                try:
                    question = pairing.read_find(raw, self.code)
                except PairingError:
                    continue  # Wrong code: the real helper does not answer either.
                if self.junk_first:  # Noise and a forged answer arrive before the real one.
                    self.sock.sendto(b'hello', sender)
                    self.sock.sendto(pairing.make_found('000000001', question['nonce_l'], 'IMPOSTOR', OTHER_UUID,
                                                        5985, 'e' * 32), sender)
                self.sock.sendto(pairing.make_found(self.code, question['nonce_l'], 'FIXTURE-SERVER', MACHINE_UUID,
                                                    5985, 'a' * 32), sender)
        except OSError:
            pass

    def stop(self):
        self.sock.close()


@unittest.skipUnless(OWN, 'needs an IPv4 network address')
class FindServerTests(unittest.TestCase):
    def serve(self, **kwargs):
        server = FakeServer(pairing.new_code(), **kwargs)
        server.start(); self.addCleanup(server.stop)
        return server

    def test_the_server_with_the_code_is_found(self):
        server = self.serve()
        found = find_server(server.code, name='DESKTOP-KHOO', sources=[OWN], targets=[(OWN, server.port)], timeout=3)
        self.assertEqual(found, FoundServer(OWN, 'FIXTURE-SERVER', MACHINE_UUID, 5985, 'a' * 32, OWN))

    def test_noise_and_forged_answers_are_ignored(self):
        server = self.serve(junk_first=True)
        found = find_server(server.code, sources=[OWN], targets=[(OWN, server.port)], timeout=3)
        self.assertEqual(found.hostname, 'FIXTURE-SERVER')

    def test_a_wrong_code_gets_no_answer_and_the_question_is_repeated(self):
        server = self.serve()
        wrong = '000000000' if server.code != '000000000' else '111111111'
        with self.assertRaisesRegex(PairingError, 'No server answered'):
            find_server(wrong, sources=[OWN], targets=[(OWN, server.port)], timeout=0.9, attempts=3)
        self.assertEqual(server.questions, 3)

    def test_no_network_address_is_explained(self):
        with patch('hardening.pairing_client.local_addresses', return_value=[]):
            with self.assertRaisesRegex(PairingError, 'no network address'):
                find_server('482913075')


@unittest.skipUnless(OWN and shutil.which('powershell.exe'), 'needs an IPv4 address and Windows PowerShell')
class PowerShellListenerTests(unittest.TestCase):
    def test_the_dashboard_pairs_with_the_helpers_own_listener(self):
        script = f'''
. "{SERVER_DIR / 'FYP-ServerAccess.ps1'}" -FunctionsOnly
$script:Saved = @()
function Save-Pairings([object[]]$Pairings) {{ $script:Saved = @($Pairings | Where-Object {{ $null -ne $_ }}) }}
function Get-Pairings {{ $script:Saved }}
function Get-ServerIdentity {{ [pscustomobject]@{{ hostname = 'WIN-TEST'; machine_uuid = '{MACHINE_UUID}' }} }}
$udp = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint([Net.IPAddress]::Parse('{OWN}'), 0))
$listener = [pscustomobject]@{{ udp = $udp; session = New-PairingSession ([DateTimeOffset]::UtcNow); done = @() }}
[Console]::Out.WriteLine("$($udp.Client.LocalEndPoint.Port) $($listener.session.code)"); [Console]::Out.Flush()
$until = (Get-Date).AddSeconds(20)
try {{
    while (-not (Test-ListenerFinished $listener) -and (Get-Date) -lt $until) {{
        Receive-PairPackets $listener | ForEach-Object {{ [Console]::Out.WriteLine($_) }}
        Start-Sleep -Milliseconds 50
    }}
}} finally {{ $udp.Close() }}
[Console]::Out.WriteLine('RECORD ' + ($script:Saved | ConvertTo-Json -Compress))
'''
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        path = Path(folder.name) / 'listener.ps1'
        path.write_text(script, encoding='ascii')  # A file, not stdin: stdin runs multi-line blocks line by line.
        process = subprocess.Popen(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                    '-File', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        port, code = process.stdout.readline().split()
        found = find_server(code, name='DESKTOP-KHOO', sources=[OWN], targets=[(OWN, int(port))], timeout=8)
        out, err = process.communicate(timeout=60)
        self.assertEqual((found.hostname, found.machine_uuid, found.laptop_address), ('WIN-TEST', MACHINE_UUID, OWN))
        self.assertIn(f'Paired with DESKTOP-KHOO ({OWN})', out, err)
        record = json.loads(out.split('RECORD ', 1)[1])
        self.assertEqual((record['pairing_id'], record['laptop_address']), (found.pairing_id, OWN))


class HelperSession:
    """Fake WinRM session: answers the identity probe, and runs the helper's remote actions on a list in memory."""

    def __init__(self, identity=IDENTITY, pairings=None, helper_enabled=False, report_uuid=None):
        self.identity, self.helper_enabled, self.report_uuid = identity, helper_enabled, report_uuid
        self.pairings = list(pairings or [])
        self.calls, self.fail = [], None

    def __call__(self, login):
        self.login = login
        return self

    def run(self, script, parameters=None):
        self.calls.append((script, parameters))
        if self.fail:
            raise self.fail
        if script == IDENTITY_SCRIPT:
            return [json.dumps(self.identity)], False, []
        assert script == HELPER_TEXT, 'Only the identity probe and the helper itself may be sent'
        action = parameters['Action']
        if action == 'RemovePairing':
            self.pairings = [p for p in self.pairings if p['pairing_id'] != parameters['PairingId']]
        elif action == 'CloseAccess':
            self.pairings = []
        report = dict(hostname=self.identity['hostname'], machine_uuid=self.report_uuid or self.identity['machine_uuid'],
                      pairings=self.pairings, helper_enabled_remoting=self.helper_enabled)
        return [json.dumps(report)], False, []


def laptop(pairing_id, address, name='DESKTOP-KHOO'):
    return dict(pairing_id=pairing_id, laptop_address=address, laptop_name=name,
                paired_at='2026-11-05T12:00:00.0000000+00:00')


class ServerControlTests(unittest.TestCase):
    def test_list_sends_the_helper_with_typed_parameters_after_the_identity_check(self):
        session = HelperSession(pairings=[laptop('a' * 32, '192.168.1.23')])
        report = paired_laptops(target(), session_factory=session)
        self.assertEqual([c[1] for c in session.calls], [None, {'Action': 'ListPairings'}])
        self.assertEqual(report['pairings'][0]['laptop_address'], '192.168.1.23')

    def test_disconnect_and_close_access(self):
        session = HelperSession(pairings=[laptop('a' * 32, '192.168.1.23'), laptop('b' * 32, '192.168.1.40', 'OTHER')])
        report = disconnect_laptop(target(), 'b' * 32, session_factory=session)
        self.assertEqual(session.calls[-1][1], {'Action': 'RemovePairing', 'PairingId': 'b' * 32})
        self.assertEqual([p['pairing_id'] for p in report['pairings']], ['a' * 32])
        self.assertEqual(close_access(target(), session_factory=session)['pairings'], [])
        with self.assertRaises(ValueError):
            disconnect_laptop(target(), "'; Remove-Item C:\\ -Recurse", session_factory=session)

    def test_another_machine_or_an_odd_answer_is_refused(self):
        session = HelperSession(identity={**IDENTITY, 'machine_uuid': OTHER_UUID})
        with self.assertRaises(ChannelError) as caught:
            paired_laptops(target(), session_factory=session)
        self.assertEqual(caught.exception.state, 'wrong_target')
        self.assertEqual(len(session.calls), 1, 'The helper is not sent to an unverified machine')
        with self.assertRaises(ChannelError) as caught:
            paired_laptops(target(), session_factory=HelperSession(report_uuid=OTHER_UUID))
        self.assertEqual(caught.exception.state, 'wrong_target')
        for bad in ([laptop('xyz', '192.168.1.23')], [laptop('a' * 32, 'not-an-address')], [{'pairing_id': 'a' * 32}]):
            with self.assertRaises(ChannelError) as caught:
                paired_laptops(target(), session_factory=HelperSession(pairings=bad))
            self.assertEqual(caught.exception.state, 'channel_error')


def servers_page():
    from hardening.databases import servers_database
    from hardening.servers_view import render_servers
    render_servers(servers_database())


FOUND = FoundServer('192.168.1.50', 'FIXTURE-SERVER', MACHINE_UUID, 5985, 'a' * 32, '192.168.1.23')


class PairingPageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.session = HelperSession(pairings=[laptop('a' * 32, '192.168.1.23'),
                                               laptop('b' * 32, '192.168.1.40', 'STRANGER-PC')])
        self.found = FOUND
        self.codes = []

        def fake_find(code):
            self.codes.append(code)
            return self.found
        for patcher in (patch.dict(os.environ, {'CIS_DASHBOARD_DB': str(self.folder / 'preview.sqlite3')}),
                        patch.object(winrm_channel, 'PsrpSession', self.session),
                        patch.object(servers_view, 'find_server', fake_find)):
            patcher.start(); self.addCleanup(patcher.stop)

    def page(self):
        return self.ok(AppTest.from_function(servers_page, default_timeout=30).run())

    def ok(self, app):
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        return app

    def registry(self):
        return ServerRegistry(self.folder / 'preview_imports_servers.sqlite3')

    def pair(self, app=None, code='482-913-075', field='servers_code', button='servers_find'):
        app = app or self.page()
        app.text_input(key=field).input(code).run()
        app = self.ok(app.button(key=button).click().run())
        if 'servers_pair_password' not in [t.key for t in app.text_input]:
            return app
        app.text_input(key='servers_pair_password').input('secret').run()
        return self.ok(app.button(key='servers_pair_finish').click().run())

    def test_pairing_by_code_saves_and_connects_after_every_check(self):
        app = self.pair()
        self.assertEqual(self.codes, ['482913075'])
        self.assertEqual(app.session_state[LIVE_TARGET].host, '192.168.1.50')
        self.assertTrue(any('Paired and connected to FIXTURE' in s.value for s in app.success))
        saved = self.registry().get(MACHINE_UUID)
        self.assertEqual((saved.pairing_id, saved.laptop_address, saved.host), ('a' * 32, '192.168.1.23', '192.168.1.50'))
        # The identity probe at login, the identity check before the helper runs, then the helper's pairing list.
        self.assertEqual([c[1] for c in self.session.calls], [None, None, {'Action': 'ListPairings'}])
        rows = app.dataframe[1].value.to_dict('records')
        self.assertEqual([(r['Laptop'], r['This laptop']) for r in rows], [('DESKTOP-KHOO', True), ('STRANGER-PC', False)])
        self.assertNotIn(b'secret', (self.folder / 'preview_imports_servers.sqlite3').read_bytes())

    def test_a_server_without_this_pairing_on_record_is_not_saved(self):
        self.session.pairings = [laptop('b' * 32, '192.168.1.40', 'STRANGER-PC')]
        app = self.pair()
        self.assertTrue(any('pairing_not_confirmed' in e.value for e in app.error))
        self.assertNotIn(LIVE_TARGET, app.session_state)
        self.assertEqual(self.registry().all(), [])
        self.session.pairings = [laptop('a' * 32, '192.168.1.99')]  # Recorded, but for another address.
        app = self.ok(app.button(key='servers_pair_finish').click().run())
        self.assertTrue(any('pairing_not_confirmed' in e.value for e in app.error))

    def test_a_different_machine_behind_the_login_is_not_saved(self):
        self.found = FoundServer('192.168.1.50', 'OTHER', OTHER_UUID, 5985, 'a' * 32, '192.168.1.23')
        app = self.pair()
        self.assertTrue(any('wrong_target' in e.value for e in app.error))
        self.assertEqual(self.registry().all(), [])

    def test_a_mistyped_code_is_explained_without_searching(self):
        app = self.page()
        app.text_input(key='servers_code').input('48291').run()
        app = self.ok(app.button(key='servers_find').click().run())
        self.assertTrue(any('9 digits' in e.value for e in app.error))
        self.assertEqual(self.codes, [])

    def test_repairing_keeps_the_same_machine_and_refuses_another(self):
        self.pair()
        app = self.page()
        self.found = FoundServer('192.168.1.77', 'OTHER', OTHER_UUID, 5985, 'c' * 32, '192.168.1.23')
        app = self.pair(app, field='servers_repair_code', button='servers_repair')
        self.assertTrue(any('A different machine answered' in e.value for e in app.error))
        self.found = FoundServer('192.168.1.77', 'FIXTURE-SERVER', MACHINE_UUID, 5985, 'c' * 32, '192.168.0.105')
        self.session.pairings = [laptop('c' * 32, '192.168.0.105')]
        app = self.pair(app, field='servers_repair_code', button='servers_repair')
        self.assertTrue(any('Re-paired FIXTURE' in s.value.replace('\\', '') for s in app.success))  # Shown escaped.
        saved = self.registry().get(MACHINE_UUID)
        self.assertEqual((saved.host, saved.pairing_id, saved.laptop_address), ('192.168.1.77', 'c' * 32, '192.168.0.105'))
        self.assertEqual(len(self.registry().all()), 1)

    def test_disconnect_another_laptop(self):
        app = self.pair()
        app = self.ok(app.button(key='servers_access_remove').click().run())
        self.assertEqual(self.session.calls[-1][1], {'Action': 'RemovePairing', 'PairingId': 'b' * 32})
        self.assertTrue(any('Disconnected STRANGER' in s.value for s in app.success))
        self.assertIn(LIVE_TARGET, app.session_state)
        self.assertEqual([r['Laptop'] for r in app.dataframe[1].value.to_dict('records')], ['DESKTOP-KHOO'])

    def test_disconnect_this_laptop_needs_confirmation_and_ends_the_session(self):
        app = self.pair()
        app = self.ok(app.button(key='servers_access_self').click().run())
        self.assertEqual(self.session.calls[-1][1], {'Action': 'ListPairings'}, 'Nothing changes before confirming')
        app = self.ok(app.button(key='servers_access_confirm').click().run())
        self.assertEqual(self.session.calls[-1][1], {'Action': 'RemovePairing', 'PairingId': 'a' * 32})
        self.assertNotIn(LIVE_TARGET, app.session_state)
        self.assertTrue(any('This laptop no longer has access' in s.value for s in app.success))

    def test_close_all_access_tells_to_revert_when_the_helper_turned_remoting_on(self):
        self.session.helper_enabled = True
        app = self.pair()
        app = self.ok(app.button(key='servers_access_all').click().run())
        app = self.ok(app.button(key='servers_access_confirm').click().run())
        self.assertEqual(self.session.calls[-1][1], {'Action': 'CloseAccess'})
        self.assertNotIn(LIVE_TARGET, app.session_state)
        self.assertTrue(any('click Revert changes' in s.value for s in app.success))


if __name__ == '__main__':
    unittest.main()
