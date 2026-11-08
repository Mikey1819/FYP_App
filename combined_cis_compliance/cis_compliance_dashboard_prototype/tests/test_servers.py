"""Saved servers: the registry (Windows Server 2022 and Ubuntu 22.04), the identity probe used at login, and the
Servers page with saved servers. Fake remoting sessions only; no server is contacted."""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest

from hardening import winrm_channel
from hardening.connection_view import LIVE_TARGET
from hardening.servers import ServerRegistry
from hardening.winrm_channel import ChannelError, WinRmLogin, probe_identity
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from system.connection import ConnectionService
from system.ledger import CoordinationLedger
from test_winrm_channel import IDENTITY, MACHINE_UUID, FakeSession

OTHER_UUID = '11111111-2222-3333-4444-555555555555'
MACHINE_ID = '0123456789abcdef0123456789abcdef'


def login(**overrides):
    values = dict(username='Administrator', password='secret', host='192.168.1.50', port=5985)
    values.update(overrides)
    return WinRmLogin(**values)


def windows(registry, host='192.168.1.50', note='', identity=IDENTITY):
    return registry.add('windows', identity['machine_uuid'], identity['hostname'], identity['os_caption'], host, 5985,
                        'Administrator', note=note)


class ProbeIdentityTests(unittest.TestCase):
    def test_probe_reads_who_answers_without_knowing_it_first(self):
        session = FakeSession()
        found = probe_identity(login(), session_factory=session)
        self.assertEqual((found['hostname'], found['machine_uuid']), ('FIXTURE-SERVER', MACHINE_UUID))
        self.assertEqual(len(session.calls), 1, 'Adding a server runs the identity probe only')
        self.assertEqual(session.target.host, '192.168.1.50')

    def test_unsupported_systems_are_refused_with_a_plain_reason(self):
        for change in ({'os_caption': 'Microsoft Windows Server 2019 Standard', 'build_number': '17763'},
                       {'part_of_domain': True, 'domain_role': 3},
                       {'os_caption': 'Microsoft Windows 11 Pro', 'build_number': '26200', 'domain_role': 0}):
            with self.assertRaises(ChannelError) as caught:
                probe_identity(login(), session_factory=FakeSession(identity={**IDENTITY, **change}))
            self.assertEqual(caught.exception.state, 'unsupported_target')
            self.assertIn('stand-alone Windows Server 2022 only', caught.exception.detail)

    def test_filtered_token_and_malformed_answers_are_refused(self):
        with self.assertRaises(ChannelError) as caught:
            probe_identity(login(), session_factory=FakeSession(identity={**IDENTITY, 'is_admin': False}))
        self.assertEqual(caught.exception.state, 'not_admin')
        for bad in ({**IDENTITY, 'machine_uuid': 'not-a-uuid'}, {**IDENTITY, 'hostname': 7},
                    {k: v for k, v in IDENTITY.items() if k != 'domain_role'}):
            with self.assertRaises(ChannelError) as caught:
                probe_identity(login(), session_factory=FakeSession(identity=bad))
            self.assertEqual(caught.exception.state, 'channel_error')

    def test_network_failures_are_classified_and_the_password_never_shown(self):
        with self.assertRaises(ChannelError) as caught:
            probe_identity(login(), session_factory=FakeSession(fail=ConnectionError('Connection refused')))
        self.assertEqual(caught.exception.state, 'unreachable')
        self.assertNotIn('secret', repr(login()))

    def test_login_needs_address_account_and_password(self):
        for bad in (dict(host=' '), dict(password=''), dict(username=''), dict(port=0), dict(port='5985')):
            with self.assertRaises(ValueError):
                login(**bad)


class ServerRegistryTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.path = Path(folder.name) / 'servers.sqlite3'
        self.registry = ServerRegistry(self.path)

    def test_add_and_list_both_systems(self):
        server, new = windows(self.registry, note='Finance server')
        self.assertTrue(new)
        self.assertEqual((server.key, server.transport, server.system_label),
                         ('windows:' + MACHINE_UUID, 'winrm', 'Windows Server 2022'))
        ubuntu, _ = self.registry.add('ubuntu', MACHINE_ID, 'ubuntu-web01', 'Ubuntu 22.04.5 LTS', '192.168.56.20', 22,
                                      'fyp-admin', auth='key', key_path=r'C:\keys\fyp_ed25519')
        self.assertEqual((ubuntu.key, ubuntu.transport, ubuntu.auth), ('ubuntu:' + MACHINE_ID, 'ssh', 'key'))
        self.assertEqual(sorted(s.hostname for s in self.registry.all()), ['FIXTURE-SERVER', 'ubuntu-web01'])

    def test_the_same_machine_added_again_keeps_its_note_and_gets_the_new_address(self):
        windows(self.registry, note='Finance server')
        server, new = windows(self.registry, host='192.168.1.77')
        self.assertFalse(new)
        self.assertEqual((server.host, server.note), ('192.168.1.77', 'Finance server'))
        self.assertEqual(len(self.registry.all()), 1)

    def test_identity_is_the_key_whatever_its_letter_case(self):
        windows(self.registry, identity={**IDENTITY, 'machine_uuid': MACHINE_UUID.upper()})
        self.assertIsNotNone(self.registry.get('windows', MACHINE_UUID))

    def test_most_recently_used_first_and_removal(self):
        windows(self.registry, host='10.0.0.5')
        windows(self.registry, host='10.0.0.6', identity={**IDENTITY, 'hostname': 'OTHER', 'machine_uuid': OTHER_UUID})
        self.registry.connected('windows', MACHINE_UUID)
        self.assertEqual([s.hostname for s in self.registry.all()], ['FIXTURE-SERVER', 'OTHER'])
        self.registry.remove('windows', MACHINE_UUID)
        self.assertEqual([s.hostname for s in self.registry.all()], ['OTHER'])
        with self.assertRaises(KeyError):
            self.registry.connected('windows', MACHINE_UUID)

    def test_notes_are_checked_and_no_password_is_stored(self):
        windows(self.registry)
        self.registry.set_note('windows', MACHINE_UUID, '  Room 3  ')
        self.assertEqual(self.registry.get('windows', MACHINE_UUID).note, 'Room 3')
        for bad in ('x' * 121, 'line\nbreak'):
            with self.assertRaises(ValueError):
                self.registry.set_note('windows', MACHINE_UUID, bad)
        self.assertNotIn(b'secret', self.path.read_bytes())

    def test_bad_values_are_refused(self):
        for platform, identity, host, port, auth, key in (
                ('windows', 'x', '10.0.0.5', 5985, 'password', ''), ('windows', MACHINE_UUID, '', 5985, 'password', ''),
                ('windows', MACHINE_UUID, '10.0.0.5', 70000, 'password', ''),
                ('windows', MACHINE_UUID, '10.0.0.5', 5985, 'key', r'C:\key'),  # Windows logs in by password only.
                ('ubuntu', MACHINE_ID.upper(), '10.0.0.5', 22, 'password', ''),  # machine-id is lower case.
                ('ubuntu', MACHINE_ID, '10.0.0.5', 22, 'key', ''),  # A key login names the key file.
                ('solaris', MACHINE_ID, '10.0.0.5', 22, 'password', '')):
            with self.assertRaises(ValueError, msg=(platform, identity, host, port, auth)):
                self.registry.add(platform, identity, 'HOST', 'System', host, port, 'admin', auth=auth, key_path=key)

    def test_an_unknown_database_layout_is_refused_not_reset(self):
        other = self.path.with_name('other.sqlite3')
        with closing(sqlite3.connect(other)) as db:  # closing(): Windows keeps an open file locked.
            db.execute('CREATE TABLE something (x)')
        with self.assertRaises(ValueError):
            ServerRegistry(other)


def servers_page():
    from pathlib import Path
    import streamlit as st
    from hardening.servers_view import render_servers
    render_servers(Path(st.session_state['fixture_servers']))


class ServersPageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.session = FakeSession()
        self.service = ConnectionService(CoordinationLedger(self.folder / 'integration.sqlite3'),
                                         backend_factory=lambda session: object())
        patcher = patch.object(winrm_channel, 'PsrpSession', self.session)
        patcher.start(); self.addCleanup(patcher.stop)

    def page(self):
        app = AppTest.from_function(servers_page, default_timeout=30)
        app.session_state[SERVICE_KEY] = self.service
        app.session_state['fixture_servers'] = str(self.folder / 'servers.sqlite3')
        return app.run()

    def ok(self, app):
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        return app

    def saved(self, note=''):
        """A server paired on an earlier day (pairing itself is tested in test_pairing_flow.py)."""
        registry = ServerRegistry(self.folder / 'servers.sqlite3')
        windows(registry, note=note)
        registry.paired('windows', MACHINE_UUID, 'a' * 32, '192.168.1.23')

    def connect(self, app=None):
        app = app or self.ok(self.page())
        app.text_input(key='servers_password').input('secret').run()  # The button turns on after a re-render.
        return self.ok(app.button(key='servers_connect').click().run())

    def test_servers_are_added_only_by_pairing_code(self):
        app = self.ok(self.page())
        self.assertTrue(any('No saved servers yet' in i.value for i in app.info))
        keys = [t.key for t in app.text_input]
        self.assertEqual(keys, ['servers_code'], 'No address, port or password box: only the pairing code')
        self.assertEqual(len(app.tabs), 0)
        self.assertTrue(app.button(key='servers_find').disabled, 'Needs a code first')
        self.assertEqual([b.label for b in app.get('download_button')],
                         ['Download helper (.zip)', 'Download pairing helper (.py)'])

    def test_connect_to_a_saved_server(self):
        self.saved(note='Finance server')
        app = self.connect()
        target = app.session_state[LIVE_TARGET]
        self.assertEqual((target.hostname, target.machine_uuid, target.host), ('FIXTURE-SERVER', MACHINE_UUID, '192.168.1.50'))
        self.assertTrue(any('Connected to FIXTURE' in s.value.replace('\\', '') for s in app.success))
        rows = app.dataframe[0].value.to_dict('records')
        self.assertEqual([(r['Server'], r['Address'], r['Note'], r['Connected now']) for r in rows],
                         [('FIXTURE-SERVER', '192.168.1.50:5985', 'Finance server', True)])
        self.assertNotIn(b'secret', (self.folder / 'servers.sqlite3').read_bytes())

    def test_reconnect_to_a_saved_server_checks_its_identity(self):
        self.saved()
        app = self.ok(self.page())  # Saved, but not connected.
        self.assertNotIn(LIVE_TARGET, app.session_state)
        # Another machine at the saved address is refused, with what to do about it.
        self.session.identity = {**IDENTITY, 'hostname': 'OTHER', 'machine_uuid': OTHER_UUID}
        app = self.connect(app)
        self.assertNotIn(CONNECTION_KEY, app.session_state)
        self.assertTrue(any('(verification_failed)' in e.value and 'Re-pair below' in e.value.replace('\\', '')
                            for e in app.error), [e.value for e in app.error])  # The hint is shown escaped.

    def test_unreachable_saved_server_says_what_probably_happened(self):
        self.saved()
        self.session.fail = ConnectionError('Connection refused')
        app = self.connect()
        self.assertTrue(any('address may have changed' in e.value for e in app.error), [e.value for e in app.error])

    def test_remove_needs_confirmation_and_disconnects_that_server(self):
        self.saved()
        app = self.connect()
        app = self.ok(app.button(key='servers_remove').click().run())
        self.assertIn(CONNECTION_KEY, app.session_state)  # Not yet: a second click confirms.
        app = self.ok(app.button(key='servers_remove_confirm').click().run())
        self.assertNotIn(CONNECTION_KEY, app.session_state)
        self.assertTrue(any('No saved servers yet' in i.value for i in app.info))

    def test_disconnect_only_ends_the_session(self):
        self.saved()
        app = self.connect()
        calls = len(self.session.calls)
        app = self.ok(app.button(key='servers_disconnect').click().run())
        self.assertNotIn(LIVE_TARGET, app.session_state)
        self.assertEqual(len(self.session.calls), calls, 'Disconnect sends nothing to the server')
        self.assertEqual(len(app.dataframe[0].value), 1, 'The server stays saved')

    def test_a_saved_ubuntu_server_shows_its_own_bundle_command(self):
        registry = ServerRegistry(self.folder / 'servers.sqlite3')
        registry.add('ubuntu', MACHINE_ID, 'ubuntu-web01', 'Ubuntu 22.04.5 LTS', '192.168.56.20', 22, 'fyp-admin')
        app = self.ok(self.page())
        self.assertIn(f'--machine-id {MACHINE_ID} --hostname ubuntu-web01 --user fyp-admin', app.code[0].value)


if __name__ == '__main__':
    unittest.main()
