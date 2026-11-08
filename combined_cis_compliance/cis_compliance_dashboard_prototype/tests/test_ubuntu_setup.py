"""One-step Ubuntu setup: the bundle's setup.sh, the SFTP copy into the account's home, the read-only setup status and
the Servers page's "Set up this server". Fake SSH/SFTP only; nothing is installed and no server is contacted."""
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

from streamlit.testing.v1 import AppTest

from backends.ubuntu.adapter import UbuntuBackend
from backends.ubuntu.ssh_channel import SETUP_FOLDER, SshChannel
from system.bootstrap import CONNECTION_KEY, SERVICE_KEY
from system.connection import ConnectionService
from system.ledger import CoordinationLedger
from tools.build_ubuntu_bundle import build
from tests.integration.pairing_fixture import paired_connect

MACHINE_ID = '033fd4e5b3884e9f973c2aa3ca2d65c4'
SERVER = dict(machine_id=MACHINE_ID, hostname='Ubuntu', user='vboxuser')


class FakeSftp:
    """Just enough of paramiko's SFTPClient: an in-memory home folder."""

    def __init__(self, existing=None):
        self.files, self.dirs, self.modes = dict(existing or {}), {'/home/vboxuser'}, {}
        for path in self.files:  # Every folder above each file exists.
            while path.count('/') > 2:
                path = path.rsplit('/', 1)[0]
                self.dirs.add(path)
        self.closed = False

    def normalize(self, path):
        return '/home/vboxuser'

    def lstat(self, path):
        if path in self.dirs:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700)
        if path in self.files:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        raise FileNotFoundError(path)

    def mkdir(self, path, mode):
        assert path.rsplit('/', 1)[0] in self.dirs and path not in self.dirs, path
        self.dirs.add(path)

    def listdir_attr(self, folder):
        names = {p[len(folder) + 1:].split('/')[0] for p in set(self.files) | self.dirs if p.startswith(folder + '/')}
        return [SimpleNamespace(filename=n, st_mode=self.lstat(folder + '/' + n).st_mode) for n in sorted(names)]

    def remove(self, path):
        del self.files[path]

    def rmdir(self, path):
        assert not any(p.startswith(path + '/') for p in set(self.files) | self.dirs)
        self.dirs.remove(path)

    def putfo(self, stream, path):
        assert path.rsplit('/', 1)[0] in self.dirs, path
        self.files[path] = stream.read()

    def chmod(self, path, mode):
        self.modes[path] = mode

    def close(self):
        self.closed = True


class SetupBundleTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, folder)
        self.bundle = build(Path(folder) / 'ubuntu-helper', **SERVER)

    def test_setup_script_is_for_this_server_asks_first_and_reuses_the_checked_scripts(self):
        text = (self.bundle / 'setup.sh').read_bytes()
        self.assertNotIn(b'\r', text)
        script = text.decode('ascii')
        for required in (f'[ "$(cat /etc/machine-id)" = "{MACHINE_ID}" ]', '[ "$(hostname)" = "Ubuntu" ]',
                         'read -r -p "Continue? [y/N] "', 'apt-get install -y libopenscap8', 'bash install.sh',
                         'bash install-runner.sh', 'already set up'):
            self.assertIn(required, script)
        self.assertNotIn('@', script.replace('@HOSTNAME', '').replace('@USER', ''))
        self.assertNotIn('setup.sh', (self.bundle / 'SHA256SUMS').read_text())  # Scripts are not in the sums.
        bash = shutil.which('bash')
        if bash:
            self.assertEqual(subprocess.run([bash, '-n', str(self.bundle / 'setup.sh')], capture_output=True).returncode, 0)

    def test_the_bundle_is_copied_into_one_emptied_folder_in_the_home(self):
        old = '/home/vboxuser/' + SETUP_FOLDER
        sftp = FakeSftp({old + '/libexec/fyp_ubuntu/stale.py': b'old', '/home/vboxuser/keep.txt': b'mine'})
        channel = SshChannel(SimpleNamespace(open_sftp_client=lambda: sftp), 'SHA256:' + 'K' * 43)
        self.assertEqual(channel.upload_setup_bundle(self.bundle), old)
        self.assertNotIn(old + '/libexec/fyp_ubuntu/stale.py', sftp.files)  # An old file can never be installed.
        self.assertEqual(sftp.files['/home/vboxuser/keep.txt'], b'mine')    # Nothing outside the folder is touched.
        local = {p.relative_to(self.bundle).as_posix() for p in self.bundle.rglob('*') if p.is_file()}
        self.assertEqual({p[len(old) + 1:] for p in sftp.files if p.startswith(old + '/')}, local)
        self.assertEqual(sftp.files[old + '/setup.sh'], (self.bundle / 'setup.sh').read_bytes())
        self.assertEqual(set(sftp.modes.values()), {0o600})
        self.assertTrue(sftp.closed)

    def test_a_file_where_the_folder_should_be_is_refused(self):
        sftp = FakeSftp({'/home/vboxuser/' + SETUP_FOLDER: b'not a folder'})
        sftp.dirs.discard('/home/vboxuser/' + SETUP_FOLDER)
        channel = SshChannel(SimpleNamespace(open_sftp_client=lambda: sftp), 'SHA256:' + 'K' * 43)
        with self.assertRaisesRegex(ValueError, 'not a folder'):
            channel.upload_setup_bundle(self.bundle)


class CollectorProbeTests(unittest.TestCase):
    def installed(self, answer):
        def read(operation):
            self.assertEqual(operation, 'helper')
            if isinstance(answer, Exception):
                raise answer
            return answer
        return UbuntuBackend._collector_installed(SimpleNamespace(session=SimpleNamespace(channel=SimpleNamespace(read=read))))

    def test_only_a_root_owned_collector_counts_as_installed(self):
        self.assertTrue(self.installed('0 755 regular file\n'))
        self.assertFalse(self.installed('1000 755 regular file\n'))  # Owned by the user: not the approved install.
        self.assertFalse(self.installed(ValueError('Read-only probe unavailable: helper')))
        self.assertIsNone(UbuntuBackend._collector_installed(SimpleNamespace(session=SimpleNamespace(channel=object()))))


def servers_page():
    from pathlib import Path
    import streamlit as st
    from hardening.servers_view import render_servers
    render_servers(Path(st.session_state['fixture_servers']))


class SetupChannel:
    host_key = 'SHA256:' + 'K' * 43

    def __init__(self):
        self.uploaded = []
        self.up = True

    def alive(self):
        return self.up

    def __call__(self, request, credentials, known):
        return self

    def verify_identity(self, request):
        from system.identity import VerifiedIdentity
        return VerifiedIdentity('ubuntu', 'Ubuntu', MACHINE_ID, '22.04', 'ssh', self.host_key)

    def upload_setup_bundle(self, local):
        self.uploaded.append({p.relative_to(local).as_posix(): p.read_bytes() for p in Path(local).rglob('*') if p.is_file()})
        return '/home/vboxuser/' + SETUP_FOLDER

    def close(self):
        pass


class SetupBackend:
    def __init__(self, session, state):
        self.session, self.state, self.refreshes, self.runner = session, state, 0, None

    def capabilities(self, connection_session_id):
        from system.contracts import Capabilities
        return Capabilities()

    def setup_status(self, connection_session_id, *, refresh=False):
        if self.state.get('fail'):
            raise self.state['fail']
        self.refreshes += refresh
        if refresh or self.runner is None:  # Like the real backend: the runner probe is cached per connection.
            self.runner = self.state['runner']
        return {k: v for k, v in dict(self.state, runner=self.runner).items() if k != 'fail'}


class SetupPageTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.state = dict(openscap=False, collector=False, runner=False)
        self.channel = SetupChannel()
        self.backends = []

        def backend(session):
            self.backends.append(SetupBackend(session, self.state))
            return self.backends[-1]
        self.service = ConnectionService(CoordinationLedger(self.folder / 'integration.sqlite3'),
                                         ssh_factory=self.channel, backend_factory=backend)

    def page(self):
        app = AppTest.from_function(servers_page, default_timeout=60)
        app.session_state[SERVICE_KEY] = self.service
        app.session_state['fixture_servers'] = str(self.folder / 'servers.sqlite3')
        app.run()
        self.assertEqual(paired_connect(app, platform='ubuntu', hostname='Ubuntu', identity=MACHINE_ID,
                                        username='vboxuser').state, 'connected')
        return self.ok(app)

    def ok(self, app):
        self.assertEqual(len(app.exception), 0, [e.value for e in app.exception])
        self.assertFalse(list(app.error), [e.value for e in app.error])
        return app

    def test_set_up_copies_files_built_for_this_server_and_shows_one_command(self):
        app = self.page()
        self.assertIn('Set up Ubuntu', [h.value for h in app.subheader])
        self.assertEqual(sum('Missing' in m.value for m in app.markdown), 1)  # One status block listing the three.
        app = self.ok(app.button(key='servers_setup').click().run())
        files = self.channel.uploaded[0]
        self.assertIn(f'"{MACHINE_ID}"'.encode(), files['setup.sh'])
        self.assertIn(b'vboxuser ALL=(root) NOPASSWD', files['sudoers/fyp-hardening'])
        self.assertEqual(app.code[0].value, f'sudo bash /home/vboxuser/{SETUP_FOLDER}/setup.sh')
        # After the administrator ran it on the server: Check again reads the status afresh.
        self.state.update(openscap=True, collector=True, runner=True)
        app = self.ok(app.button(key='servers_setup_check').click().run())
        self.assertEqual(self.backends[-1].refreshes, 1)
        self.assertTrue(any('This server is set up' in s.value for s in app.success))
        self.assertNotIn('servers_setup', [b.key for b in app.button])

    def test_a_connection_that_stopped_answering_is_explained_not_a_crash(self):
        import paramiko
        app = self.page()
        self.state['fail'] = paramiko.SSHException('Timeout opening channel.')  # As seen live after a VM restart.
        app = self.ok(app.run())
        self.assertTrue(any('stopped answering' in w.value for w in app.warning), [w.value for w in app.warning])

    def test_a_closed_connection_is_disconnected_and_explained(self):
        app = self.page()
        self.channel.up = False  # The server restarted: SSH keepalives closed the connection.
        app = self.ok(app.run())
        self.assertNotIn(CONNECTION_KEY, app.session_state)
        self.assertTrue(any('was lost' in w.value for w in app.warning), [w.value for w in app.warning])
        self.assertEqual(app.title[0].value, 'Servers')

    def test_nothing_is_offered_for_a_server_that_is_already_set_up(self):
        self.state.update(openscap=True, collector=True, runner=True)
        app = self.page()
        self.assertTrue(any('Execution acceptance' in s.value for s in app.success))
        self.assertEqual(self.channel.uploaded, [])


if __name__ == '__main__':
    unittest.main()
