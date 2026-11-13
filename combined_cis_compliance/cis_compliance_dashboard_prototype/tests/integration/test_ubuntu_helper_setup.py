"""Task 9: one file on the server sets it up, then shows the pairing code (administrator, 12 November 2026).

`sudo python3 fyp-pair-ubuntu.py` now carries the setup files (collector, runner, SCAP content, sudo rules, boot rollback
unit and the install scripts) as a hash-pinned embedded payload. Before pairing it fills them for this machine and the
account that ran sudo, removes older FYP tools, installs OpenSCAP if needed and installs the tools, after one console
prompt. Same version installed: skipped. A change still open on the server: setup skipped, pairing goes on. OpenSCAP
missing and no route to the package mirror: it stops, nothing changed, and says to add the NAT adapter.

Fakes only: a temporary folder stands in for the server's file system; no command runs, nothing is installed.
"""
import base64
import contextlib
import hashlib
import io
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as N
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'server_access' / 'fyp-pair-ubuntu.py'
spec = importlib.util.spec_from_file_location('fyp_pair_ubuntu_setup', SCRIPT)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

VALUES = {'machine_id': '0123456789abcdef0123456789abcdef', 'hostname': 'FYP-Ubuntu2204', 'user': 'kai'}


def tree(folder):
    return {p.relative_to(folder).as_posix(): p.read_bytes() for p in sorted(Path(folder).rglob('*')) if p.is_file()}


class PayloadTests(unittest.TestCase):
    def test_the_embedded_payload_is_built_from_the_current_code(self):
        """The laptop's deployment check compares the installed helper with this application's vm/ubuntu files, so a
        helper whose payload is older than the code would install tools the dashboard then refuses."""
        from tools.build_ubuntu_helper import payload
        data = payload()
        self.assertEqual(hashlib.sha256(data).hexdigest(), helper.PAYLOAD_SHA256,
                         'Rebuild the helper: python -B -m tools.build_ubuntu_helper')
        self.assertEqual(base64.b64decode(''.join(helper.PAYLOAD)), data)

    def test_filled_on_the_server_it_equals_the_bundle_built_for_that_server(self):
        from tools.build_ubuntu_bundle import build
        with tempfile.TemporaryDirectory() as here, tempfile.TemporaryDirectory() as there:
            helper.extract_payload(Path(here) / 'b')
            helper.fill_bundle(Path(here) / 'b', VALUES)
            build(Path(there) / 'b', **VALUES)
            self.assertEqual(tree(Path(here) / 'b'), tree(Path(there) / 'b'))

    def test_a_changed_payload_is_refused_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(helper, 'PAYLOAD', (helper.PAYLOAD[0][:-4] + 'AAAA',) + tuple(helper.PAYLOAD[1:])):
            with self.assertRaisesRegex(helper.HelperError, 'damaged'):
                helper.extract_payload(Path(folder) / 'b')
            self.assertFalse((Path(folder) / 'b').exists())


class LocalValuesTests(unittest.TestCase):
    def values(self, env, machine='0123456789abcdef0123456789abcdef\n', host='FYP-Ubuntu2204'):
        return helper.local_values(read=lambda path: machine, hostname=lambda: host, env=env)

    def test_this_machine_and_the_account_that_ran_sudo(self):
        self.assertEqual(self.values({'SUDO_USER': 'kai'}), VALUES)

    def test_root_itself_or_no_sudo_account_is_refused(self):
        for env in ({}, {'SUDO_USER': 'root'}, {'SUDO_USER': 'bad user'}):
            with self.subTest(env=env), self.assertRaisesRegex(helper.HelperError, 'sudo'):
                self.values(env)


class InstalledStateTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root, self.bundle = Path(folder.name) / 'root', Path(folder.name) / 'bundle'
        helper.extract_payload(self.bundle)
        helper.fill_bundle(self.bundle, VALUES)

    def install_copy(self, *, user='kai', change=None):
        """What install.sh and install-runner.sh leave, under the fake root."""
        lib, share = self.root / 'usr/local/libexec/fyp-hardening', self.root / 'usr/local/share/fyp-hardening'
        (lib / 'fyp_ubuntu').mkdir(parents=True)
        share.mkdir(parents=True)
        for p in (self.bundle / 'libexec/fyp_ubuntu').iterdir():
            (lib / 'fyp_ubuntu' / p.name).write_bytes(p.read_bytes())
        for name in ('collect', 'runner'):
            (lib / name).write_bytes((self.bundle / 'libexec' / name).read_bytes())
        for p in (self.bundle / 'share').iterdir():
            (share / p.name).write_bytes(p.read_bytes())
        sudoers = self.root / 'etc/sudoers.d'
        sudoers.mkdir(parents=True)
        for name in ('fyp-hardening', 'fyp-hardening-runner'):
            (sudoers / name).write_bytes((self.bundle / 'sudoers' / name).read_bytes().replace(b'kai', user.encode()))
        unit = self.root / 'etc/systemd/system'
        (unit / 'multi-user.target.wants').mkdir(parents=True)
        (unit / 'fyp-hardening-boot-rollback.service').write_bytes(
            (self.bundle / 'systemd/fyp-hardening-boot-rollback.service').read_bytes())
        (unit / 'multi-user.target.wants' / 'fyp-hardening-boot-rollback.service').write_text('enabled')
        if change:
            (self.root / 'var/lib/fyp-hardening/runner').mkdir(parents=True)
            (self.root / 'var/lib/fyp-hardening/runner/active').write_text(change)

    def state(self):
        return helper.installed_state(self.bundle, root=self.root)

    def test_nothing_installed(self):
        self.assertEqual(self.state(), 'absent')

    def test_the_same_version_for_the_same_account_is_current(self):
        self.install_copy()
        self.assertEqual(self.state(), 'current')

    def test_an_older_file_another_account_or_a_missing_part_is_outdated(self):
        self.install_copy()
        (self.root / 'usr/local/libexec/fyp-hardening/fyp_ubuntu/runner.py').write_bytes(b'# older runner\n')
        self.assertEqual(self.state(), 'outdated')
        for change in ('user', 'unit'):
            with self.subTest(change=change):
                import shutil
                shutil.rmtree(self.root)
                self.install_copy(user='other' if change == 'user' else 'kai')
                if change == 'unit':
                    (self.root / 'etc/systemd/system/multi-user.target.wants/fyp-hardening-boot-rollback.service').unlink()
                self.assertEqual(self.state(), 'outdated')

    def test_an_open_change_is_seen(self):
        self.assertFalse(helper.change_open(root=self.root))
        self.install_copy(change='f' * 32)
        self.assertTrue(helper.change_open(root=self.root))


class PlanTests(unittest.TestCase):
    def plan(self, state='absent', oscap=True, change=False, internet=True):
        return helper.setup_plan(state, oscap=oscap, change_open=change, internet=internet)

    def test_nothing_installed_installs_both_stages(self):
        self.assertEqual(self.plan()['steps'], ['install.sh', 'install-runner.sh'])
        self.assertEqual(self.plan(oscap=False)['steps'], ['openscap', 'install.sh', 'install-runner.sh'])

    def test_older_tools_are_removed_first(self):
        self.assertEqual(self.plan('outdated')['steps'],
                         ['uninstall-runner.sh', 'uninstall.sh', 'install.sh', 'install-runner.sh'])

    def test_the_same_version_is_skipped(self):
        plan = self.plan('current')
        self.assertEqual((plan['action'], plan['steps']), ('up_to_date', []))
        self.assertEqual(self.plan('current', oscap=False)['steps'], ['openscap'])

    def test_an_open_change_skips_setup_but_pairing_goes_on(self):
        plan = self.plan('outdated', change=True)
        self.assertEqual((plan['action'], plan['steps']), ('skip', []))
        self.assertIn('settle', plan['message'])

    def test_no_openscap_and_no_package_mirror_stops_with_the_nat_advice(self):
        plan = self.plan(oscap=False, internet=False)
        self.assertEqual((plan['action'], plan['steps']), ('stop', []))
        self.assertIn('NAT', plan['message'])
        self.assertEqual(self.plan(oscap=True, internet=False)['action'], 'install')  # OpenSCAP there: no internet needed


class SetupFlowTests(unittest.TestCase):
    def run_setup(self, *, answer='', state='absent', change=False, oscap=True, internet=True, fail=None,
                  env=None):
        commands, printed = [], []

        def run(command, **kwargs):
            commands.append(command if command[0] != 'bash' else ['bash', Path(command[1]).name])
            return N(returncode=1 if fail and fail in ' '.join(map(str, command)) else 0)
        with mock.patch.object(helper, 'installed_state', return_value=state), \
                mock.patch.object(helper, 'change_open', return_value=change), \
                mock.patch.object(helper, 'oscap_installed', return_value=oscap), \
                mock.patch.object(helper, 'can_reach_mirror', return_value=internet), \
                mock.patch.object(helper, 'local_values', return_value=VALUES):
            go_on = helper.prepare(ask=lambda prompt: printed.append(prompt) or answer, run=run,
                                   out=lambda *a: printed.append(' '.join(map(str, a))))
        return go_on, commands, ' '.join(printed)

    def test_one_prompt_then_old_tools_out_openscap_and_both_stages_in(self):
        go_on, commands, text = self.run_setup(state='outdated', oscap=False)
        self.assertTrue(go_on)
        self.assertEqual(commands, [['bash', 'uninstall-runner.sh'], ['bash', 'uninstall.sh'], ['apt-get', 'update'],
                                    ['apt-get', 'install', '-y', 'libopenscap8'], ['bash', 'install.sh'],
                                    ['bash', 'install-runner.sh']])
        self.assertEqual(text.count('[Y/n]'), 1)
        self.assertIn('kai', text)  # the account the sudo rules are for

    def test_no_means_pairing_only_and_nothing_runs(self):
        go_on, commands, text = self.run_setup(answer='n')
        self.assertEqual((go_on, commands), (True, []))

    def test_up_to_date_asks_nothing(self):
        go_on, commands, text = self.run_setup(state='current')
        self.assertEqual((go_on, commands), (True, []))
        self.assertNotIn('[Y/n]', text)
        self.assertIn('up to date', text)

    def test_a_failed_step_stops_before_pairing(self):
        go_on, commands, text = self.run_setup(fail='install.sh')
        self.assertFalse(go_on)
        self.assertEqual(commands[-1], ['bash', 'install.sh'])  # install-runner.sh never ran
        self.assertIn('install.sh failed', text)

    def test_no_internet_without_openscap_stops_and_changes_nothing(self):
        go_on, commands, text = self.run_setup(oscap=False, internet=False)
        self.assertEqual((go_on, commands), (False, []))
        self.assertIn('NAT', text)

    def test_an_open_change_pairs_without_setup(self):
        go_on, commands, text = self.run_setup(state='outdated', change=True)
        self.assertEqual((go_on, commands), (True, []))


class MainOrderTests(unittest.TestCase):
    def test_setup_comes_before_the_pairing_code_and_can_be_skipped(self):
        order = []

        def pair(**kwargs):  # never waits for a laptop: pairing stops at once
            order.append('pair')
            raise helper.HelperError('TEST-ONLY stop')
        with mock.patch.object(helper.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(helper, 'prepare', side_effect=lambda **k: order.append('setup') or False), \
                mock.patch.object(helper, 'server_facts', side_effect=pair):
            self.assertEqual(helper.main([]), 1)  # setup stopped: no code is shown
        self.assertEqual(order, ['setup'])
        order.clear()
        with mock.patch.object(helper.os, 'geteuid', return_value=0, create=True), \
                mock.patch.object(helper, 'prepare', side_effect=lambda **k: order.append('setup') or True), \
                mock.patch.object(helper, 'server_facts', side_effect=helper.HelperError('TEST-ONLY stop')), \
                contextlib.redirect_stdout(io.StringIO()):
            helper.main(['--pair-only'])
        self.assertEqual(order, [])  # --pair-only skips setup


if __name__ == '__main__':
    unittest.main()
