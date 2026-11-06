"""Client package definition (scripts/packaging/build_client_package.py) and the launcher. Fast checks only: the full
build (about 300 MB, one minute) is run by hand and checks itself, see PROGRESS.md."""
import ast
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_client_package', ROOT / 'scripts' / 'packaging' / 'build_client_package.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class PackageDefinitionTests(unittest.TestCase):
    def test_every_file_the_package_lists_exists(self):
        for name in build.APP_FILES:
            self.assertTrue((build.APP / name).is_file(), name)
        for name in build.SCRIPT_FILES:
            self.assertTrue((ROOT / 'scripts' / name).is_file(), name)

    def test_every_script_the_code_sends_to_a_server_is_shipped(self):
        # The code finds these relative to itself; a missing one would only fail on the client's first scan.
        from hardening.remediation import RUNNER
        from hardening.server_access import FILES
        from hardening.winrm_channel import COLLECTOR
        shipped = {(ROOT / 'scripts' / name).resolve() for name in build.SCRIPT_FILES}
        for path in [COLLECTOR, RUNNER] + [ROOT / 'scripts' / 'server_access' / f for f in FILES]:
            self.assertIn(path.resolve(), shipped)

    def test_start_and_readme_are_plain_text_for_windows(self):
        for text in (build.START_CMD, build.README):
            self.assertTrue(text.isascii())
        self.assertIn('launch.py" %*', build.START_CMD)
        self.assertIn('PYTHONNOUSERSITE=1', build.START_CMD)
        self.assertIn(r'%LOCALAPPDATA%\FYP-Hardening\data', build.START_CMD)

    def test_lab_data_and_tests_are_never_shipped(self):
        listed = ' '.join(build.APP_FILES + build.SCRIPT_FILES)
        for forbidden in ('data/', 'tests/', '.venv', 'docs/', 'evaluation', 'tools/'):
            self.assertNotIn(forbidden, listed)

    def test_the_lock_file_pins_what_requirements_ask_for(self):
        lock = {line.split('==')[0].lower(): line.split('==')[1] for line in
                (build.APP / 'requirements-lock.txt').read_text(encoding='utf-8').splitlines()
                if line and not line.startswith('#')}
        for name in ('streamlit', 'pypsrp'):
            self.assertIn(name, lock)


class LauncherTests(unittest.TestCase):
    def test_the_dashboard_listens_on_this_laptop_only_and_never_prompts(self):
        source = (build.APP / 'launch.py').read_text(encoding='utf-8')
        command = next(node for node in ast.walk(ast.parse(source))
                       if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', '') == 'command')
        values = [n.value for n in ast.walk(command.value) if isinstance(n, ast.Constant)]
        self.assertEqual(values[values.index('--server.address') + 1], '127.0.0.1')
        self.assertEqual(values[values.index('--server.headless') + 1], 'true')
        self.assertEqual(values[values.index('--browser.gatherUsageStats') + 1], 'false')


if __name__ == '__main__':
    unittest.main()
