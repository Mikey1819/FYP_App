"""The VM-side second-reading script must stay read-only and run on Ubuntu 22.04's Python 3.10 (the administrator runs
it with sudo). Static checks over its source; nothing is executed on any VM."""
import ast
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[3] / 'scripts' / 'vm' / 'ubuntu_cross_check_values.py'
READ_ONLY_TOOLS = {'apt-cache', 'systemctl', 'sshd', 'chage', 'auditctl', 'apt', 'dpkg'}
READ_ONLY_ARGS = {'systemctl': {'is-enabled', 'is-active'}, 'sshd': {'-T'}, 'chage': {'-l'}, 'auditctl': {'-l'},
                  'apt': {'list'}, 'dpkg': {'--get-selections'}, 'apt-cache': {'policy'}}
# ('replace' is left out: the script uses str.replace to build /proc/sys paths; Path.replace would rename.)
WRITING_NAMES = {'write_text', 'write_bytes', 'unlink', 'rmdir', 'mkdir', 'chmod', 'chown', 'rename',
                 'remove', 'makedirs', 'rmtree', 'touch', 'symlink_to', 'system', 'popen'}


class CrossCheckScriptTests(unittest.TestCase):
    def tree(self):
        return ast.parse(SCRIPT.read_text(encoding='utf-8'), feature_version=(3, 10))

    def test_parses_as_python_3_10(self):
        self.tree()

    def test_every_command_is_a_fixed_read_only_tool_and_action(self):
        calls = [n for n in ast.walk(self.tree()) if isinstance(n, ast.Call) and getattr(n.func, 'id', None) == 'run']
        self.assertTrue(calls)
        for call in calls:
            # Tool and action are fixed literals; a final argument may name a package, unit or account.
            words = [a.value for a in call.args[:2] if isinstance(a, ast.Constant)]
            self.assertEqual(len(words), 2, 'the tool and its action must be fixed literals')
            self.assertLessEqual(len(call.args), 4)
            self.assertIn(words[0], READ_ONLY_TOOLS)
            self.assertIn(words[1], READ_ONLY_ARGS[words[0]])

    def test_nothing_writes_deletes_or_starts_a_shell(self):
        tree = self.tree()
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | \
                {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        self.assertEqual(names & WRITING_NAMES, set())
        opens = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, 'id', None) == 'open']
        self.assertEqual(opens, [])
        self.assertNotIn('shell=True', SCRIPT.read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
