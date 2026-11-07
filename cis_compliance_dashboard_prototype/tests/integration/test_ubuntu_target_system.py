"""The real target system mixes every family's IO class. Live 2026-11-07 (5.1.20): LinuxAuditIO._put(name, content)
shadowed LinuxSshIO._put(content), so the SSH job raised TypeError before writing and rolled itself back; and
LinuxSshIO.write_managed shadowed the sysctl one, so sysctl fixes would have entered the SSH write path. Family tests
use fakes, so only the real class can show this. No VM is contacted."""
import unittest


class TargetSystemCompositionTests(unittest.TestCase):
    def test_every_io_attribute_is_the_one_the_real_system_uses(self):
        import inspect
        from vm.ubuntu.families import LinuxTargetSystem
        shadowed = []
        for cls in LinuxTargetSystem.__mro__[1:]:
            if cls is object:
                continue
            for name, value in vars(cls).items():  # methods, static methods and constants alike
                if name.startswith('__'):
                    continue
                if inspect.getattr_static(LinuxTargetSystem, name) is not value:
                    shadowed.append('%s.%s' % (cls.__name__, name))
        self.assertEqual(shadowed, [])

    def test_sysctl_and_ssh_writes_resolve_to_their_own_io(self):
        from vm.ubuntu.families import LinuxTargetSystem
        from vm.ubuntu.family_sysctl import LinuxSysctlSystem
        self.assertIs(LinuxTargetSystem.write_managed, LinuxSysctlSystem.write_managed)


    def test_every_system_call_a_family_makes_exists_on_the_real_system(self):
        import re
        from pathlib import Path
        from vm.ubuntu.families import LinuxTargetSystem
        folder = Path(__file__).resolve().parents[2] / 'vm' / 'ubuntu'
        missing = [(f.name, name) for f in sorted(folder.glob('family_*.py'))
                   for name in sorted(set(re.findall(r'self\.system\.([A-Za-z_]\w*)', f.read_text(encoding='utf-8'))))
                   if not hasattr(LinuxTargetSystem, name)]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
