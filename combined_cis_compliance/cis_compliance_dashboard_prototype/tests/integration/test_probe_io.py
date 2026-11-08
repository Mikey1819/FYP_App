import unittest
from unittest.mock import patch


class FixedProbeIoTests(unittest.TestCase):
    def test_unregistered_command_and_file_are_refused_before_io(self):
        from vm.ubuntu.collector import FixedProbeIO
        io = FixedProbeIO(deadline_seconds=5)
        with patch('subprocess.Popen', side_effect=AssertionError('Must not spawn')):
            for key in ('apt upgrade','shell','sysctl -w kernel.randomize_va_space=0'):
                with self.assertRaises(ValueError):io.command(key)
        for path in ('/home/user/.ssh/id_rsa','/etc/../etc/shadow','/proc/self/environ'):
            with self.assertRaises(ValueError):io.read_file(path)

    def test_collection_requires_linux_ubuntu_identity_before_probes(self):
        from vm.ubuntu.collector import preflight
        from types import SimpleNamespace
        class FakeIO:
            def __init__(self): self.reads = []
            def read_file(self,path):
                self.reads.append(path)
                return {'/etc/os-release':'ID=ubuntu\nVERSION_ID="22.04"\n',
                        '/etc/machine-id':'a'*32+'\n','/proc/sys/kernel/hostname':'fixture\n'}[path]
        io = FakeIO()
        request = dict(hostname='fixture',machine_id='b'*32)
        with patch('platform.system',return_value='Linux'),patch('os.geteuid',return_value=0,create=True):
            with self.assertRaises(ValueError):preflight(io,request)
        self.assertNotIn('/etc/shadow',io.reads)
        request['machine_id'] = 'a'*32
        with patch('platform.system',return_value='Windows'):
            with self.assertRaises(ValueError):preflight(io,request)

    def test_fixed_registry_contains_only_read_operations(self):
        from vm.ubuntu.collector import COMMANDS
        self.assertGreater(len(COMMANDS),10)
        for argv in COMMANDS.values():
            self.assertIsInstance(argv,tuple)
            self.assertTrue(argv[0].startswith('/'))
            for forbidden in ('--remediate','--load','--now','install','remove','update','-w','enable','restart'):
                self.assertNotIn(forbidden,argv)
