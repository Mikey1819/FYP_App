import json
import stat
import unittest
from unittest.mock import patch
from types import SimpleNamespace


class PrivilegedInventoryTests(unittest.TestCase):
    def test_eligible_mounts_exclude_nodev_noexec_and_nosuid_filesystems(self):
        from vm.ubuntu.inventory import eligible_mounts
        raw=json.dumps({'filesystems':[{'target':'/','fstype':'ext4','options':'rw,relatime'},
            {'target':'/proc','fstype':'proc','options':'rw'}, {'target':'/srv','fstype':'ext4','options':'rw,nosuid'},
            {'target':'/data','fstype':'ext4','options':'rw,noexec'}]})
        self.assertEqual(eligible_mounts(raw,'nodev\tproc\n\text4\n'),('/',))
        with self.assertRaises(ValueError):eligible_mounts('{malformed','ext4')

    def test_bounded_traversal_does_not_follow_symlinks_or_execute_files(self):
        from vm.ubuntu.inventory import discover_privileged
        class Entry:
            def __init__(self,name,mode,device=1):self.name=name;self.path='/'+name;self.mode=mode;self.device=device
            def stat(self,follow_symlinks=False):
                assert follow_symlinks is False
                return SimpleNamespace(st_mode=self.mode,st_dev=self.device)
        class Entries:
            def __enter__(self):return iter([Entry('safe',stat.S_IFREG|0o4755),Entry('normal',stat.S_IFREG|0o755),
                                             Entry('link',stat.S_IFLNK|0o777),Entry('otherfs',stat.S_IFDIR|0o755,2)])
            def __exit__(self,*args):pass
        with (patch('os.stat',return_value=SimpleNamespace(st_dev=1,st_mode=stat.S_IFDIR|0o755)),
             patch('os.open',return_value=3),patch('os.close'),
             patch('os.fstat',return_value=SimpleNamespace(st_dev=1,st_mode=stat.S_IFDIR|0o755)),
             patch('os.scandir',return_value=Entries()),patch('subprocess.Popen',side_effect=AssertionError('Never execute discovered files'))):
            self.assertEqual(discover_privileged(('/',),deadline_seconds=1),('/safe',))
            with self.assertRaises(ValueError):discover_privileged(('/',),deadline_seconds=1,max_entries=1)

    def test_permission_failure_and_deadline_never_return_partial_inventory(self):
        from vm.ubuntu.inventory import discover_privileged
        with (patch('os.stat',return_value=SimpleNamespace(st_dev=1,st_mode=stat.S_IFDIR|0o755)),
             patch('os.open',return_value=3),patch('os.close'),
             patch('os.fstat',return_value=SimpleNamespace(st_dev=1,st_mode=stat.S_IFDIR|0o755)),
             patch('os.scandir',side_effect=PermissionError('not exported'))):
            with self.assertRaises(ValueError):discover_privileged(('/',),deadline_seconds=1)
        with self.assertRaises(ValueError):discover_privileged(('/',),deadline_seconds=0)
