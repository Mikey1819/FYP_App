import importlib.util
import unittest

class IdentityTests(unittest.TestCase):
    def test_os_release_is_data_not_shell_and_duplicates_rejected(self):
        self.assertIsNotNone(importlib.util.find_spec('system.identity'))
        from system.identity import parse_os_release, verify_ubuntu
        text='ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu $(touch /tmp/no)"\n'
        facts=parse_os_release(text)
        self.assertEqual(facts['PRETTY_NAME'],'Ubuntu $(touch /tmp/no)')
        self.assertEqual(verify_ubuntu(text,'FYP-Ubuntu2204','a'*32,'fyp-ubuntu2204','a'*32).platform,'ubuntu')
        for invalid in [text+'ID=debian\n','ID=ubuntu\nVERSION_ID="24.04"', 'ID=debian\nVERSION_ID="22.04"']:
            with self.assertRaises(ValueError):verify_ubuntu(invalid,'vm','a'*32,'vm','a'*32)
        with self.assertRaises(ValueError):verify_ubuntu(text,'vm','a'*32,'other','a'*32)
        with self.assertRaises(ValueError):verify_ubuntu(text,'vm','a'*32,'vm','b'*32)

    def test_host_key_change_requires_reenrolment_and_no_tofu(self):
        self.assertIsNotNone(importlib.util.find_spec('system.identity'))
        from system.identity import verify_fingerprint
        fp='SHA256:'+'a'*43
        with self.assertRaises(ValueError):verify_fingerprint(fp,None,None)
        verify_fingerprint(fp,None,fp)
        with self.assertRaises(ValueError):verify_fingerprint(fp,'SHA256:'+'b'*43,fp)

    def test_credentials_are_opaque_and_destroyed_on_disconnect(self):
        self.assertIsNotNone(importlib.util.find_spec('system.session'))
        from system.session import CredentialVault, Credentials
        vault=CredentialVault(); value=Credentials('user','SECRET')
        self.assertNotIn('SECRET',repr(value))
        ref=vault.put(value); self.assertEqual(vault.take(ref).password,'SECRET')
        with self.assertRaises(ValueError):vault.take(ref)
        ref=vault.put(value);vault.clear()
        with self.assertRaises(ValueError):vault.take(ref)
