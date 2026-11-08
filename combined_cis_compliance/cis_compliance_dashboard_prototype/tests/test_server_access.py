"""Server access helper bundle offered on the connection form. Reads repository files only; no server."""
import hashlib
from io import BytesIO
import unittest
import zipfile

from hardening.server_access import FILES, SCRIPTS, helper_bundle, helper_sha256


class ServerAccessBundleTests(unittest.TestCase):
    def test_bundle_holds_the_helper_launcher_and_readme_unchanged(self):
        with zipfile.ZipFile(BytesIO(helper_bundle())) as bundle:
            self.assertEqual(tuple(bundle.namelist()), FILES)
            for name in FILES:
                self.assertEqual(bundle.read(name), (SCRIPTS / name).read_bytes())

    def test_published_hash_is_the_helper_inside_the_bundle(self):
        with zipfile.ZipFile(BytesIO(helper_bundle())) as bundle:
            self.assertEqual(hashlib.sha256(bundle.read(FILES[0])).hexdigest(), helper_sha256())

    def test_bundle_is_identical_on_every_build(self):
        self.assertEqual(helper_bundle(), helper_bundle())

    def test_helper_opens_winrm_only_to_paired_laptops_and_never_weakens_it(self):
        text = (SCRIPTS / FILES[0]).read_text(encoding='utf-8')
        # The WinRM rule lists only paired laptops' addresses; only the temporary pairing rule uses the local subnet.
        self.assertIn('-Protocol TCP -LocalPort $WinRmPort -RemoteAddress $Addresses', text)
        self.assertIn('-Protocol UDP -LocalPort $PairingPort `\n            -RemoteAddress LocalSubnet', text)
        self.assertEqual(text.count('LocalSubnet'), 1)
        for widening in ('-RemoteAddress Any', 'AllowUnencrypted -Value', 'Auth\\Basic -Value', 'TrustedHosts'):
            self.assertNotIn(widening, text)

    def test_helper_files_are_plain_ascii(self):
        # Windows PowerShell 5.1 reads a script without a byte-order mark in the local code page.
        for name in FILES:
            self.assertTrue((SCRIPTS / name).read_bytes().isascii(), name)


if __name__ == '__main__':
    unittest.main()
