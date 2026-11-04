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

    def test_helper_opens_only_one_address_and_never_weakens_winrm(self):
        text = (SCRIPTS / FILES[0]).read_text(encoding='utf-8')
        self.assertIn('-RemoteAddress $Address', text)
        for widening in ('-RemoteAddress Any', 'AllowUnencrypted -Value', 'Auth\\Basic -Value', 'TrustedHosts'):
            self.assertNotIn(widening, text)


if __name__ == '__main__':
    unittest.main()
