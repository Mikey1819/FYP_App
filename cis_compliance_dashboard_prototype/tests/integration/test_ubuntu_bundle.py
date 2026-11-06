"""The VM provisioning bundle is exact, hash-checked and limited to the previewed changes. Nothing is run here."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

APP = Path(__file__).resolve().parents[2]


class BundleTests(unittest.TestCase):
    def build(self):
        from tools.build_ubuntu_bundle import build
        folder = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, folder)
        return build(Path(folder) / 'bundle')

    def test_bundle_holds_exact_helper_bytes_datastream_and_correct_sums(self):
        from vm.ubuntu.provenance import HELPER_FILES, collector_digest
        out = self.build()
        for name in HELPER_FILES:  # the package directory holds every digest-pinned file, launchers included
            self.assertEqual((out / 'libexec' / 'fyp_ubuntu' / name).read_bytes(), (APP / 'vm' / 'ubuntu' / name).read_bytes(), name)
        for launcher in ('collect', 'runner'):  # executable copies, byte-identical to the pinned ones
            self.assertEqual((out / 'libexec' / launcher).read_bytes(), (APP / 'vm' / 'ubuntu' / launcher).read_bytes())
        self.assertEqual(collector_digest(out / 'libexec' / 'fyp_ubuntu'), collector_digest())
        ds = (out / 'share' / 'ssg-ubuntu2204-ds.xml').read_bytes()
        self.assertEqual(hashlib.sha256(ds).hexdigest(), 'c8be1aa2bf93284507b8810ea829f8904ab4552865f07d106561d5fd5d06ca67')
        for line in (out / 'SHA256SUMS').read_text().splitlines():
            digest, path = line.split('  ', 1)
            self.assertEqual(hashlib.sha256((out / path).read_bytes()).hexdigest(), digest, path)
        # Only the approved read-only collector; the runner's write path waits for execution acceptance.
        self.assertEqual((out / 'sudoers' / 'fyp-hardening').read_text(),
                         'vboxuser ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/collect ""\n')

    def test_install_script_is_bounded_to_the_preview(self):
        out = self.build()
        script = (out / 'install.sh').read_text()
        for required in ('f1d16ae7e6bc4d2488f9410fcd858e36', 'FYP-Ubuntu2204', 'sha256sum -c SHA256SUMS',
                         'visudo -cf', 'install -o root -g root -m 0440', 'cmp -s', '/var/lib/fyp-hardening/scans',
                         '/var/lib/fyp-hardening/runner', 'Python 3.10'):
            self.assertIn(required, script)
        for forbidden in ('apt ', 'apt-get', 'dpkg -i', 'systemctl', 'ufw ', 'sshd', 'pam', 'reboot', 'curl', 'wget'):
            self.assertNotIn(forbidden, script.lower() if forbidden != 'pam' else script)
        uninstall = (out / 'uninstall.sh').read_text()
        self.assertLess(uninstall.index('/etc/sudoers.d/fyp-hardening'), uninstall.index('rm -rf /usr/local/libexec/fyp-hardening'))
        for path in (out / 'install.sh', out / 'uninstall.sh'):
            self.assertNotIn(b'\r', path.read_bytes())
            bash = shutil.which('bash')
            if bash:
                self.assertEqual(subprocess.run([bash, '-n', str(path)], capture_output=True).returncode, 0, path.name)
