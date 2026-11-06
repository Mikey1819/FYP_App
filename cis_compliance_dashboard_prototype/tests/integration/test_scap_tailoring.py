"""Selected-rule scope via an XCCDF tailoring file, because OpenSCAP 1.2.17 honours only one --rule option.

Evidence (user-run on FYP-Ubuntu2204, 2026-11-06): 53 --rule options gave exit 0 with 1 notapplicable and 622
notselected results, i.e. only the last rule was evaluated.
"""
import hashlib
from pathlib import Path
import unittest
from defusedxml import ElementTree as ET

APP = Path(__file__).resolve().parents[2]
X = '{http://checklists.nist.gov/xccdf/1.2}'


class TailoringTests(unittest.TestCase):
    def test_generated_tailoring_is_pinned_deterministic_and_selects_exactly_our_rules(self):
        from backends.ubuntu.scap_tailoring import build_tailoring, datastream_rules
        from vm.ubuntu.scap_results import SELECTED
        from vm.ubuntu.spec import SCAP_PROFILE, SCAP_TAILORED_PROFILE, SCAP_TAILORING_SHA256
        raw = build_tailoring()
        self.assertEqual(raw, build_tailoring())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), SCAP_TAILORING_SHA256)
        root = ET.fromstring(raw)
        [profile] = root.findall(X + 'Profile')
        self.assertEqual((profile.get('id'), profile.get('extends')), (SCAP_TAILORED_PROFILE, SCAP_PROFILE))
        selects = {s.get('idref'): s.get('selected') for s in profile.findall(X + 'select')}
        rules = datastream_rules()
        self.assertEqual(len(rules), 623)
        self.assertEqual(set(selects), set(rules))
        self.assertEqual({r for r, v in selects.items() if v == 'true'}, set(SELECTED))
        self.assertEqual(len(selects) - len(SELECTED), 623 - 53)
        self.assertNotIn(b'remediat', raw.lower())

    def test_scan_argv_uses_the_tailoring_file_and_no_rule_options(self):
        from vm.ubuntu.scap_results import scan_argv, DATASTREAM, RESULT_ROOT, TAILORING
        from vm.ubuntu.spec import SCAP_TAILORED_PROFILE
        self.assertEqual(scan_argv('a' * 32), ('/usr/bin/oscap', 'xccdf', 'eval', '--tailoring-file', TAILORING,
                                               '--profile', SCAP_TAILORED_PROFILE, '--results',
                                               RESULT_ROOT + '/' + 'a' * 32 + '/xccdf.xml', DATASTREAM))

    def test_bundle_ships_the_pinned_tailoring_and_installs_it(self):
        import shutil, tempfile
        from tools.build_ubuntu_bundle import build
        from backends.ubuntu.scap_tailoring import build_tailoring
        folder = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, folder)
        out = build(Path(folder) / 'bundle')
        self.assertEqual((out / 'share' / 'fyp-selected-tailoring.xml').read_bytes(), build_tailoring())
        self.assertIn('share/fyp-selected-tailoring.xml', (out / 'install.sh').read_text())


class FirewallRegistrationTests(unittest.TestCase):
    def test_reviewed_ufw_registration_applies_only_to_the_registered_machine(self):
        from system.connection import _backend
        from system.connection import VerifiedSession
        from system.identity import VerifiedIdentity
        from system.ledger import CoordinationLedger
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            ledger = CoordinationLedger(Path(folder) / 'ledger.sqlite3')
            def backend(machine):
                session = VerifiedSession('c', VerifiedIdentity('ubuntu', 'FYP-Ubuntu2204', machine, '22.04', 'ssh'),
                                          'ubuntu:x', 'epoch', 'vboxuser', '192.168.56.10', 22, None)
                return _backend(session, ledger)
            self.assertEqual(backend('f1d16ae7e6bc4d2488f9410fcd858e36').registered_firewall_manager, 'ufw')
            self.assertIsNone(backend('a' * 32).registered_firewall_manager)
