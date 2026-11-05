"""Offline provenance checks against pinned upstream content, not VM evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CatalogueTests(unittest.TestCase):
    def test_exact_scope_and_real_one_to_many_mappings(self):
        from backends.ubuntu.catalogue import load_catalogue
        catalogue = load_catalogue(ROOT / 'catalogues/ubuntu2204.json', ROOT / 'catalogues/source-lock.json')
        self.assertEqual(len(catalogue.controls), 30)
        self.assertEqual(sum(c.server_level == 2 for c in catalogue.controls), 6)
        self.assertEqual(sum(c.cis_assessment_type == 'Manual' for c in catalogue.controls), 1)
        apparmor = next(c for c in catalogue.controls if c.control_id == '1.3.1.1')
        self.assertEqual(len(apparmor.scap_rule_ids), 2)
        self.assertFalse(catalogue.activation_ready)

    def test_modified_datastream_missing_rule_and_duplicate_control_refused(self):
        from backends.ubuntu.catalogue import load_catalogue, validate_catalogue
        path = ROOT / 'catalogues'
        raw = json.loads((path / 'ubuntu2204.json').read_text())
        lock = json.loads((path / 'source-lock.json').read_text())
        stream = (path / lock['datastream_path']).read_bytes()
        with self.assertRaises(ValueError):
            validate_catalogue(raw, lock, stream + b'\n')
        bad = copy.deepcopy(raw)
        bad['controls'][1]['scap_rule_ids'] = ['xccdf_org.ssgproject.content_rule_invented']
        with self.assertRaises(ValueError):
            validate_catalogue(bad, lock, stream)
        bad = copy.deepcopy(raw)
        bad['controls'][-1] = bad['controls'][0]
        with self.assertRaises(ValueError):
            validate_catalogue(bad, lock, stream)
        with self.assertRaisesRegex(ValueError, 'activation'):
            load_catalogue(path / 'ubuntu2204.json', path / 'source-lock.json', require_activation=True)

    def test_xml_entity_payload_refused_before_mapping(self):
        from backends.ubuntu.catalogue import validate_catalogue
        import hashlib
        path = ROOT / 'catalogues'
        raw = json.loads((path / 'ubuntu2204.json').read_text())
        lock = json.loads((path / 'source-lock.json').read_text())
        malicious = b'<!DOCTYPE x [<!ENTITY leak SYSTEM "file:///etc/passwd">]><x>&leak;</x>'
        lock['datastream_sha256'] = hashlib.sha256(malicious).hexdigest()
        with self.assertRaises(ValueError):
            validate_catalogue(raw, lock, malicious)
