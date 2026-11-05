import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

class ContractTests(unittest.TestCase):
    def test_endpoint_rejects_urls_injection_and_boolean_port(self):
        self.assertIsNotNone(importlib.util.find_spec('system.contracts'))
        from system.contracts import Endpoint
        self.assertEqual(Endpoint('192.168.56.10',22).method,'auto')
        for host,port in [('http://example.com',22),('host\r\nAuthorization: secret',22),('host',True),('host',0),('host',65536),('host/path',22)]:
            with self.subTest(host=host,port=port),self.assertRaises(ValueError):Endpoint(host,port)

    def test_summary_never_counts_unknown_as_pass_and_checks_total(self):
        self.assertIsNotNone(importlib.util.find_spec('system.contracts'))
        from system.contracts import AssessmentSummary, RecordRef
        ref=RecordRef('ubuntu','ubuntu:fixture','run')
        summary=AssessmentSummary.from_counts(ref,30,0,0,29,1,'catalogue','2026-11-05T00:00:00+00:00')
        self.assertIsNone(summary.compliance_percent)
        self.assertEqual(summary.coverage_percent,0)
        with self.assertRaises(ValueError):AssessmentSummary.from_counts(ref,30,30,1,0,0,'catalogue','2026-11-05T00:00:00+00:00')
        with self.assertRaises(ValueError):RecordRef('windows','ubuntu:fixture','run')

    def test_serializer_rejects_unknown_fields_and_nonfinite(self):
        self.assertIsNotNone(importlib.util.find_spec('system.contracts'))
        from system.contracts import Endpoint, decode_record, encode_record
        item=Endpoint('vm.example',2222,'ssh')
        self.assertEqual(decode_record(Endpoint,encode_record(item)),item)
        for raw in ['{"host":"vm","host":"other","port":22}', '{"host":"vm","port":22,"password":"secret"}', '{"host":"vm","port":NaN}']:
            with self.assertRaises(ValueError):decode_record(Endpoint,raw)

    def test_isolated_paths_ignore_legacy_live_environment(self):
        self.assertIsNotNone(importlib.util.find_spec('system.config'))
        from system.config import IntegrationPaths
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'CIS_DASHBOARD_DB':'C:/live/production.sqlite3'}):
            app=Path(folder)
            paths=IntegrationPaths.for_app(app)
            self.assertEqual(paths.windows_imports,app/'data'/'windows'/'integration_imports.sqlite3')
            self.assertNotIn('production',str(paths.windows_imports))
            self.assertNotEqual(paths.windows_imports,paths.ubuntu_imports)
