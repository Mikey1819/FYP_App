import hashlib
import json
from datetime import datetime, timezone
import unittest
from tests.integration.ubuntu_fixtures import cases


def envelope():
    return dict(namespace='ubuntu-cis',schema_version=1,collector='ubuntu2204-readonly-v1',
        catalogue='ubuntu2204-cis2-selected30-v1',target_id='ubuntu:fixture',registration_epoch='epoch',
        hostname='UBUNTU-FIXTURE',machine_id='a'*32,request_id='fixture-request',
        benchmark_sha256='b'*64,source_lock_sha256='c'*64,collector_sha256='d'*64,
        started_at='2026-11-06T00:00:00+00:00',completed_at='2026-11-06T00:00:01+00:00',
        evidence_mode='Synthetic fixture',observations=cases(),artifacts=[],
        probes={cid:dict(probe_id='ubuntu.'+cid+'.effective.v1',version=1,source='fixed-target-helper',
            started_at='2026-11-06T00:00:00+00:00',completed_at='2026-11-06T00:00:01+00:00',exit_state='ok') for cid in cases()},
        transformation='allowlisted-normalized-facts-v1')


class UbuntuEvidenceTests(unittest.TestCase):
    def parse(self, document):
        from backends.ubuntu.envelope import parse_bundle, ExpectedEvidence
        expected = ExpectedEvidence('ubuntu:fixture','epoch','UBUNTU-FIXTURE','a'*32,'fixture-request',
                                    'b'*64,'c'*64,'d'*64,'Synthetic fixture')
        raw = document if isinstance(document,bytes) else json.dumps(document).encode()
        return parse_bundle(raw,expected,now=datetime(2026,11,6,0,0,2,tzinfo=timezone.utc))

    def test_canonical_ownership_hash_and_all30_evaluation(self):
        bundle = self.parse(envelope())
        self.assertEqual(bundle.raw_sha256,hashlib.sha256(bundle.raw).hexdigest())
        self.assertEqual(len(bundle.assessments),30)
        self.assertEqual(sum(r.status.value == 'Compliant' for r in bundle.assessments),29)
        self.assertEqual(sum(r.status.value == 'Unknown' for r in bundle.assessments),1)

    def test_wrong_binding_source_request_time_mode_and_unknown_fields_rejected(self):
        for key,value in [('target_id','ubuntu:other'),('registration_epoch','other'),('machine_id','e'*32),
            ('request_id','replayed-request'),('source_lock_sha256','f'*64),('collector_sha256','f'*64),
            ('evidence_mode','Live (SSH)'),('schema_version',True),('password','SECRET-SENTINEL'),
            ('completed_at','2026-11-05T00:00:00+00:00'),('started_at','2026-11-07T00:00:00+00:00')]:
            with self.subTest(key=key):
                doc = envelope();doc[key] = value
                with self.assertRaises(ValueError) as caught:self.parse(doc)
                self.assertNotIn('SECRET-SENTINEL',str(caught.exception))

    def test_duplicate_json_nonfinite_truncation_and_oversize_rejected(self):
        for raw in (b'{"schema_version":1,"schema_version":1}', b'{"value":NaN}', b'{', b' '* (10*1024*1024+1)):
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):self.parse(raw)

    def test_missing_control_cannot_silently_reduce_selected_count(self):
        doc = envelope();doc['observations'].pop('1.5.1')
        with self.assertRaises(ValueError):self.parse(doc)

    def test_scap_strips_system_characteristics_and_refuses_entities_and_duplicate_results(self):
        from backends.ubuntu.scap import parse_results
        prefix = 'xccdf_org.ssgproject.content_rule_'
        rule = prefix+'package_apparmor_installed'
        xml = ('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult id="r">'
               '<target>ubuntu-fixture</target><profile idref="profile"/>'
               '<rule-result idref="'+rule+'"><result>pass</result><message>SECRET-SENTINEL</message></rule-result>'
               '<set-value idref="secret">SECRET-SENTINEL</set-value></TestResult></Benchmark>').encode()
        result = parse_results(xml,expected_target='ubuntu-fixture',expected_profile='profile',rule_ids=(rule,))
        self.assertEqual(result[rule],'pass')
        self.assertNotIn('SECRET-SENTINEL',repr(result))
        for malformed in (b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/shadow">]><x>&e;</x>',
                          xml.replace(b'</TestResult>', ('<rule-result idref="'+rule+'"><result>pass</result></rule-result></TestResult>').encode())):
            with self.assertRaises(ValueError):parse_results(malformed,expected_target='ubuntu-fixture',expected_profile='profile',rule_ids=(rule,))
        with self.assertRaises(ValueError):parse_results(xml,expected_target='wrong',expected_profile='profile',rule_ids=(rule,))
