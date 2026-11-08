"""One fixture collector export for all tests: every one of the 32 controls compliant. Not real VM evidence."""
from datetime import datetime, timezone
import json

from hardening.evidence_import import CONTEXT_SOURCES, load_evidence
from hardening.server2022_catalogue import (BENCHMARK_SHA256, CATALOGUE_ID, COLLECTOR_ID, PROFILE, SCHEMA_VERSION,
                                            SOURCES)

NOW = datetime(2026, 10, 19, 2, tzinfo=timezone.utc)
HOSTNAME = 'FIXTURE-SERVER'
MACHINE_UUID = '2ca18359-73dc-49ef-9dd3-18602c0d9b55'
COLLECTED_AT = '2026-10-19T01:00:15+00:00'

COMPLIANT_VALUES = {
    '1.1.1': 24, '1.1.2': 365, '1.1.3': 1, '1.1.4': 14, '1.1.5': 1, '1.1.7': 0, '1.2.1': 15, '1.2.2': 5, '1.2.4': 15,
    '2.3.1.1': False, '2.3.1.2': 1, '2.3.10.1': 0, '2.3.10.2': 1, '2.3.10.3': 1,
    '9.2.1': 1, '9.2.2': 1, '9.2.6': 1, '9.2.7': 1, '9.3.1': 1, '9.3.2': 1, '9.3.6': 1, '9.3.7': 1,
    '17.1.1': 3, '17.2.2': 1, '17.2.3': 3, '17.5.1': 2, '17.5.4': 3,
    '18.10.57.2.2': 1, '18.10.57.3.9.1': 1, '18.10.57.3.9.3': 2, '18.10.57.3.9.4': 1, '18.10.57.3.9.5': 3,
}
CONTEXT_VALUES = {'firewall_public_enabled': True, 'nla_required': 1, 'nla_policy_source': 0,
                  'firewall_private_enabled': True, 'firewall_private_inbound_blocked': True,
                  'firewall_public_inbound_blocked': True}


def evidence_fixture():
    """A fresh, valid export (the format Collect-Server2022Evidence.ps1 writes)."""
    return {
        'schema_version': SCHEMA_VERSION, 'collector_id': COLLECTOR_ID, 'catalogue_id': CATALOGUE_ID,
        'benchmark_sha256': BENCHMARK_SHA256, 'profile': PROFILE, 'evidence_mode': 'Imported',
        'started_at': '2026-10-19T01:00:00+00:00', 'completed_at': '2026-10-19T01:00:30+00:00',
        'target': {'hostname': HOSTNAME, 'machine_uuid': MACHINE_UUID,
                   'os_caption': 'Microsoft Windows Server 2022 Standard Evaluation',
                   'os_version': '10.0.20348', 'build_number': '20348', 'os_architecture': '64-bit',
                   'product_type': 3, 'part_of_domain': False, 'domain_role': 2},
        'observations': [dict(control_id=key, source=source, state='ok', value=COMPLIANT_VALUES[key], error=None,
                              collected_at=COLLECTED_AT) for key, source in SOURCES.items()],
        'effective_context': [dict(control_id=key, source=source, state='ok', value=CONTEXT_VALUES[key], error=None,
                                   collected_at=COLLECTED_AT) for key, source in CONTEXT_SOURCES.items()],
    }


def observation(data, control_id):
    return next(r for r in data['observations'] if r['control_id'] == control_id)


def result(assessment, control_id):
    return next(r for r in assessment.results if r.control.control_id == control_id)


def load(payload, **kwargs):
    return load_evidence(json.dumps(payload).encode(), expected_hostname=HOSTNAME,
                         expected_machine_uuid=MACHINE_UUID, now=NOW, **kwargs)
