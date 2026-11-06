"""Bounded, fail-closed loading of the pinned Ubuntu control inventory."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

EXPECTED_IDS = frozenset('1.2.2.1 1.3.1.1 1.5.1 1.5.3 1.5.4 2.1.2 5.3.3.2.2 5.4.1.1 5.4.1.3 5.4.1.5 5.2.2 5.2.3 3.3.1 3.3.2 3.3.8 4.1.3 4.1.4 4.1.7 6.3.1.1 6.3.1.2 6.3.1.3 6.3.3.4 6.3.3.8 6.3.3.6 5.1.20 5.1.19 5.1.16 5.1.7 5.1.10 5.1.21'.split())
NS = {'x': 'http://checklists.nist.gov/xccdf/1.2'}


@dataclass(frozen=True)
class Control:
    control_id: str
    title: str
    area: str
    server_level: int
    cis_assessment_type: str
    source_pages: tuple[int, ...]
    predicate_id: str
    assessment_contract: str
    scap_rule_ids: tuple[str, ...]
    direct_probe_reason: str
    action_ids: tuple[str, ...]


@dataclass(frozen=True)
class Catalogue:
    version: str
    controls: tuple[Control, ...]
    benchmark_sha256: str
    content_sha256: str
    activation_ready: bool


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def read_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1_000_000:
        raise ValueError('Manifest exceeds limit')
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite manifest value')))


def _local(base, relative):
    path = (base / relative).resolve()
    if not path.is_relative_to(base.resolve()):
        raise ValueError('Source path escapes catalogue directory')
    return path


def validate_catalogue(raw, lock, stream):
    try:
        return _validate(raw, lock, stream)
    except (KeyError, TypeError, AttributeError, ET.ParseError, DefusedXmlException) as exc:
        raise ValueError('Malformed catalogue, source lock or datastream') from exc


def _validate(raw, lock, stream):
    if raw['schema_version'] != 1 or lock['schema_version'] != 1:
        raise ValueError('Unsupported source schema')
    if len(stream) > 32_000_000 or hashlib.sha256(stream).hexdigest() != lock['datastream_sha256']:
        raise ValueError('Datastream hash mismatch or size limit')
    if not re.fullmatch('[0-9a-f]{40}', lock['content_commit']) or not re.fullmatch('[0-9a-f]{64}', lock['benchmark_sha256']):
        raise ValueError('Invalid source provenance')
    tree = ET.fromstring(stream, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    rules = {r.get('id') for r in tree.findall('.//x:Rule', NS)}
    profiles = {p.get('id') for p in tree.findall('.//x:Profile', NS)}
    values = {v.get('id'): {s.get('selector'): s.text for s in v.findall('x:value', NS)}
              for v in tree.findall('.//x:Value', NS)}
    if lock['profile_id'] not in profiles:
        raise ValueError('Source profile absent from pinned datastream')
    rows = raw['controls']
    if len(rows) != 30 or {c['control_id'] for c in rows} != EXPECTED_IDS:
        raise ValueError('Catalogue must contain the exact 30 distinct selected controls')
    if sorted(Counter(c['area'] for c in rows).values()) != [6]*5:
        raise ValueError('Catalogue must contain five areas of six controls')
    if Counter(c['server_level'] for c in rows) != {1:24, 2:6}:
        raise ValueError('Catalogue must contain 24 L1 and six L2 controls')
    if Counter(c['cis_assessment_type'] for c in rows) != {'Automated':29, 'Manual':1}:
        raise ValueError('Catalogue classification changed')
    controls = []
    for c in rows:
        cid = c['control_id']
        if c['platform'] != 'ubuntu' or c['benchmark_sha256'] != lock['benchmark_sha256']:
            raise ValueError('Control source/platform mismatch')
        if c['server_level'] != (2 if cid.startswith('6.3.') else 1) or c['cis_assessment_type'] != ('Manual' if cid == '1.2.2.1' else 'Automated'):
            raise ValueError('Control classification does not match selected PDF recommendation')
        if not c['source_pages'] or any(type(p) is not int or not 1 <= p <= 1064 for p in c['source_pages']):
            raise ValueError('Invalid printed source page')
        if len(set(c['scap_rule_ids'])) != len(c['scap_rule_ids']) or not set(c['scap_rule_ids']) <= rules:
            raise ValueError('Missing or duplicate real datastream rule')
        if not c['direct_probe_reason'] or not c['direct_probe_ids']:
            raise ValueError('Effective-state mapping gaps must be explained')
        for key, setting in c['scap_variable_values'].items():
            if key not in values or values[key].get(setting['selector']) != setting['value']:
                raise ValueError('Unknown or changed SCAP variable selector')
        if c['action_ids'] != ['ubuntu.'+cid+'.v1']:
            raise ValueError('One distinct reserved action family is required per selected control')
        controls.append(Control(cid, c['title'], c['area'], c['server_level'], c['cis_assessment_type'],
            tuple(c['source_pages']), c['predicate_id'], c['assessment_contract'], tuple(c['scap_rule_ids']),
            c['direct_probe_reason'], tuple(c['action_ids'])))
    # An inventory or downloaded content is not an accepted collector/runner implementation.
    ready = (lock['activation_ready'] is True and lock['review_status'] == 'approved'
             and bool(lock['openscap_version']) and all(c['review_status'] == 'approved'
             and c['coverage']['assessment'] == 'fixture_tested' for c in rows))
    return Catalogue(raw['catalogue_version'], tuple(controls), lock['benchmark_sha256'], lock['datastream_sha256'], ready)


def load_catalogue(path, source_lock, *, require_activation=False):
    path, source_lock = Path(path), Path(source_lock)
    raw, lock = read_json(path), read_json(source_lock)
    base = source_lock.parent
    mapping = _local(base, lock['mapping_source_path']).read_bytes()
    if hashlib.sha256(mapping).hexdigest() != lock['mapping_source_sha256']:
        raise ValueError('Upstream mapping source hash mismatch')
    validate_mapping(raw,mapping.decode('utf-8'))
    stream = _local(base, lock['datastream_path']).read_bytes()
    catalogue = validate_catalogue(raw, lock, stream)
    if require_activation and not catalogue.activation_ready:
        raise ValueError('Ubuntu catalogue activation requires reviewed sources, engine and assessment acceptance')
    return catalogue


def validate_mapping(raw, source):
    """Verify associations against the pinned upstream control list, not just rule existence."""
    for control in raw['controls']:
        match = re.search(r'^    - id: '+re.escape(control['control_id'])+r'\n(.*?)(?=^    - id: |\Z)',
                          source,re.S|re.M)
        if not match:raise ValueError('Control absent from upstream mapping')
        block = match.group(1)
        rules_block = block.split('      rules:\n',1)[-1] if '      rules:\n' in block else ''
        rule_names, selectors = [], {}
        for entry in re.findall(r'^          - (.+)$',rules_block,re.M):
            if '=' in entry:
                name,selector=entry.split('=',1);selectors[name]=selector
            else:rule_names.append(entry)
        actual = [value.removeprefix('xccdf_org.ssgproject.content_rule_') for value in control['scap_rule_ids']]
        actual_selectors = {key.removeprefix('xccdf_org.ssgproject.content_value_'):value['selector']
                            for key,value in control['scap_variable_values'].items()}
        if actual != rule_names or actual_selectors != selectors:
            raise ValueError('Control mapping differs from pinned upstream associations')
