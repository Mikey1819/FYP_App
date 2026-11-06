"""Deterministic read-only SCAP invocation plan from verified content; no execution here."""
from dataclasses import dataclass
from pathlib import Path
import re
from defusedxml import ElementTree as ET
from .catalogue import load_catalogue, read_json, NS


@dataclass(frozen=True)
class ScapPlan:
    argv: tuple[str, ...]
    rule_ids: tuple[str, ...]
    known_rule_ids: tuple[str, ...]
    profile_id: str
    datastream_sha256: str
    engine_version: str
    result_path: str
    live_eligible: bool


def prepare_scan(catalogues, request_id, *, engine_version, fixture=False):
    if not re.fullmatch('[0-9a-f]{32}',request_id):raise ValueError('Invalid scan request identifier')
    if not re.fullmatch(r'\d+\.\d+\.\d+',engine_version):raise ValueError('Invalid OpenSCAP version')
    root=Path(catalogues)
    catalogue=load_catalogue(root/'ubuntu2204.json',root/'source-lock.json',require_activation=not fixture)
    lock=read_json(root/'source-lock.json')
    if not fixture and engine_version != lock['openscap_version']:
        raise ValueError('OpenSCAP executable version differs from accepted source lock')
    raw=read_json(root/'ubuntu2204.json')
    xml=ET.fromstring((root/lock['datastream_path']).read_bytes(),forbid_dtd=True,forbid_entities=True,forbid_external=True)
    profiles={p.get('id'):p for p in xml.findall('.//x:Profile',NS)}
    profile=lock['profile_id'];chain=[];seen=set()
    while profile:
        if profile in seen or profile not in profiles:raise ValueError('Invalid SCAP profile inheritance')
        seen.add(profile);chain.append(profiles[profile]);profile=profiles[profile].get('extends')
    selectors={}
    for p in reversed(chain):
        selectors.update({row.get('idref'):row.get('selector') for row in p.findall('x:refine-value',NS)})
    for control in raw['controls']:
        for key,setting in control['scap_variable_values'].items():
            if selectors.get(key) != setting['selector']:
                raise ValueError('Selected profile variable differs from the pinned mapping')
    rule_ids=tuple(sorted({r for c in catalogue.controls for r in c.scap_rule_ids}))
    known=tuple(sorted(r.get('id') for r in xml.findall('.//x:Rule',NS)))
    result='/var/lib/fyp-hardening/scans/'+request_id+'/xccdf.xml'
    args=['/usr/bin/oscap','xccdf','eval','--profile',lock['profile_id'],'--results',result]
    for rule in rule_ids:args.extend(('--rule',rule))
    args.append('/usr/local/share/fyp-hardening/ssg-ubuntu2204-ds.xml')
    return ScapPlan(tuple(args),rule_ids,known,lock['profile_id'],lock['datastream_sha256'],engine_version,
                    result,catalogue.activation_ready and not fixture)
