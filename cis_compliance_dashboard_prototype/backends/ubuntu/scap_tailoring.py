"""Deterministic XCCDF tailoring that scopes evaluation to exactly the 53 selected rules.

OpenSCAP 1.2.17 (observed on the target) honours only one `--rule` option, so selection is expressed as a
tailored profile that extends the pinned CIS Level 2 Server profile (keeping its variable refinements),
selects our rules and deselects every other rule in the pinned datastream. The bytes are pinned by
`spec.SCAP_TAILORING_SHA256` and shipped beside the datastream; they contain no remediation content.
"""
import re
from pathlib import Path
from defusedxml import ElementTree as ET
from vm.ubuntu.scap_results import SELECTED
from vm.ubuntu.spec import SCAP_PROFILE, SCAP_TAILORED_PROFILE

APP = Path(__file__).resolve().parents[2]
DATASTREAM = APP / 'catalogues' / 'vendor' / 'ssg-ubuntu2204-ds.xml'
TAILORING_ID = 'xccdf_org.fyphardening_tailoring_cis_selected30'
X = '{http://checklists.nist.gov/xccdf/1.2}'


def datastream_rules(path=DATASTREAM):
    root = ET.fromstring(Path(path).read_bytes(), forbid_dtd=True, forbid_entities=True, forbid_external=True)
    rules = sorted({r.get('id') for r in root.iter(X + 'Rule')})
    if not rules or any(not re.fullmatch(r'xccdf_org\.ssgproject\.content_rule_[A-Za-z0-9_.-]+', r) for r in rules):
        raise ValueError('Unexpected rule identifiers in the pinned datastream')
    return rules


def build_tailoring(path=DATASTREAM):
    rules = datastream_rules(path)
    selected = set(SELECTED)
    if not selected <= set(rules):
        raise ValueError('A selected rule is absent from the pinned datastream')
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f'<xccdf:Tailoring xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" id="{TAILORING_ID}">',
             '  <xccdf:benchmark href="/usr/local/share/fyp-hardening/ssg-ubuntu2204-ds.xml"/>',
             '  <xccdf:version time="2026-11-06T00:00:00">1</xccdf:version>',
             f'  <xccdf:Profile id="{SCAP_TAILORED_PROFILE}" extends="{SCAP_PROFILE}">',
             '    <xccdf:title>CIS Ubuntu 22.04 Level 2 Server: FYP selected 30 controls (evaluation only)</xccdf:title>']
    lines += [f'    <xccdf:select idref="{rule}" selected="{"true" if rule in selected else "false"}"/>' for rule in rules]
    lines += ['  </xccdf:Profile>', '</xccdf:Tailoring>', '']
    return '\n'.join(lines).encode('utf-8')
