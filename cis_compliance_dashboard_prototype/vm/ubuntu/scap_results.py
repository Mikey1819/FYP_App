"""Target-side selected-rule OpenSCAP invocation and result sanitization. Python 3.10, standard library only.

The argument vector is built only from the digest-pinned helper constants, the hash-pinned tailoring file and
a validated request ID:
evaluation only, no remediation, no remote resources, no extra reports. Sanitization keeps one result
token per selected rule and discards messages, values, system characteristics and all other text.
"""
import re
import xml.etree.ElementTree as ET
from .spec import SCAP_RESULTS, SCAP_RULE_PREFIX, SCAP_RULES, SCAP_TAILORED_PROFILE

OSCAP = '/usr/bin/oscap'
DATASTREAM = '/usr/local/share/fyp-hardening/ssg-ubuntu2204-ds.xml'
TAILORING = '/usr/local/share/fyp-hardening/fyp-selected-tailoring.xml'
RESULT_ROOT = '/var/lib/fyp-hardening/scans'
RESULT_LIMIT = 100*1024*1024
SELECTED = tuple(sorted({rule for rules in SCAP_RULES.values() for rule in rules}))
_XCCDF = '{http://checklists.nist.gov/xccdf/1.2}'


def result_path(request_id):
    if type(request_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', request_id):
        raise ValueError('Invalid scan request identifier')
    return RESULT_ROOT + '/' + request_id + '/xccdf.xml'


def scan_argv(request_id):
    # No --rule options: OpenSCAP 1.2.17 keeps only the last one. The pinned tailoring selects exactly SELECTED.
    return (OSCAP, 'xccdf', 'eval', '--tailoring-file', TAILORING, '--profile', SCAP_TAILORED_PROFILE,
            '--results', result_path(request_id), DATASTREAM)


def engine_version(output):
    """Version from `oscap --version`; anything unexpected is refused, not guessed."""
    first = output.splitlines()[0] if output else ''
    match = re.fullmatch(r'OpenSCAP command line tool \(oscap\) (\d+\.\d+\.\d+)', first.strip())
    if not match:
        raise ValueError('Unrecognised OpenSCAP version output')
    return match.group(1)


def sanitize_results(raw, *, rule_ids, profile_id, expected_target):
    if type(raw) is not bytes or len(raw) > RESULT_LIMIT:
        raise ValueError('SCAP result size limit')
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise ValueError('SCAP results must be UTF-8') from None
    # The standard parser is only used on documents with no DTD at all: no entities can be declared.
    if '\x00' in text or '<!DOCTYPE' in text or '<!ENTITY' in text:
        raise ValueError('SCAP results with DTD or entity declarations are refused')
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, RecursionError, ValueError):
        raise ValueError('Malformed SCAP results') from None
    results = [root] if root.tag == _XCCDF + 'TestResult' else root.findall('.//' + _XCCDF + 'TestResult')
    if len(results) != 1:
        raise ValueError('Exactly one SCAP test result required')
    result = results[0]
    profiles, targets = result.findall(_XCCDF + 'profile'), result.findall(_XCCDF + 'target')
    if (len(profiles) != 1 or profiles[0].get('idref') != profile_id or len(targets) != 1
            or (targets[0].text or '').strip().casefold() != expected_target.casefold()):
        raise ValueError('SCAP target or profile mismatch')
    selected, seen, found = set(rule_ids), set(), {}
    if len(selected) != len(rule_ids):
        raise ValueError('Duplicate selected SCAP rule')
    for row in result.findall(_XCCDF + 'rule-result'):
        key, values = row.get('idref'), row.findall(_XCCDF + 'result')
        if (type(key) is not str or not key.startswith(SCAP_RULE_PREFIX) or key in seen
                or len(values) != 1 or values[0].text not in SCAP_RESULTS):
            raise ValueError('Unexpected or duplicate SCAP rule result')
        seen.add(key)
        if key not in selected:
            if values[0].text != 'notselected':
                raise ValueError('SCAP evaluated a rule outside the selected scope')
            continue
        found[key] = values[0].text
    # A missing selected result stays unresolved; it never defaults to pass.
    return {key: found.get(key, 'notchecked') for key in rule_ids}
