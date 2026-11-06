"""Sanitize XCCDF results; discard system characteristics, text and raw artifacts."""
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

NS = {'x':'http://checklists.nist.gov/xccdf/1.2'}
RESULTS = frozenset(('pass','fail','error','unknown','notapplicable','notchecked','notselected','informational','fixed'))


def parse_results(raw, *, expected_target, expected_profile, rule_ids, known_rule_ids=None):
    if type(raw) is not bytes or len(raw) > 100*1024*1024:
        raise ValueError('SCAP artifact exceeds limit')
    try:
        root = ET.fromstring(raw,forbid_dtd=True,forbid_entities=True,forbid_external=True)
        results = root.findall('.//x:TestResult',NS)
        if root.tag == '{'+NS['x']+'}TestResult': results = [root]
        if len(results) != 1:
            raise ValueError('Exactly one bounded SCAP result required')
        result = results[0]
        profiles, targets = result.findall('x:profile',NS),result.findall('x:target',NS)
        if len(profiles) != 1 or profiles[0].get('idref') != expected_profile or len(targets) != 1 or targets[0].text != expected_target:
            raise ValueError('SCAP target or profile mismatch')
        allowed, found = set(rule_ids), {}
        known=set(known_rule_ids) if known_rule_ids is not None else allowed
        seen=set()
        if not allowed <= known:raise ValueError('Selected rule absent from pinned content')
        if len(allowed) != len(rule_ids):
            raise ValueError('Duplicate selected SCAP rule')
        for row in result.findall('x:rule-result',NS):
            key = row.get('idref')
            values = row.findall('x:result',NS)
            if key not in known or key in seen or len(values) != 1 or values[0].text not in RESULTS:
                raise ValueError('Unexpected or duplicate SCAP rule result')
            seen.add(key)
            if key not in allowed:
                if values[0].text != 'notselected':raise ValueError('SCAP evaluated a rule outside the selected scope')
                continue
            found[key] = values[0].text
        # A missing result remains unresolved; it never defaults to pass.
        return {key:found.get(key,'notchecked') for key in rule_ids}
    except (ET.ParseError,DefusedXmlException,UnicodeError,RecursionError):
        raise ValueError('Unsafe or malformed SCAP XML') from None
