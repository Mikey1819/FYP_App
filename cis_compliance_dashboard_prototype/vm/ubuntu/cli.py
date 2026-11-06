"""Target helper entry point: one bounded JSON request on stdin, exact envelope bytes on stdout.

Run only through the fixed root-owned launcher. Nothing but the envelope is written to stdout,
and every failure writes one fixed line to stderr: no exception text, paths or values are echoed.
"""
import json
import re
import sys
from .collector import FixedProbeIO, preflight as target_preflight
from .provenance import run_collection, validate_request

LIMIT = 64*1024
FIELDS = frozenset(('request', 'scap_engine_version', 'registered_firewall_manager'))
REFUSED = b'fyp-hardening: collection refused\n'


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate request field')
        result[key] = value
    return result


def _parse(raw):
    if len(raw) > LIMIT:
        raise ValueError('Request size limit')
    doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite request value')))
    if type(doc) is not dict or set(doc) != FIELDS:
        raise ValueError('Unexpected request fields')
    engine, manager = doc['scap_engine_version'], doc['registered_firewall_manager']
    if engine is not None and (type(engine) is not str or not re.fullmatch(r'\d+\.\d+\.\d+', engine)):
        raise ValueError('Invalid OpenSCAP version')
    if manager not in (None, 'ufw'):
        raise ValueError('Unsupported firewall manager registration')
    return validate_request(doc['request']), engine, manager


def main(stdin=None, stdout=None, stderr=None, *, io_factory=None, preflight=None, clock=None):
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    stderr = stderr or sys.stderr.buffer
    try:
        request, engine, manager = _parse(stdin.read(LIMIT + 1))
        target = (io_factory or (lambda: FixedProbeIO(deadline_seconds=540)))()
        (preflight or target_preflight)(target, request)
        envelope = run_collection(target, request, clock=clock, registered_firewall_manager=manager,
                                  scap_engine_version=engine)
    except Exception:
        stderr.write(REFUSED)
        stderr.flush()
        return 2
    stdout.write(envelope)
    stdout.flush()
    return 0
