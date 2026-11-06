"""Runner entry point: one header line naming a fixed operation, then the operation's payload, on stdin.

Operations: `preview` (read-only), `execute` (exact approved request bytes follow the header), `reconcile`
(status; never replays) and `confirm` (commit-confirm, over a fresh SSH login). systemd units call the runner
with argv instead: `job <id>`, `rollback <id>` and `boot-rollback` (see supervision.py). Only the result document is written to stdout; any failure writes one fixed stderr line.
"""
import json
from pathlib import Path
import re
import sys
from .families import build
from .runner import Runner
from .remediation_schema import REQUEST_LIMIT, canonical

LIMIT = REQUEST_LIMIT + 4096
STATE = '/var/lib/fyp-hardening/runner'
REFUSED = b'fyp-hardening: runner refused\n'
HEADERS = {'preview': {'op', 'action_id', 'parameters'}, 'execute': {'op'}, 'reconcile': {'op', 'request_id'},
           'confirm': {'op', 'request_id'}}
UNIT_OPS = ('job', 'rollback')  # argv-only, from systemd units; the sudo rule allows the runner no arguments


def _identity():
    from .collector import read_bounded
    with open('/etc/machine-id', 'rb') as handle:
        machine = read_bounded(handle, 4096).decode('ascii').strip()
    with open('/proc/sys/kernel/hostname', 'rb') as handle:  # small chunks: /proc/sys rejects large reads
        hostname = read_bounded(handle, 4096).decode('ascii').strip().casefold()
    return machine, hostname


def _default_runner():
    """Root-owned runner over preflighted fixed target I/O (identity, root, Ubuntu 22.04 checked first)."""
    from .collector import FixedProbeIO, preflight
    from .families import LinuxTargetSystem
    machine, hostname = _identity()
    io = FixedProbeIO(deadline_seconds=300)
    preflight(io, {'machine_id': machine, 'hostname': hostname})
    from .supervision import SystemdLauncher
    return Runner(STATE, build(LinuxTargetSystem(io)), _identity, launcher=SystemdLauncher())


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate header field')
        result[key] = value
    return result


def _unit(argv, environ, runner_factory):
    """systemd unit entry: `job <id>`, `rollback <id>` or `boot-rollback`. sudo resets the environment, so
    INVOCATION_ID (set by systemd for every unit) is absent for anything that came through the sudo rule."""
    if not environ.get('INVOCATION_ID'):
        raise ValueError('Unit operations run only under systemd')
    if argv == ['boot-rollback']:
        runner_factory().boot_rollback()
        return
    if len(argv) != 2 or argv[0] not in UNIT_OPS or not re.fullmatch('[0-9a-f]{32}', argv[1]):
        raise ValueError('Unregistered unit operation')
    runner = runner_factory()
    runner.run_job(argv[1]) if argv[0] == 'job' else runner.rollback(argv[1])


def main(stdin=None, stdout=None, stderr=None, *, runner_factory=None, argv=None, environ=None):
    stdin, stdout, stderr = stdin or sys.stdin.buffer, stdout or sys.stdout.buffer, stderr or sys.stderr.buffer
    if argv:
        try:
            _unit(list(argv), environ if environ is not None else {}, runner_factory or _default_runner)
        except Exception:
            stderr.write(REFUSED)
            stderr.flush()
            return 2
        return 0
    try:
        data = stdin.read(LIMIT + 1)
        if len(data) > LIMIT or b'\n' not in data:
            raise ValueError('Invalid runner input')
        line, payload = data.split(b'\n', 1)
        header = json.loads(line.decode('utf-8'), object_pairs_hook=_pairs)
        if type(header) is not dict or HEADERS.get(header.get('op')) != set(header):
            raise ValueError('Unregistered runner operation')
        runner = (runner_factory or _default_runner)()
        if header['op'] == 'preview':
            if payload:
                raise ValueError('Preview takes no payload')
            result = canonical(runner.preview(header['action_id'], header['parameters']))
        elif header['op'] == 'execute':
            result = runner.execute(payload)
        else:
            if payload or type(header['request_id']) is not str or not re.fullmatch('[0-9a-f]{32}', header['request_id']):
                raise ValueError('Invalid reconcile request')
            operation = runner.confirm if header['op'] == 'confirm' else runner.reconcile
            result = operation(header['request_id'])
    except Exception:
        stderr.write(REFUSED)
        stderr.flush()
        return 2
    stdout.write(result)
    stdout.flush()
    return 0
