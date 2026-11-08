"""TEST-ONLY action family for exercising the runner: writes one value to a file in a temporary directory.

It is never registered in the production family registry and touches no system configuration.
"""
import hashlib
import json
from pathlib import Path
import re
import sys


class FileValueFamily:
    action_id = 'fixture.file_value.v1'
    version = 1
    implementation_sha256 = 'f' * 64
    max_seconds = 60

    def __init__(self, root, *, crash_after_write=False):
        self.root, self.crash_after_write = Path(root), crash_after_write

    def validate(self, params):
        if (type(params) is not dict or set(params) != {'name', 'value'} or type(params['name']) is not str
                or not re.fullmatch('[a-z]{1,16}', params['name']) or type(params['value']) is not str
                or len(params['value']) > 32):
            raise ValueError('Invalid fixture parameters')

    def read_state(self, params):
        path = self.root / params['name']
        return path.read_bytes() if path.exists() else b''

    def expected_after(self, params, before):
        return params['value'].encode()

    def summary(self, params, before):
        # Sanitized preview: lengths only, as a real family exports only allowlisted facts.
        return {'name': params['name'], 'current_length': len(before), 'proposed_length': len(params['value'])}

    def restore(self, params, before):
        path = self.root / params['name']
        if before:
            path.write_bytes(before)
        elif path.exists():
            path.unlink()

    def apply(self, params):
        (self.root / params['name']).write_bytes(params['value'].encode())
        with open(self.root / 'writes.log', 'a', encoding='utf-8') as log:
            log.write(params['name'] + '\n')
        if self.crash_after_write:
            import os
            os._exit(9)  # A real process death: no finally blocks, no receipt.


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    """Subprocess entry: python -B runner_fixture.py <state_dir> <work_dir> <request_file> <utc_now> [crash]."""
    from datetime import datetime
    from vm.ubuntu.runner import Runner
    state, work, request, now = sys.argv[1:5]
    family = FileValueFamily(work, crash_after_write=len(sys.argv) > 5)
    fixed = datetime.fromisoformat(now)  # the test's fixed clock, so fixture approvals are not judged by wall time
    runner = Runner(state, {family.action_id: family}, lambda: ('a' * 32, 'ubuntu-fixture'), clock=lambda: fixed,
                    require_root_owned=False)
    receipt = runner.execute(Path(request).read_bytes())
    sys.stdout.write(json.loads(receipt)['outcome'] + ' ' + json.loads(receipt)['code'])


if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    main()
