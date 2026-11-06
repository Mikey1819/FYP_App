"""recovery.restore.v1: approved restore of one applied request to its exact stored before-state.

Auxiliary operation, not a CIS control. It runs through the same runner protocol (fence, fresh read-set,
claim, receipt, at most once). It is eligible only when the original request was applied and the current
state still equals the state that request produced, so a restore never overwrites a newer change.
The original family must implement `restore(params, before_bytes)`. Python 3.10, standard library only.
"""
import hashlib
from pathlib import Path
import re
from .remediation_schema import parse_receipt, parse_request

ACTION_ID = 'recovery.restore.v1'
IMPLEMENTATION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_params(params):
    if (type(params) is not dict or set(params) != {'restores_request_id', 'restores_request_sha256'}
            or type(params['restores_request_id']) is not str or not re.fullmatch('[0-9a-f]{32}', params['restores_request_id'])
            or type(params['restores_request_sha256']) is not str
            or not re.fullmatch('[0-9a-f]{64}', params['restores_request_sha256'])):
        raise ValueError('Invalid restore parameters')


class RestoreFamily:
    action_id = ACTION_ID
    version = 1
    implementation_sha256 = IMPLEMENTATION_SHA256
    max_seconds = 60

    def __init__(self, runner):
        self.runner = runner

    def _original(self, params):
        validate_params(params)
        directory = self.runner._directory(params['restores_request_id'])
        try:
            raw = (directory / 'request.json').read_bytes()
            receipt = parse_receipt((directory / 'receipt.json').read_bytes())
            before = (directory / 'before_state').read_bytes()
        except FileNotFoundError:
            raise ValueError('No applied request with a stored before-state') from None
        if _sha(raw) != params['restores_request_sha256']:
            raise ValueError('Restore names other request bytes')
        request = parse_request(raw)
        if request['action']['action_id'] == ACTION_ID:
            raise ValueError('A restore is not itself restorable')
        if receipt['outcome'] not in ('applied', 'reconciled_applied'):
            raise ValueError('Only an applied request can be restored')
        family = self.runner.families.get(request['action']['action_id'])
        if family is None or not hasattr(family, 'restore') or (family.version, family.implementation_sha256) != (
                request['action']['version'], request['action']['implementation_sha256']):
            raise ValueError('The original family is not available at the approved version')
        if _sha(before) != request['before_state_sha256']:
            raise ValueError('Stored before-state failed its integrity check')
        return request, family, before

    def validate(self, params):
        validate_params(params)

    def read_state(self, params):
        request, family, _ = self._original(params)
        return family.read_state(request['parameters'])

    def expected_after(self, params, current):
        return self._original(params)[2]

    def check_eligible(self, params):
        request, family, _ = self._original(params)
        if _sha(family.read_state(request['parameters'])) != request['expected_after_sha256']:
            raise ValueError('State changed since the fix; a restore would overwrite a newer change')

    def summary(self, params, before):
        request, _, _ = self._original(params)
        return {'restores_request_id': request['request_id'], 'restores_action_id': request['action']['action_id'],
                'control_id': request['control_id']}

    def apply(self, params):
        request, family, before = self._original(params)
        family.restore(request['parameters'], before)
