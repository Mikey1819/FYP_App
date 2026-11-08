"""Host dispatch of one approved request: ledger claim (with target ownership) -> one dispatch -> strict receipt.

A lost or untrusted receipt is `unresolved`, never a retry. `reconcile` asks the target what happened
and settles the ledger from that evidence; it never dispatches the request again. `completed` means the
change was applied as approved, not that the control is compliant: a fresh verification scan decides that.
"""
from dataclasses import dataclass
from vm.ubuntu.remediation_schema import parse_receipt
from .approvals import verify

SETTLED = {'applied': 'completed', 'reconciled_applied': 'completed', 'refused': 'refused',
           'reconciled_not_applied': 'refused', 'unresolved': 'unresolved', 'running': 'running',
           'rolled_back': 'refused'}
DETAIL = {'completed': 'Applied as approved; a fresh verification scan is required before it counts as compliant.',
          'refused': 'Not applied: {code}. A new plan and approval are required for another attempt.',
          'unresolved': 'Outcome unknown ({code}); reconcile from target evidence before any further change.',
          'running': 'Running under systemd supervision ({code}); check status, never re-dispatch.'}


@dataclass(frozen=True)
class ExecutionResult:
    operation_id: str
    state: str
    receipt: dict | None
    receipt_raw: bytes | None = None


def _trusted(raw, approved):
    receipt = parse_receipt(raw)
    if (receipt['request_id'], receipt['request_sha256']) != (approved.request['request_id'], approved.sha256):
        raise ValueError('Receipt belongs to another request')
    return receipt


def execute(approved, *, ledger, binding, operation_id, dispatch, now):
    request = verify(approved, now)
    if (binding.platform, binding.target_id, binding.registration_epoch, binding.workflow_session_id) != (
            'ubuntu', request['target_id'], request['registration_epoch'], request['workflow_session_id']):
        raise ValueError('Approved request belongs to another workflow, target or registration epoch')
    owner, state = ledger.claim(binding, operation_id, 'execution', {'request_sha256': approved.sha256}, mutation=True)
    if not owner:
        return ExecutionResult(state.operation_id, state.state, None)
    try:
        raw = dispatch(approved.raw)
        receipt = _trusted(raw, approved)
    except Exception:
        ledger.transition(operation_id, 'unresolved', detail=DETAIL['unresolved'].format(code='no_trusted_receipt'))
        return ExecutionResult(operation_id, 'unresolved', None)
    settled = SETTLED[receipt['outcome']]
    if settled != 'running':  # a supervised job keeps the claim's running state until its status settles
        ledger.transition(operation_id, settled, detail=DETAIL[settled].format(code=receipt['code']))
    return ExecutionResult(operation_id, settled, receipt, raw)


def reconcile(approved, *, ledger, operation_id, status):
    """Settle an unresolved execution from the target's own record; no dispatch."""
    current = ledger.operation_state(operation_id)
    if current.state not in ('unresolved', 'running'):
        return ExecutionResult(operation_id, current.state, None)
    raw = status(approved.request['request_id'])
    receipt = _trusted(raw, approved)
    settled = SETTLED[receipt['outcome']]
    if settled not in ('unresolved', 'running'):
        ledger.reconcile(operation_id, settled, detail=DETAIL[settled].format(code=receipt['code']))
    return ExecutionResult(operation_id, settled, receipt, raw)


def confirm(approved, *, ledger, operation_id, send):
    """Confirm a commit-confirm change. `send` must use a fresh SSH login made after the change was applied:
    that login is the proof the management channel survived. Without it the target's timer rolls back."""
    current = ledger.operation_state(operation_id)
    if current.state != 'running':
        return ExecutionResult(operation_id, current.state, None)
    raw = send(approved.request['request_id'])
    receipt = _trusted(raw, approved)
    settled = SETTLED[receipt['outcome']]
    if settled not in ('unresolved', 'running'):
        ledger.reconcile(operation_id, settled, detail=DETAIL[settled].format(code=receipt['code']))
    return ExecutionResult(operation_id, settled, receipt, raw)
