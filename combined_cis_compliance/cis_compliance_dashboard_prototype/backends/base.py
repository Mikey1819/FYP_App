"""Common fail-closed command validation; unsupported operations never report success."""
from system.contracts import OperationState, WorkflowBinding
from system.ledger import now
from uuid import uuid4


class BoundBackend:
    def __init__(self, *, session, ledger):
        self.session, self.ledger = session, ledger

    def check(self, connection_id, workflow_id=None, reference=None):
        s = self.session
        if not s.active or connection_id != s.connection_session_id:
            raise ValueError('Expired or different connection session')
        if reference and (reference.platform, reference.target_id) != (s.identity.platform, s.target_id):
            raise ValueError('Reference belongs to another platform or target')
        return self.ledger.resume(workflow_id, s.identity.platform, s.target_id, s.registration_epoch) if workflow_id else None

    def new_binding(self, connection_id):
        self.check(connection_id)
        s = self.session
        return self.ledger.add_binding(WorkflowBinding(uuid4().hex, s.identity.platform, s.target_id,
                                                       s.registration_epoch, uuid4().hex, now()))

    def operation_state(self, operation_id):
        return self.ledger.operation_state(operation_id)

    def request_auxiliary(self, connection_session_id, workflow_session_id, kind, basis, inputs, operation_id):
        self.check(connection_session_id, workflow_session_id, basis)
        return OperationState(operation_id, 'refused', code='unsupported', detail='This backend does not support this auxiliary operation.')

    def dispatch_auxiliary(self, connection_session_id, workflow_session_id, proposal_ref, operation_id):
        self.check(connection_session_id, workflow_session_id, proposal_ref)
        return OperationState(operation_id, 'refused', code='unsupported', detail='No auxiliary dispatcher is enabled.')

    def record_manual_review(self, connection_session_id, workflow_session_id, review, operation_id):
        self.check(connection_session_id, workflow_session_id, review.assessment_reference)
        return OperationState(operation_id, 'refused', code='unsupported', detail='Manual review is not enabled for this backend.')

    def cancel_operation(self, connection_session_id, workflow_session_id, subject_operation_id, operator, operation_id):
        self.check(connection_session_id, workflow_session_id)
        # Do not pretend a dispatched remote process has stopped.
        return OperationState(operation_id, 'refused', code='unsupported', detail='Cancellation is not yet implemented; inspect the existing operation.')

    def reconcile_operation(self, connection_session_id, subject_operation_id):
        self.check(connection_session_id)
        return OperationState(subject_operation_id, 'unresolved', code='reconciliation_required',
                              detail='No automatic replay. Target-side receipt reconciliation is required.')
