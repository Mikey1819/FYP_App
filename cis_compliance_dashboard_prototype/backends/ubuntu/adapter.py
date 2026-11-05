"""Ubuntu connection/capability boundary; assessment stays closed until its source/collector gate is met.

This early integration checkpoint deliberately emits no invented findings or execution outcomes.
Assessment, agent and remediation implementations are tracked separately in INTEGRATION_PROGRESS.md.
"""
from backends.base import BoundBackend
from system.contracts import Capabilities, ComparisonResult, RecordRef, TargetSummary, WorkspaceSnapshot


class UbuntuBackend(BoundBackend):
    def __init__(self, database_path, *, session, ledger):
        super().__init__(session=session, ledger=ledger)
        self.database_path = database_path

    def capabilities(self, connection_session_id):
        self.check(connection_session_id)
        return Capabilities(False, False, False, True, (
            'Ubuntu assessment is not enabled: the reviewed source lock and read-only collector are still being implemented.',
            'Ubuntu execution is not enabled: runner, approval and recovery acceptance gates are pending.',))

    def snapshot(self, connection_session_id, workflow_session_id, round_ref=None):
        binding = self.check(connection_session_id, workflow_session_id, round_ref)
        s = self.session
        return WorkspaceSnapshot(TargetSummary(RecordRef('ubuntu', s.target_id, s.target_id),
            s.identity.hostname, 'Ubuntu Server 22.04', 'ssh', 'No assessment collected',
            'connected' if s.active else 'disconnected'), binding)

    def start_round(self, connection_session_id, workflow_session_id, goal, mode, operation_id):
        self.check(connection_session_id, workflow_session_id)
        raise ValueError('Ubuntu source and collector acceptance gates are pending; no scan was run')

    def decide(self, connection_session_id, workflow_session_id, proposal_ref, approved, operator, comment, operation_id):
        self.check(connection_session_id, workflow_session_id, proposal_ref)
        raise ValueError('No Ubuntu proposal implementation is enabled')

    def execute_approved(self, connection_session_id, workflow_session_id, round_ref,
                         expected_approved_request_ids, deterministic, operation_id):
        self.check(connection_session_id, workflow_session_id, round_ref)
        raise ValueError('Ubuntu target-runner and recovery gates are pending; no write was dispatched')

    def history(self, target_id=None, limit=50):
        if target_id not in (None, self.session.target_id):
            raise ValueError('History belongs to another target')
        return ()

    def compare(self, before, after):
        return ComparisonResult(False, 'No validated Ubuntu assessment history is available yet')
