"""Durable approval and at-most-once simulation; deliberately no live executor.

The UI and future model may propose only the registered synthetic NLA action.
Only the administrator controller calls decide/execute_simulated. A committed
attempt consumes approval even if the process stops before recording its result.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import uuid

from .domain import Evidence, EvidenceMode, Operator, Status, assess
from .storage import AssessmentStore, _encode_result, _decode_result


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    assessment_id: str
    target_id: str
    control_id: str
    action_id: str
    parameters_json: str
    reason: str
    created_at: str
    binding: str


@dataclass(frozen=True)
class WorkflowState:
    proposal: Proposal
    events: tuple[dict, ...]

    def event(self, kind):
        return next((event for event in self.events if event["kind"] == kind), None)

    @property
    def phase(self):
        decision = self.event("decision")
        if not decision:
            return "Awaiting Approval"
        if not decision["payload"]["approved"]:
            return "Rejected"
        verification = self.event("verification")
        if verification:
            result = _decode_result(verification["payload"])
            return "Verification Passed" if result.status == Status.COMPLIANT else "Verification Failed"
        execution = self.event("execution")
        if execution:
            return "Verification unavailable" if execution["payload"]["success"] else "Execution Failed"
        return "Execution outcome unknown" if self.event("attempt") else "Approved"


class WorkflowStore:
    def __init__(self, assessments: AssessmentStore):
        self.assessments = assessments

    def create_proposal(self, *, assessment_id, target_id, control_id, action_id,
                        parameters, reason) -> Proposal:
        snapshot = self.assessments.get(assessment_id)
        finding = next((r for r in snapshot.results if r.control.control_id == control_id), None)
        if (finding is None or finding.evidence.target_id != target_id
                or target_id != "DEMO-SERVER-2022" or control_id != "DEMO-NLA"
                or finding.evidence.mode != EvidenceMode.SYNTHETIC
                or finding.status != Status.NON_COMPLIANT
                or finding.control.catalogue_version != "demo-v1"
                or finding.control.rule.operator != Operator.EQUALS
                or finding.control.rule.expected is not True):
            raise ValueError("Only a non-compliant synthetic demo NLA finding is supported")
        if (action_id != "DEMO-ENABLE-NLA" or type(parameters) is not dict
                or set(parameters) != {"required"} or parameters["required"] is not True):
            raise ValueError("Unsupported action or parameters")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise ValueError("A short proposal reason is required")
        proposal_id = uuid.uuid4().hex
        created_at = _now()
        payload = dict(proposal_id=proposal_id, assessment_id=assessment_id, target_id=target_id,
                       control_id=control_id, action_id=action_id, parameters_json=_json(parameters),
                       reason=reason, created_at=created_at)
        binding = hashlib.sha256(_json(payload).encode()).hexdigest()
        with self.assessments._connection() as connection:
            connection.execute("INSERT INTO workflow_proposals VALUES (?, ?, ?, ?, ?)",
                               (proposal_id, assessment_id, created_at, binding, _json(payload)))
        return Proposal(**payload, binding=binding)

    @staticmethod
    def _state(connection, proposal_id):
        row = connection.execute("SELECT payload, binding FROM workflow_proposals WHERE proposal_id = ?",
                                 (proposal_id,)).fetchone()
        if row is None:
            raise KeyError(proposal_id)
        proposal = Proposal(**json.loads(row[0]), binding=row[1])
        events = tuple({"kind": kind, "created_at": created, "payload": json.loads(payload)}
                       for kind, created, payload in connection.execute(
                           "SELECT kind, created_at, payload FROM workflow_events WHERE proposal_id = ? ORDER BY sequence",
                           (proposal_id,)))
        return WorkflowState(proposal, events)

    def get(self, proposal_id):
        with self.assessments._connection() as connection:
            return self._state(connection, proposal_id)

    def list_for_assessment(self, assessment_id):
        with self.assessments._connection() as connection:
            ids = connection.execute("SELECT proposal_id FROM workflow_proposals WHERE assessment_id = ? ORDER BY created_at DESC, rowid DESC",
                                     (assessment_id,)).fetchall()
            return tuple(self._state(connection, row[0]) for row in ids)

    @staticmethod
    def _append(connection, proposal_id, kind, payload):
        connection.execute("INSERT INTO workflow_events (proposal_id, kind, created_at, payload) VALUES (?, ?, ?, ?)",
                           (proposal_id, kind, _now(), _json(payload)))

    def decide(self, proposal_id, *, binding, approved, actor, comment=""):
        if type(approved) is not bool or not isinstance(actor, str) or not actor.strip():
            raise ValueError("An explicit administrator decision and actor are required")
        if not isinstance(comment, str) or len(comment) > 4000:
            raise ValueError("Review comment must be text of at most 4000 characters")
        with self.assessments._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = self._state(connection, proposal_id)
            if binding != state.proposal.binding or state.event("decision"):
                raise ValueError("Proposal changed or already decided; reload the saved proposal")
            self._append(connection, proposal_id, "decision",
                         dict(binding=binding, approved=approved, actor=actor, comment=comment))

    def execute_simulated(self, proposal_id, *, binding, simulator):
        """Claim once before calling the simulator; never retry an uncertain effect."""
        if not isinstance(simulator, NlaSimulator):
            raise ValueError("Only the synthetic NLA simulator is supported")
        with self.assessments._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            state = self._state(connection, proposal_id)
            decision = state.event("decision")
            if (binding != state.proposal.binding or not decision
                    or not decision["payload"]["approved"] or state.event("attempt")):
                raise ValueError("Exact approval is required and may be consumed only once")
            self._append(connection, proposal_id, "attempt", {
                "binding": binding, "mode": "Simulated",
                "scenario": {"apply_change": simulator.apply_change,
                             "fail_execution": simulator.fail_execution,
                             "fail_collection": simulator.fail_collection},
            })
        proposal = state.proposal
        try:
            success = simulator.execute(proposal)
            if type(success) is not bool:
                raise ValueError("Invalid executor result")
            detail = "Simulated action completed" if success else "Simulated execution failed"
        except Exception as error:
            success, detail = False, f"Simulator failed ({type(error).__name__}); no automatic retry"
        with self.assessments._connection() as connection:
            self._append(connection, proposal_id, "execution", {"success": success, "detail": detail, "mode": "Simulated"})
        if success:
            original = next(r for r in self.assessments.get(proposal.assessment_id).results
                            if r.control.control_id == proposal.control_id)
            try:
                evidence = simulator.collect(proposal)
                attempt_time = datetime.fromisoformat(self.get(proposal_id).event("attempt")["created_at"])
                if (not isinstance(evidence, Evidence) or evidence.target_id != proposal.target_id
                        or evidence.control_id != proposal.control_id or evidence.mode != EvidenceMode.SYNTHETIC
                        or evidence.collected_at < attempt_time):
                    raise ValueError("Verification evidence has wrong identity, mode or timestamp")
            except Exception as error:
                evidence = Evidence(proposal.target_id, proposal.control_id, None, datetime.now(timezone.utc),
                                    EvidenceMode.SYNTHETIC, "Synthetic verification collector",
                                    f"Verification collection failed ({type(error).__name__})")
            result = assess("verification:" + proposal_id, original.control, evidence)
            with self.assessments._connection() as connection:
                self._append(connection, proposal_id, "verification", _encode_result(result))
        return self.get(proposal_id)


class NlaSimulator:
    """In-memory fixture tool with a separate read-back; never calls the host OS."""

    def __init__(self, *, apply_change=True, fail_execution=False, fail_collection=False):
        self.apply_change = apply_change
        self.fail_execution = fail_execution
        self.fail_collection = fail_collection
        self.value = False
        self.write_calls = 0

    def execute(self, proposal):
        self.write_calls += 1
        if self.fail_execution:
            return False
        if self.apply_change:
            self.value = True
        return True

    def collect(self, proposal):
        return Evidence(proposal.target_id, proposal.control_id,
                        None if self.fail_collection else self.value, datetime.now(timezone.utc),
                        EvidenceMode.SYNTHETIC, "NLA simulator read-back; no Windows target inspected",
                        "Simulated collection failure" if self.fail_collection else None)
