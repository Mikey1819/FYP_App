"""Authorization/verification contracts with fixtures; never run host commands."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo import CURRENT_RESULTS
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo_storage import load_demo
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.domain import EvidenceMode, Status
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.storage import AssessmentStore, _decode_result
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.workflow import WorkflowStore, NlaSimulator


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "workflow.sqlite3"
        self.assessments = AssessmentStore(self.path)
        load_demo(self.assessments)
        self.workflow = WorkflowStore(self.assessments)

    def propose(self, **overrides):
        arguments = dict(assessment_id="1042", target_id="DEMO-SERVER-2022", control_id="DEMO-NLA",
                         action_id="DEMO-ENABLE-NLA", parameters={"required": True}, reason="Synthetic proposal")
        arguments.update(overrides)
        return self.workflow.create_proposal(**arguments)

    def approve(self, proposal):
        self.workflow.decide(proposal.proposal_id, binding=proposal.binding, approved=True,
                             actor="demo-admin", comment="Exact simulated action only")

    def execute(self, proposal, simulator=None):
        return self.workflow.execute_simulated(proposal.proposal_id, binding=proposal.binding,
                                               simulator=simulator or NlaSimulator())

    def test_allowlist_rejects_wrong_target_control_action_parameters_and_mode(self):
        for args in ({"target_id": "laptop"}, {"control_id": "DEMO-GUEST"},
                     {"action_id": "powershell"}, {"parameters": {"required": 1}},
                     {"parameters": {"required": True, "command": "anything"}},
                     {"assessment_id": "1041"}, {"reason": ""}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.propose(**args)
        imported = tuple(replace(r, assessment_id="imported", evidence=replace(r.evidence, mode=EvidenceMode.IMPORTED))
                         for r in CURRENT_RESULTS)
        self.assessments.save(imported, initiated_by="test")
        with self.assertRaises(ValueError):
            self.propose(assessment_id="imported")
        self.assertEqual(self.workflow.list_for_assessment("1042"), ())

    def test_unapproved_and_rejected_proposals_make_zero_executor_calls(self):
        proposal = self.propose()
        simulator = NlaSimulator()
        with self.assertRaises(ValueError):
            self.execute(proposal, simulator)
        self.workflow.decide(proposal.proposal_id, binding=proposal.binding, approved=False,
                             actor="demo-admin", comment="Wait for maintenance")
        with self.assertRaises(ValueError):
            self.execute(proposal, simulator)
        self.assertEqual(simulator.write_calls, 0)
        state = WorkflowStore(AssessmentStore(self.path)).get(proposal.proposal_id)
        self.assertEqual(state.phase, "Rejected")
        self.assertIsNone(state.event("attempt"))
        self.assertEqual(state.event("decision")["payload"]["comment"], "Wait for maintenance")

    def test_binding_cannot_approve_or_execute_another_proposal(self):
        first, second = self.propose(), self.propose()
        with self.assertRaises(ValueError):
            self.workflow.decide(second.proposal_id, binding=first.binding, approved=True, actor="admin")
        self.approve(first)
        with self.assertRaises(ValueError):
            self.workflow.execute_simulated(second.proposal_id, binding=first.binding, simulator=NlaSimulator())
        with self.assertRaises(ValueError):
            self.workflow.decide(first.proposal_id, binding=first.binding, approved=False, actor="admin")

    def test_success_survives_new_process_and_preserves_original_snapshot(self):
        proposal = self.propose()
        self.approve(proposal)
        state = self.execute(proposal)
        self.assertEqual(state.phase, "Verification Passed")
        self.assertEqual(self.assessments.get("1042").results, CURRENT_RESULTS)
        result = _decode_result(state.event("verification")["payload"])
        self.assertEqual(result.status, Status.COMPLIANT)
        self.assertTrue(result.evidence.value)
        script = """
import json, sys
from hardening.storage import AssessmentStore
from hardening.workflow import WorkflowStore, NlaSimulator
store = WorkflowStore(AssessmentStore(sys.argv[1]))
state = store.get(sys.argv[2])
simulator = NlaSimulator()
blocked = False
try:
    store.execute_simulated(state.proposal.proposal_id, binding=state.proposal.binding, simulator=simulator)
except ValueError:
    blocked = True
print(json.dumps([state.phase, blocked, simulator.write_calls]))
"""
        process = subprocess.run([sys.executable, "-B", "-c", script, str(self.path), proposal.proposal_id],
                                 cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                 text=True, check=True, timeout=20)
        self.assertEqual(json.loads(process.stdout), ["Verification Passed", True, 0])

    def test_command_success_without_changed_evidence_fails_verification(self):
        proposal = self.propose()
        self.approve(proposal)
        simulator = NlaSimulator(apply_change=False)
        state = self.execute(proposal, simulator)
        self.assertTrue(state.event("execution")["payload"]["success"])
        self.assertEqual(state.phase, "Verification Failed")
        with self.assertRaises(ValueError):
            self.execute(proposal, simulator)
        self.assertEqual(simulator.write_calls, 1)
        retry = self.propose()
        with self.assertRaises(ValueError):
            self.execute(retry, simulator)
        self.approve(retry)
        self.assertEqual(self.execute(retry).phase, "Verification Passed")
        self.assertEqual(len(self.workflow.list_for_assessment("1042")), 2)

    def test_failed_execution_does_not_collect_or_retry(self):
        proposal = self.propose()
        self.approve(proposal)
        simulator = NlaSimulator(fail_execution=True)
        with patch.object(simulator, "collect") as collect:
            state = self.execute(proposal, simulator)
            collect.assert_not_called()
        self.assertEqual(state.phase, "Execution Failed")
        self.assertIsNone(state.event("verification"))
        with self.assertRaises(ValueError):
            self.execute(proposal, simulator)

    def test_failed_or_wrong_identity_collection_is_error_not_compliance(self):
        for wrong_target in (False, True):
            proposal = self.propose()
            self.approve(proposal)
            simulator = NlaSimulator(fail_collection=not wrong_target)
            if wrong_target:
                original_collect = simulator.collect
                simulator.collect = lambda p: replace(original_collect(p), target_id="another-target")
            state = self.execute(proposal, simulator)
            result = _decode_result(state.event("verification")["payload"])
            self.assertEqual(result.status, Status.ERROR)
            self.assertEqual(state.phase, "Verification Failed")
            self.assertEqual(result.evidence.target_id, proposal.target_id)

    def test_interrupted_attempt_cannot_be_replayed_after_restart(self):
        proposal = self.propose()
        self.approve(proposal)
        simulator = NlaSimulator()
        with patch.object(simulator, "execute", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.execute(proposal, simulator)
        restarted = WorkflowStore(AssessmentStore(self.path))
        self.assertEqual(restarted.get(proposal.proposal_id).phase, "Execution outcome unknown")
        with self.assertRaises(ValueError):
            restarted.execute_simulated(proposal.proposal_id, binding=proposal.binding, simulator=NlaSimulator())

    def test_concurrent_execution_consumes_approval_once(self):
        proposal = self.propose()
        self.approve(proposal)
        simulator = NlaSimulator()
        def execute(_):
            try:
                self.execute(proposal, simulator)
                return "executed"
            except ValueError:
                return "blocked"
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertEqual(sorted(executor.map(execute, range(2))), ["blocked", "executed"])
        self.assertEqual(simulator.write_calls, 1)

    def test_schema_one_upgrade_keeps_assessment_payloads(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            original = connection.execute("SELECT * FROM assessment_snapshots ORDER BY assessment_id").fetchall()
            connection.execute("DROP TABLE workflow_events")
            connection.execute("DROP TABLE workflow_proposals")
            connection.execute("PRAGMA user_version = 1")
        upgraded = AssessmentStore(self.path)
        self.assertEqual(upgraded.get("1042").results, CURRENT_RESULTS)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], AssessmentStore.SCHEMA_VERSION)
            self.assertEqual(connection.execute("SELECT * FROM assessment_snapshots ORDER BY assessment_id").fetchall(), original)

    def test_workflow_audit_rows_cannot_be_updated_deleted_or_replaced(self):
        proposal = self.propose()
        self.approve(proposal)
        self.execute(proposal)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            for table in ("workflow_proposals", "workflow_events"):
                for sql in (f"DELETE FROM {table}", f"UPDATE {table} SET payload = '{{}}'",
                            f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}"):
                    with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(sql)
        self.assertEqual(self.workflow.get(proposal.proposal_id).phase, "Verification Passed")


if __name__ == "__main__":
    unittest.main()
