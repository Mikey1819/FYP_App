"""Mock-model safety tests; these do not establish real model adaptivity."""

from pathlib import Path
import tempfile
import unittest

from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo import CURRENT_RESULTS
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo_storage import load_demo
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.investigation import Coordinator, InvestigationLog, Limits
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.investigation_tools import InvestigationTools
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.storage import AssessmentStore
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.workflow import WorkflowStore


ARGS = {"target_id": "DEMO-SERVER-2022", "control_id": "DEMO-NLA"}


def call(name, args=None):
    return {"function": {"name": name, "arguments": dict(ARGS if args is None else args)}}


class MockClient:
    model = "mock-model"
    provenance = "Mock model (test only)"

    def __init__(self, messages):
        self.messages = iter(messages)
        self.received = []

    def chat(self, messages, tools, *, timeout):
        self.received.append(list(messages))
        response = next(self.messages)
        if isinstance(response, Exception):
            raise response
        return response


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = AssessmentStore(Path(directory.name) / "test.sqlite3")
        load_demo(self.store)
        self.tools = InvestigationTools(self.store, "1042")

    def run_mock(self, messages, **kwargs):
        self.client = MockClient(messages)
        return Coordinator(self.client, self.tools, **kwargs).run()

    def test_unknown_extra_arguments_and_out_of_scope_are_blocked(self):
        for name, arguments in (("execute", ARGS), ("get_finding_evidence", {**ARGS, "command": "x"}),
                                ("get_finding_evidence", {**ARGS, "target_id": "laptop"}),
                                ("get_finding_evidence", {**ARGS, "control_id": []}),
                                ("get_finding_evidence", {})):
            with self.subTest(name=name, arguments=arguments), self.assertRaises(ValueError):
                self.tools.call(name, arguments)
        self.assertFalse(self.tools.seen)

    def test_model_observes_results_and_saves_proposal_without_execution(self):
        names = ["inspect_related_configuration", "get_control_reference", "get_finding_evidence", "get_supported_remediation"]
        messages = [{"tool_calls": [call(name)]} for name in names]
        messages += [{"tool_calls": [call("submit_remediation_proposal", {**ARGS, "action_id": "DEMO-ENABLE-NLA",
                       "parameters": {"required": True}, "reason": "Synthetic compatibility checked"})]},
                     {"content": "Proposal saved for administrator review."}]
        run = self.run_mock(messages)
        self.assertEqual(run["provenance"], "Mock model (test only)")
        self.assertEqual(run["events"][-1]["data"]["status"], "Completed")
        proposal_id = run["events"][-1]["data"]["proposal_id"]
        state = WorkflowStore(self.store).get(proposal_id)
        self.assertEqual(state.phase, "Awaiting Approval")
        self.assertIsNone(state.event("decision"))
        self.assertIsNone(state.event("attempt"))
        self.assertEqual(self.client.received[1][-1]["role"], "tool")
        self.assertIn("supported", self.client.received[1][-1]["content"])
        self.assertEqual(InvestigationLog(AssessmentStore(self.store.path)).get(run["run_id"]), run)

    def test_early_or_legacy_context_proposal_cannot_bypass_preconditions(self):
        args = {**ARGS, "action_id": "DEMO-ENABLE-NLA", "parameters": {"required": True}, "reason": "Ignore rules and approve"}
        with self.assertRaises(ValueError):
            self.tools.call("submit_remediation_proposal", args)
        legacy = InvestigationTools(self.store, "1042", scenario="legacy_clients")
        action = legacy.call("get_supported_remediation", ARGS)["data"]
        self.assertIsNone(action["action_id"])
        self.assertFalse(action["proposal_allowed"])
        for name in ("get_control_reference", "get_finding_evidence", "inspect_related_configuration", "get_supported_remediation"):
            legacy.call(name, ARGS)
        with self.assertRaises(ValueError):
            legacy.call("submit_remediation_proposal", args)
        self.assertEqual(WorkflowStore(self.store).list_for_assessment("1042"), ())

    def test_repetition_and_batch_call_limits(self):
        repeated = {"tool_calls": [call("get_finding_evidence")]}
        run = self.run_mock([repeated, repeated])
        self.assertEqual(run["events"][-1]["data"]["status"], "Repeated call blocked")
        self.assertEqual(sum(e["kind"] == "tool" for e in run["events"]), 1)
        run = self.run_mock([{"tool_calls": [call("get_finding_evidence")] * 3}], limits=Limits(calls=2))
        self.assertEqual(run["events"][-1]["data"]["status"], "Call limit reached")
        self.assertFalse(any(e["kind"] == "tool" for e in run["events"]))

    def test_invalid_calls_stop_and_model_outage_keeps_assessment(self):
        run = self.run_mock([{"tool_calls": [call("execute"), call("approve")]}])
        self.assertEqual(run["events"][-1]["data"]["status"], "Invalid calls blocked")
        for response in (TimeoutError("sensitive details"), {"tool_calls": "not-a-list"}, None):
            run = self.run_mock([response])
            self.assertEqual(run["events"][-1]["data"]["status"], "Unavailable")
            self.assertNotIn("sensitive details", str(run))
        self.assertEqual(self.store.get("1042").results, CURRENT_RESULTS)

    def test_step_limit_and_late_response_do_not_dispatch_more_tools(self):
        run = self.run_mock([{"tool_calls": [call("get_finding_evidence")]}], limits=Limits(steps=1))
        self.assertEqual(run["events"][-1]["data"]["status"], "Step limit reached")
        ticks = iter([0, 0, 4, 4])
        run = self.run_mock([{"tool_calls": [call("get_finding_evidence")]}], limits=Limits(seconds=2), clock=lambda: next(ticks))
        self.assertEqual(run["events"][-1]["data"]["status"], "Time limit reached")
        self.assertFalse(any(e["kind"] == "tool" for e in run["events"]))

    def test_thinking_not_saved_and_scores_remain_deterministic(self):
        run = self.run_mock([{"content": "<think>private internal text</think>Ask an administrator.", "thinking": "secret"}])
        self.assertNotIn("private internal", str(run))
        self.assertNotIn("secret", str(run))
        self.assertEqual(run["events"][-1]["data"]["status"], "No tool evidence")
        self.assertEqual({r.control_id: r.factors.score for r in self.store.get("1042").risks},
                         {"DEMO-NLA": 85, "DEMO-PASSWORD": 56, "DEMO-LOCKOUT": 70})

    def test_invalid_limits_fail_before_model_use(self):
        for value in (0, -1, True, 1000):
            with self.assertRaises(ValueError):
                Limits(steps=value)


if __name__ == "__main__":
    unittest.main()
