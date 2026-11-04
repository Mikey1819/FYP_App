"""Coordinator contracts with a scripted model and a minimal tool double; not evidence of real model behaviour."""

from pathlib import Path
import tempfile
import unittest

from hardening.import_storage import ImportedEvidenceStore
from hardening.investigation import Coordinator, InvestigationLog, Limits
from hardening.remediation import RemediationStore


def call(name, args=None):
    return {"function": {"name": name, "arguments": dict(args or {})}}


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


class EchoTools:
    """One read-only lookup and one terminal decision; validates names and arguments like a real role."""
    names = ("lookup", "finish")
    evidence_mode, proposal_id = "Synthetic", None
    assessment_id, target_id, scenario = "test-assessment", "test-target", "Coordinator contract test"
    system_prompt, initial_message = "Test agent.", "Start."

    def __init__(self, store, *, repeatable=(), nudge=False):
        self.store, self.repeatable, self.nudge = store, repeatable, nudge
        self.terminal_outcome, self.calls = None, []

    def schemas(self):
        return [{"type": "function", "function": {"name": n, "parameters": {"type": "object", "properties": {}}}}
                for n in self.names]

    def call(self, name, arguments):
        if name not in self.names or arguments != {}:
            raise ValueError("Tool or arguments outside this role")
        self.calls.append(name)
        if name == "finish":
            self.terminal_outcome = dict(outcome="done", reason="Finished by decision.")
            return dict(self.terminal_outcome)
        return {"value": 42}


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        imports = ImportedEvidenceStore(Path(directory.name) / "imports.sqlite3")
        self.store = RemediationStore(Path(directory.name) / "agentic.sqlite3", imports)  # The agents' trace store.

    def run_mock(self, messages, tools=None, **kwargs):
        self.client, self.tools = MockClient(messages), tools or EchoTools(self.store)
        return Coordinator(self.client, self.tools, **kwargs).run()

    def test_model_observes_results_and_a_terminal_decision_ends_the_run(self):
        run = self.run_mock([{"tool_calls": [call("lookup")]}, {"tool_calls": [call("finish")]}])
        self.assertEqual(run["events"][-1]["data"]["status"], "Completed")
        self.assertEqual(run["events"][-1]["data"]["outcome"]["outcome"], "done")
        self.assertEqual(self.client.received[1][-1]["role"], "tool")  # The lookup result was returned.
        self.assertIn("42", self.client.received[1][-1]["content"])
        self.assertEqual(InvestigationLog(self.store).get(run["run_id"]), run)  # Durable and re-readable.

    def test_answer_without_a_decision_is_labelled_not_completed(self):
        run = self.run_mock([{"tool_calls": [call("lookup")]}, {"content": "I think we are done."}])
        self.assertEqual(run["events"][-1]["data"]["status"], "No structured decision")

    def test_out_of_role_and_extra_arguments_are_rejected_and_two_invalid_calls_stop(self):
        run = self.run_mock([{"tool_calls": [call("execute"), call("lookup", {"command": "x"})]}])
        self.assertEqual(run["events"][-1]["data"]["status"], "Invalid calls blocked")
        self.assertEqual(self.tools.calls, [])
        self.assertEqual([e["kind"] for e in run["events"] if e["kind"].startswith("tool")],
                         ["tool_rejected", "tool_rejected"])

    def test_repetition_is_blocked_unless_the_role_declares_it_and_batches_are_bounded(self):
        repeated = {"tool_calls": [call("lookup")]}
        run = self.run_mock([repeated, repeated])
        self.assertEqual(run["events"][-1]["data"]["status"], "Repeated call blocked")
        self.assertEqual(self.tools.calls, ["lookup"])
        run = self.run_mock([repeated, repeated, {"tool_calls": [call("finish")]}],
                            tools=EchoTools(self.store, repeatable=("lookup",)))
        self.assertEqual(self.tools.calls, ["lookup", "lookup", "finish"])
        run = self.run_mock([{"tool_calls": [call("lookup")] * 3}], limits=Limits(calls=2))
        self.assertEqual(run["events"][-1]["data"]["status"], "Call limit reached")
        self.assertEqual(self.tools.calls, [])

    def test_one_nudge_when_the_role_asks_for_it(self):
        silent = {"content": "", "tool_calls": []}
        run = self.run_mock([silent, {"tool_calls": [call("finish")]}], tools=EchoTools(self.store, nudge=True))
        self.assertEqual(run["events"][-1]["data"]["status"], "Completed")
        self.assertEqual([e["data"]["available"] for e in run["events"] if e["kind"] == "nudge"], [["lookup", "finish"]])
        self.assertIn("Valid now: lookup, finish", self.client.received[1][-1]["content"])
        run = self.run_mock([silent, silent], tools=EchoTools(self.store, nudge=True))
        self.assertEqual(run["events"][-1]["data"]["status"], "Unavailable")  # Only one reminder.

    def test_model_outage_and_malformed_messages_are_unavailable_without_leaking_details(self):
        for response in (TimeoutError("sensitive details"), {"tool_calls": "not-a-list"}, None):
            run = self.run_mock([response])
            self.assertEqual(run["events"][-1]["data"]["status"], "Unavailable")
            self.assertNotIn("sensitive details", str(run))

    def test_step_limit_and_late_response_do_not_dispatch_more_tools(self):
        run = self.run_mock([{"tool_calls": [call("lookup")]}], limits=Limits(steps=1))
        self.assertEqual(run["events"][-1]["data"]["status"], "Step limit reached")
        ticks = iter([0, 0, 4, 4])
        run = self.run_mock([{"tool_calls": [call("lookup")]}], limits=Limits(seconds=2), clock=lambda: next(ticks))
        self.assertEqual(run["events"][-1]["data"]["status"], "Time limit reached")
        self.assertEqual(self.tools.calls, [])

    def test_model_thinking_is_never_saved(self):
        run = self.run_mock([{"content": "<think>private internal text</think>Ask an administrator.", "thinking": "secret"}])
        self.assertNotIn("private internal", str(run))
        self.assertNotIn("secret", str(run))

    def test_invalid_limits_fail_before_model_use(self):
        for value in (0, -1, True, 1000):
            with self.assertRaises(ValueError):
                Limits(steps=value)


if __name__ == "__main__":
    unittest.main()
