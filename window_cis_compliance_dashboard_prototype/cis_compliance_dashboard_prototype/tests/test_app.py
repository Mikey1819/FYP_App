"""Integration checks for the sample workflow, not live server validation."""

from pathlib import Path
from contextlib import closing
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from streamlit.testing.v1 import AppTest
from hardening.demo_storage import load_demo
from hardening.storage import AssessmentStore
from hardening.workflow import WorkflowStore
from hardening.ollama_client import OllamaClient
from hardening.investigation import InvestigationLog


APP = Path(__file__).resolve().parents[1] / "synthetic_demo_app.py"


class DashboardTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / "preview.sqlite3"
        environment = patch.dict(os.environ, {"CIS_DASHBOARD_DB": str(self.database)})
        environment.start()
        self.addCleanup(environment.stop)

    def test_saved_snapshots_survive_new_app_session(self):
        first = AppTest.from_file(str(APP)).run()
        self.assertEqual(len(first.exception), 0)
        second = AppTest.from_file(str(APP)).run()
        self.assertEqual(len(second.exception), 0)
        self.assertTrue(any("SQLite assessment snapshots" in item.value for item in second.caption))
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM assessment_snapshots").fetchone()[0], 2)

    def test_model_outage_preserves_dashboard_and_saved_trace(self):
        with patch.object(OllamaClient, "provenance", "Mock model UI test"), patch.object(OllamaClient, "chat", side_effect=TimeoutError):
            app = AppTest.from_file(str(APP)).run()
            app.button(key="run_investigation").click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("unavailable" in item.value.lower() for item in app.text))
        self.assertTrue(any("40% of evaluated" in item.value for item in app.markdown))
        runs = InvestigationLog(AssessmentStore(self.database)).recent("1042")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["provenance"], "Mock model UI test")
        self.assertEqual(runs[0]["events"][-1]["data"]["status"], "Unavailable")
        app.button(key="run_assessment").click().run()
        self.assertEqual(app.session_state["agent_phase"], "Awaiting Approval")

    def test_unsupported_database_displays_error_and_preserves_data(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("PRAGMA user_version = 99")
        app = AppTest.from_file(str(APP)).run()
        self.assertEqual(len(app.exception), 0)
        self.assertTrue(any("storage unavailable" in item.value for item in app.error))
        with closing(sqlite3.connect(self.database)) as connection, connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 99)

    def test_failed_verification_and_rejection_survive_new_sessions(self):
        app = AppTest.from_file(str(APP)).run()
        app.button(key="run_assessment").click().run()
        first_id = app.session_state["active_proposal_id"]
        app.sidebar.radio[0].set_value("Remediation Review").run()
        app.selectbox(key="simulation_scenario").set_value("Verification failure").run()
        app.text_area(key="review_comment_input").set_value("Failure demonstration").run()
        app.button(key="approve_remediation").click().run()
        self.assertEqual(app.session_state["agent_phase"], "Verification Failed")
        self.assertTrue(any("remains unresolved" in item.value for item in app.error))
        restarted = AppTest.from_file(str(APP)).run()
        self.assertEqual(restarted.session_state["active_proposal_id"], first_id)
        self.assertEqual(restarted.session_state["agent_phase"], "Verification Failed")
        self.assertEqual(restarted.session_state["decision_comment"], "Failure demonstration")
        restarted.sidebar.radio[0].set_value("Remediation Review").run()
        self.assertTrue(restarted.button(key="approve_remediation").disabled)
        restarted.sidebar.radio[0].set_value("Dashboard / Overview").run()
        restarted.button(key="reset_workflow").click().run()
        restarted.button(key="run_assessment").click().run()
        rejected_id = restarted.session_state["active_proposal_id"]
        self.assertNotEqual(rejected_id, first_id)
        restarted.sidebar.radio[0].set_value("Remediation Review").run()
        restarted.button(key="reject_remediation").click().run()
        newest = AppTest.from_file(str(APP)).run()
        self.assertEqual(newest.session_state["agent_phase"], "Rejected")
        store = WorkflowStore(AssessmentStore(self.database))
        self.assertIsNone(store.get(rejected_id).event("attempt"))
        self.assertEqual(len(store.list_for_assessment("1042")), 2)
        newest.sidebar.radio[0].set_value("Configuration Drift / Assessment History").run()
        newest.selectbox(key="saved_proposal").set_value(first_id).run()
        newest.button(key="open_saved_proposal").click().run()
        self.assertEqual(newest.session_state["agent_phase"], "Verification Failed")
        self.assertTrue(newest.button(key="approve_remediation").disabled)
        self.assertEqual(len(newest.exception), 0)

    def test_approved_but_unstarted_proposal_can_be_executed_once(self):
        assessments = AssessmentStore(self.database)
        load_demo(assessments)
        workflows = WorkflowStore(assessments)
        proposal = workflows.create_proposal(assessment_id="1042", target_id="DEMO-SERVER-2022",
                    control_id="DEMO-NLA", action_id="DEMO-ENABLE-NLA", parameters={"required": True}, reason="Test")
        workflows.decide(proposal.proposal_id, binding=proposal.binding, approved=True, actor="demo-admin")
        app = AppTest.from_file(str(APP)).run()
        app.sidebar.radio[0].set_value("Remediation Review").run()
        self.assertEqual(app.session_state["agent_phase"], "Approved")
        app.button(key="resume_approved").click().run()
        self.assertEqual(app.session_state["agent_phase"], "Verification Passed")
        self.assertFalse(any(button.key == "resume_approved" for button in app.button))
        restarted = AppTest.from_file(str(APP)).run()
        self.assertEqual(restarted.session_state["agent_phase"], "Verification Passed")
        self.assertEqual(len(restarted.exception), 0)

    def test_views_filters_and_review_comments(self):
        app = AppTest.from_file(str(APP), default_timeout=20).run()
        self.assertEqual(len(app.exception), 0)
        pages = list(app.sidebar.radio[0].options)
        for page in pages:
            app.sidebar.radio[0].set_value(page).run()
            self.assertEqual(len(app.exception), 0, page)
        app.sidebar.radio[0].set_value("Remediation Review").run()
        self.assertTrue(app.button(key="approve_remediation").disabled)
        app.sidebar.radio[0].set_value("Assessment Results").run()
        for selection in app.selectbox[0].options:
            app.selectbox[0].set_value(selection).run()
            self.assertEqual(len(app.exception), 0)
        app.sidebar.radio[0].set_value("Risk Findings / Risk Details").run()
        app.selectbox[0].set_value("DEMO-LOCKOUT").run()
        self.assertTrue(any("Risk score: <strong>70" in item.value for item in app.markdown))

        app.sidebar.radio[0].set_value(pages[0]).run()
        app.button(key="run_assessment").click().run()
        self.assertEqual(app.session_state["agent_phase"], "Awaiting Approval")
        app.sidebar.radio[0].set_value("Remediation Review").run()
        comment = 'Approved in simulation only <script>alert("x")</script>'
        app.text_area(key="review_comment_input").set_value(comment).run()
        app.button(key="approve_remediation").click().run()
        self.assertEqual(len(app.exception), 0)
        self.assertEqual(app.session_state["agent_phase"], "Verification Passed")
        self.assertEqual(app.session_state["decision_comment"], comment)
        self.assertTrue(any(comment in item.value for item in app.text))
        app.sidebar.radio[0].set_value("Remediation Review").run()
        self.assertTrue(app.button(key="approve_remediation").disabled)
        app.sidebar.radio[0].set_value(pages[0]).run()
        self.assertTrue(any("original snapshot" in item.value.lower() for item in app.success))
        self.assertTrue(any("40% of evaluated" in item.value for item in app.markdown))
        app.button(key="reset_workflow").click().run()
        app.button(key="run_assessment").click().run()
        app.sidebar.radio[0].set_value("Remediation Review").run()
        app.text_area(key="review_comment_input").set_value("Defer until maintenance").run()
        app.button(key="reject_remediation").click().run()
        self.assertEqual(app.session_state["agent_phase"], "Rejected")
        self.assertEqual(app.session_state["decision_comment"], "Defer until maintenance")
        self.assertFalse(any(event["State"] == "Executed" for event in app.session_state["agent_events"]))
        self.assertTrue(app.button(key="approve_remediation").disabled)
        self.assertEqual(len(app.exception), 0)


if __name__ == "__main__":
    unittest.main()
