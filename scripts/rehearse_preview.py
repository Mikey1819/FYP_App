"""Timed Streamlit rehearsal: real local model, synthetic evidence/execution only.

Creates a new database and incremental JSON evidence for every invocation. This
exercises UI callbacks via AppTest; it is not browser layout or human timing QA.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "cis_compliance_dashboard_prototype"
sys.path.insert(0, str(APP_DIR))

from streamlit.testing.v1 import AppTest
from hardening.demo import CURRENT_RESULTS
from hardening.investigation import InvestigationLog
from hardening.ollama_client import OllamaClient
from hardening.storage import AssessmentStore
from hardening.workflow import WorkflowStore


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def healthy(app):
    require(not app.exception, "Dashboard exception: " + str([error.value for error in app.exception]))


def open_app():
    app = AppTest.from_file(str(APP_DIR / "app.py"), default_timeout=260).run()
    healthy(app)
    return app


def navigate(app, page):
    app.sidebar.radio[0].set_value(page).run()
    healthy(app)


def restart_check(report_path):
    report = json.loads(report_path.read_text(encoding="utf-8"))
    with patch.dict(os.environ, {"CIS_DASHBOARD_DB": report["database"]}):
        app = open_app()
        require(app.session_state["agent_phase"] == "Verification Failed", "Restart lost failed verification")
        require(app.session_state["decision_comment"] == "Rehearsal: failed read-back", "Restart lost comment")
        for page in app.sidebar.radio[0].options:
            navigate(app, page)
        store = AssessmentStore(report["database"])
        require(store.get("1042").results == CURRENT_RESULTS, "Original snapshot changed")
    print(json.dumps({"restart": "passed", "views": 6, "original_snapshot": "preserved"}), flush=True)


def rehearse():
    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d_%H%M%S")
    directory = APP_DIR / "data" / "rehearsals" / f"{stamp}_{uuid.uuid4().hex[:8]}"
    directory.mkdir(parents=True, exist_ok=False)
    database = directory / "preview.sqlite3"
    report_path = directory / "rehearsal.json"
    report = {"started_at": datetime.now(timezone(timedelta(hours=8))).isoformat(),
              "database": str(database), "method": "Streamlit AppTest with real local Ollama",
              "evidence_mode": "Synthetic", "execution_mode": "Simulated",
              "status": "Running", "steps": [], "investigations": []}
    started = time.monotonic()

    def save():
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        temporary = report_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2), encoding="utf-8")
        temporary.replace(report_path)

    @contextmanager
    def step(name):
        entry = {"name": name, "status": "Running"}
        report["steps"].append(entry)
        save()
        print("START " + name, flush=True)
        step_started = time.monotonic()
        try:
            yield entry
            entry["status"] = "Passed"
        except Exception as error:
            entry["status"] = "Failed"
            entry["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            entry["seconds"] = round(time.monotonic() - step_started, 3)
            save()
            print(json.dumps(entry), flush=True)

    print("REHEARSAL_REPORT " + str(report_path), flush=True)
    try:
        with patch.dict(os.environ, {"CIS_DASHBOARD_DB": str(database)}):
            with step("Launch, six views and deterministic risk"):
                app = open_app()
                for page in app.sidebar.radio[0].options:
                    navigate(app, page)
                navigate(app, "Risk Findings / Risk Details")
                app.selectbox[0].set_value("DEMO-LOCKOUT").run()
                require(any("Risk score: <strong>70" in item.value for item in app.markdown), "Lockout score not shown")
                navigate(app, "Dashboard / Overview")
                require(any("40% of evaluated" in item.value for item in app.markdown), "Original compliance not shown")
                store = AssessmentStore(database)
                workflows = WorkflowStore(store)
                log = InvestigationLog(store)

            proposal_id = None
            for scenario in ("compatible_clients", "legacy_clients"):
                with step("Real model through UI: " + scenario) as entry:
                    app.selectbox(key="investigation_scenario").set_value(scenario).run()
                    app.button(key="run_investigation").click().run(timeout=260)
                    healthy(app)
                    run = log.recent("1042")[0]
                    result = run["events"][-1]["data"]
                    report["investigations"].append(run)
                    entry.update(run_id=run["run_id"], model_seconds=result["duration_seconds"],
                                 tools=[e["data"]["name"] for e in run["events"] if e["kind"] == "tool"])
                    require(run["provenance"] == "Local Ollama", "Expected actual local model provenance")
                    require(result["status"] == "Completed", "Model run did not complete: " + result["status"])
                    require(app.selectbox(key="saved_investigation").value == run["run_id"], "UI selected an older trace")
                    if scenario == "compatible_clients":
                        proposal_id = result["proposal_id"]
                        require(proposal_id is not None, "Compatible case produced no proposal")
                        require(workflows.get(proposal_id).event("attempt") is None, "Model caused execution")
                    else:
                        require(result["proposal_id"] is None, "Legacy case produced a proposal")
            paths = [entry["tools"] for entry in report["steps"] if "tools" in entry]
            require(paths[0] != paths[1], "Two scenarios did not choose different tool paths")

            with step("Reject model-prepared proposal with zero executor calls"):
                navigate(app, "Remediation Review")
                require(app.session_state["active_proposal_id"] == proposal_id, "Wrong proposal selected")
                app.text_area(key="review_comment_input").set_value("Rehearsal: reject this action").run()
                app.button(key="reject_remediation").click().run()
                healthy(app)
                rejected = workflows.get(proposal_id)
                require(rejected.phase == "Rejected" and rejected.event("attempt") is None, "Rejection dispatched an attempt")

            for scenario, expected in (("Successful verification", "Verification Passed"),
                                       ("Verification failure", "Verification Failed")):
                with step("Simulated action: " + scenario):
                    navigate(app, "Dashboard / Overview")
                    app.button(key="reset_workflow").click().run()
                    app.button(key="run_assessment").click().run()
                    navigate(app, "Remediation Review")
                    app.selectbox(key="simulation_scenario").set_value(scenario).run()
                    comment = "Rehearsal: approved synthetic action" if expected == "Verification Passed" else "Rehearsal: failed read-back"
                    app.text_area(key="review_comment_input").set_value(comment).run()
                    app.button(key="approve_remediation").click().run()
                    healthy(app)
                    require(app.session_state["agent_phase"] == expected, "Unexpected verification outcome")
                    state = workflows.get(app.session_state["active_proposal_id"])
                    require(state.event("execution")["payload"]["success"], "Expected successful simulated execution")
                    require(state.event("verification") is not None, "Independent verification missing")
                    require(store.get("1042").results == CURRENT_RESULTS, "Historical snapshot overwritten")
                    navigate(app, "Remediation Review")
                    require(app.button(key="approve_remediation").disabled, "Repeat approval is enabled")

            with step("History and actual new-process restart") as entry:
                navigate(app, "Configuration Drift / Assessment History")
                require(len(workflows.list_for_assessment("1042")) == 3, "Audit history missing an attempt")
                child = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
                                        "--verify-restart", str(report_path)],
                                       capture_output=True, text=True, timeout=45, check=True)
                entry["restart_result"] = json.loads(child.stdout.strip().splitlines()[-1])

            with step("Injected model outage and explicit previous-run fallback"):
                navigate(app, "Dashboard / Overview")
                with patch.object(OllamaClient, "provenance", "Mock outage (rehearsal only)"), patch.object(OllamaClient, "chat", side_effect=TimeoutError):
                    app.button(key="run_investigation").click().run()
                healthy(app)
                require(log.recent("1042")[0]["events"][-1]["data"]["status"] == "Unavailable", "Outage was hidden")
                require(any("40% of evaluated" in item.value for item in app.markdown), "Outage removed assessment")
                previous_run = report["investigations"][0]["run_id"]
                app.selectbox(key="saved_investigation").set_value(previous_run).run()
                require(app.selectbox(key="saved_investigation").value == previous_run, "Cannot open previous trace")
                healthy(app)
            report["status"] = "Passed"
    except Exception as error:
        report["status"] = "Failed"
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        report["finished_at"] = datetime.now(timezone(timedelta(hours=8))).isoformat()
        save()
    print(json.dumps({"status": report["status"], "seconds": report["elapsed_seconds"], "report": str(report_path)}), flush=True)
    return 0 if report["status"] == "Passed" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live-model", action="store_true", help="Explicitly make real local Ollama calls")
    parser.add_argument("--verify-restart", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.verify_restart:
        restart_check(arguments.verify_restart)
    elif arguments.live_model:
        raise SystemExit(rehearse())
    else:
        parser.error("Pass --live-model to run the real local model rehearsal")
