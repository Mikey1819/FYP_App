"""CIS Compliance Dashboard - synthetic assessment demonstration.

This application evaluates typed synthetic evidence using deterministic domain rules.
SQLite preserves synthetic assessment snapshots. It does not execute PowerShell or call an LLM.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from html import escape

from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo import TARGET_ID, PROFILE, display_value
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo_storage import load_demo
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.storage import AssessmentStore
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.workflow import WorkflowStore, NlaSimulator
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.investigation import Coordinator, InvestigationLog
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.investigation_tools import InvestigationTools
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.ollama_client import OllamaClient
from window_cis_compliance_dashboard_prototype.cis_compliance_dashboard_prototype.hardening.demo_context import DEVICE_CONTEXT

import streamlit as st


st.set_page_config(
    page_title="CIS Compliance Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


INITIAL_AGENT_EVENTS = [
    {
        "Time": "—",
        "Component": "Workflow simulator",
        "Activity": "Saved synthetic assessment ready for a proposal",
        "State": "Ready to Scan",
    }
]


def init_session_state() -> None:
    """Restore the latest durable proposal when opening a new browser session."""
    st.session_state.setdefault("agent_phase", "Ready to Scan")
    st.session_state.setdefault("agent_events", INITIAL_AGENT_EVENTS.copy())
    st.session_state.setdefault("remediation_decision", None)
    st.session_state.setdefault("decision_comment", "")
    st.session_state.setdefault("navigation", "Dashboard / Overview")
    if "active_proposal_id" not in st.session_state:
        saved = WORKFLOWS.list_for_assessment("1042")
        st.session_state["active_proposal_id"] = saved[0].proposal.proposal_id if saved else None
    sync_saved_workflow()


def request_navigation(page: str) -> None:
    """Navigate safely on the next rerun, before the sidebar radio is created."""
    st.session_state["requested_page"] = page
    st.rerun()


def sync_saved_workflow() -> None:
    proposal_id = st.session_state.get("active_proposal_id")
    if not proposal_id:
        return
    state = WORKFLOWS.get(proposal_id)
    st.session_state["agent_phase"] = state.phase
    decision = state.event("decision")
    st.session_state["remediation_decision"] = (
        "Approved" if decision["payload"]["approved"] else "Rejected"
    ) if decision else None
    st.session_state["decision_comment"] = decision["payload"]["comment"] if decision else ""
    events = [{"Time": state.proposal.created_at, "Component": "Workflow service",
               "Activity": "Saved synthetic NLA proposal for assessment 1042", "State": "Awaiting Approval"}]
    for event in state.events:
        kind, payload = event["kind"], event["payload"]
        if kind == "decision":
            label = "Approved" if payload["approved"] else "Rejected"
            activity = f"{payload['actor']}: {label} this exact simulated action"
        elif kind == "attempt":
            label, activity = "Claimed", "Approval consumed for one simulated execution attempt"
        elif kind == "execution":
            label = "Executed" if payload["success"] else "Execution Failed"
            activity = payload["detail"]
        else:
            label, activity = payload["status"], "Separate synthetic read-back evaluated against the original rule"
        events.append({"Time": event["created_at"], "Component": "Administrator" if kind == "decision" else "Simulation service",
                       "Activity": activity, "State": label})
    st.session_state["agent_events"] = events


def run_sample_assessment() -> None:
    """Prepare a proposal from the saved fixture; this does not run a new scan."""
    proposal = WORKFLOWS.create_proposal(
        assessment_id="1042", target_id=TARGET_ID, control_id="DEMO-NLA",
        action_id="DEMO-ENABLE-NLA", parameters={"required": True},
        reason="Synthetic assessment 1042 does not require NLA. Demonstrate one approved change and independent read-back.",
    )
    st.session_state["active_proposal_id"] = proposal.proposal_id
    st.session_state.pop("review_comment_input", None)
    sync_saved_workflow()


def run_approved_simulation() -> None:
    state = WORKFLOWS.get(st.session_state["active_proposal_id"])
    scenario = st.session_state.get("simulation_scenario", "Successful verification")
    simulator = NlaSimulator(
        apply_change=scenario != "Verification failure",
        fail_execution=scenario == "Execution failure",
        fail_collection=scenario == "Collection error",
    )
    WORKFLOWS.execute_simulated(state.proposal.proposal_id, binding=state.proposal.binding, simulator=simulator)
    sync_saved_workflow()


def approve_sample_remediation(comment: str = "") -> None:
    state = WORKFLOWS.get(st.session_state["active_proposal_id"])
    WORKFLOWS.decide(state.proposal.proposal_id, binding=state.proposal.binding,
                     approved=True, actor="demo-admin", comment=comment)
    run_approved_simulation()


def reject_sample_remediation(comment: str = "") -> None:
    state = WORKFLOWS.get(st.session_state["active_proposal_id"])
    WORKFLOWS.decide(state.proposal.proposal_id, binding=state.proposal.binding,
                     approved=False, actor="demo-admin", comment=comment)
    sync_saved_workflow()


def reset_sample_workflow() -> None:
    # Clear only the current view. Saved decisions/attempts are never erased.
    st.session_state["active_proposal_id"] = None
    st.session_state["agent_phase"] = "Ready to Scan"
    st.session_state["agent_events"] = INITIAL_AGENT_EVENTS.copy()
    st.session_state["remediation_decision"] = None
    st.session_state["decision_comment"] = ""
    st.session_state.pop("review_comment_input", None)
    st.session_state.pop("simulation_scenario", None)


def inject_css() -> None:
    st.markdown(
        """
        <style>
        :root { color-scheme: dark; }
        .stApp { background: #09111f; color: #e6edf7; }
        [data-testid="stHeader"] { background: rgba(9, 17, 31, 0.92); }
        section[data-testid="stSidebar"] {
            background: linear-gradient(180deg, #0b1728 0%, #0a1322 100%);
            border-right: 1px solid #20314a;
        }
        section[data-testid="stSidebar"] .stMarkdown, section[data-testid="stSidebar"] p { color: #d7e3f4; }
        [data-testid="stSidebarNav"] { display: none; }
        .block-container { max-width: 1460px; padding-top: 3.9rem; padding-bottom: 2rem; }
        h1, h2, h3 { color: #f8fbff !important; letter-spacing: -0.02em; }
        h1 { font-size: 2rem !important; margin-bottom: 0.1rem !important; }
        h2 { font-size: 1.15rem !important; margin-top: 1.65rem !important; }
        h3 { font-size: 0.96rem !important; }
        .muted { color: #93a6c3; font-size: 0.91rem; margin: 0.12rem 0 1rem; }
        .prototype-banner {
            border: 1px solid #1d4f81; background: #0b2745; color: #c9e7ff;
            padding: 0.6rem 0.85rem; border-radius: 8px; font-weight: 600;
            font-size: 0.88rem; margin-bottom: 1.25rem;
        }
        .scope-label { color: #a9b9cf; font-size: 0.85rem; margin-top: 0.35rem; }
        .kpi-card {
            background: linear-gradient(145deg, #111f34, #0d192b); border: 1px solid #233954;
            border-radius: 10px; padding: 0.9rem 1rem; min-height: 92px;
        }
        .kpi-label { color: #9cafc9; font-size: 0.76rem; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; }
        .kpi-value { color: #f7fbff; font-size: 1.65rem; line-height: 1.2; font-weight: 760; margin-top: 0.24rem; }
        .kpi-note { color: #7890b2; font-size: 0.76rem; margin-top: 0.25rem; }
        .section-card { background: #0e1a2b; border: 1px solid #203550; border-radius: 10px; padding: 1rem 1.1rem; margin-bottom: 0.9rem; }
        .badge { display: inline-block; border-radius: 99px; padding: 0.19rem 0.55rem; font-size: 0.76rem; font-weight: 750; white-space: nowrap; }
        .badge-good { background: #123b35; color: #70e6bd; border: 1px solid #246c5d; }
        .badge-issue { background: #3d2d10; color: #ffd275; border: 1px solid #765318; }
        .badge-critical { background: #36204e; color: #e0bdff; border: 1px solid #784ba5; }
        .badge-high { background: #3c2715; color: #ffbd82; border: 1px solid #874c1f; }
        .badge-moderate, .badge-info { background: #102f53; color: #8ed0ff; border: 1px solid #2e6596; }
        .badge-completed { background: #123b35; color: #70e6bd; border: 1px solid #246c5d; }
        table { width: 100%; border-collapse: separate; border-spacing: 0; font-size: 0.83rem; overflow: hidden; border: 1px solid #243752; border-radius: 8px; }
        th { background: #14243b; color: #adc0dc; text-align: left; font-size: 0.71rem; letter-spacing: 0.045em; text-transform: uppercase; padding: 0.58rem 0.65rem; }
        td { background: #0e1a2b; color: #e2ebf8; padding: 0.58rem 0.65rem; border-top: 1px solid #1b2c44; vertical-align: middle; }
        tr:hover td { background: #11213a; }
        .formula { background: #0b2038; color: #c2dcf7; border-left: 3px solid #3b9eea; border-radius: 6px; padding: 0.65rem 0.8rem; font-family: Consolas, monospace; font-size: 0.85rem; margin: 0.75rem 0 1rem; }
        .factor-card { background: #101e31; border: 1px solid #263b58; border-radius: 9px; padding: 0.75rem 0.85rem; min-height: 78px; }
        .factor-name { color: #9fb4d1; font-size: 0.76rem; font-weight: 650; }
        .factor-value { color: #f8fbff; font-size: 1.5rem; font-weight: 750; padding-top: 0.15rem; }
        .detail-label { color: #8fa4c2; font-size: 0.76rem; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase; }
        .detail-value { color: #ecf3fd; font-size: 0.96rem; margin: 0.13rem 0 0.7rem; }
        .sidebar-brand { font-size: 1.05rem; color: #f6f9ff; font-weight: 800; line-height: 1.2; margin-bottom: 0.45rem; }
        .sidebar-subtitle { color: #8fa7c9; font-size: 0.75rem; margin-bottom: 1.25rem; }
        .sidebar-footer { color: #8296b6; font-size: 0.73rem; border-top: 1px solid #223650; padding-top: 1rem; margin-top: 1.2rem; line-height: 1.55; }
        div[data-testid="stRadio"] label { border-radius: 7px; padding: 0.28rem 0.35rem; margin: 0.03rem 0; }
        div[data-testid="stRadio"] label:hover { background: #162942; }
        div[data-testid="stRadio"] p { font-size: 0.84rem; }
        [data-testid="stBaseButton-primary"] { background: #168a69 !important; border-color: #168a69 !important; color: #fff !important; }
        [data-testid="stBaseButton-primary"]:hover { background: #20a97f !important; border-color: #20a97f !important; }
        button[kind="secondary"] { color: #ff9c9c !important; border-color: #a84141 !important; background: #241619 !important; }
        button[kind="secondary"]:hover { background: #3a1c22 !important; border-color: #e35b5b !important; }
        .stAlert { border-radius: 8px; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def badge(text: str) -> str:
    styles = {
        "Compliant": "badge-good",
        "Non-Compliant": "badge-issue",
        "Critical": "badge-critical",
        "High": "badge-high",
        "Moderate": "badge-moderate",
        "Awaiting Approval": "badge-info",
        "Completed": "badge-completed",
        "Executed": "badge-info",
        "Passed": "badge-good",
        "Ready to Scan": "badge-info",
        "Scanning": "badge-info",
        "Risk Prioritisation": "badge-info",
        "Approved": "badge-good",
        "Rejected": "badge-issue",
        "Verification Passed": "badge-good",
    }
    return f'<span class="badge {styles.get(text, "badge-info")}">{escape(text)}</span>'


def metric_card(label: str, value: str, note: str = "") -> str:
    return f"""
    <div class="kpi-card">
      <div class="kpi-label">{escape(label)}</div>
      <div class="kpi-value">{escape(value)}</div>
      <div class="kpi-note">{escape(note)}</div>
    </div>
    """


def html_table(rows: list[dict[str, str]], columns: list[str], badge_columns: set[str] | None = None) -> None:
    badge_columns = badge_columns or set()
    headers = "".join(f"<th>{escape(column)}</th>" for column in columns)
    body = []
    for row in rows:
        cells = []
        for column in columns:
            value = str(row[column])
            cells.append(f"<td>{badge(value) if column in badge_columns else escape(value)}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    st.markdown(f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(body)}</tbody></table>", unsafe_allow_html=True)


def render_page_intro(title: str, subtitle: str) -> None:
    st.markdown('<div class="prototype-banner">Synthetic evidence · demo rules not yet benchmark-validated.</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<div class="muted">{escape(subtitle)}</div>', unsafe_allow_html=True)
    st.caption(f"Target: {TARGET_ID} · {PROFILE} · Backend: SQLite assessment snapshots · LLM: local qwen3:8b, invoked only on request")
    st.caption(f"Evidence coverage: {SUMMARY.evaluated}/{SUMMARY.selected} evaluated · {SUMMARY.errors} errors · {SUMMARY.unknown} unknown. Final project catalogue: 36 planned controls.")


def detail_item(label: str, value: str) -> None:
    st.markdown(f'<div class="detail-label">{escape(label)}</div><div class="detail-value">{escape(value)}</div>', unsafe_allow_html=True)


def render_agent_activity(show_heading: bool = True) -> None:
    if show_heading:
        st.header("Simulation activity")
    phase = st.session_state["agent_phase"]
    st.markdown(
        f'<div class="formula">Workflow simulator state: {badge(phase)}</div>',
        unsafe_allow_html=True,
    )
    html_table(
        st.session_state["agent_events"],
        ["Time", "Component", "Activity", "State"],
        {"State"},
    )


def render_current_device_situation() -> None:
    """Describe the sample target's present posture without claiming a live scan."""
    context = DEVICE_CONTEXT["DEMO-NLA"]
    st.header("Current device situation")
    st.caption("Representative interpretation of the sample assessment only. It is not a live diagnosis of this device.")
    target, posture, urgent = st.columns(3)
    with target:
        st.markdown(metric_card("Sample target", "Server 2022", "CIS hardening scope"), unsafe_allow_html=True)
    with posture:
        st.markdown(metric_card("Original snapshot", f"{SUMMARY.non_compliant} / {SUMMARY.selected}", "Sample controls non-compliant"), unsafe_allow_html=True)
    with urgent:
        st.markdown(metric_card("Immediate concern", "RDP / NLA", "DEMO-NLA · Critical"), unsafe_allow_html=True)
    st.markdown(
        f'<div class="section-card"><div class="detail-label">What is happening in this sample</div><div class="detail-value">{context["condition"]}</div><div class="detail-label">Why the administrator should care</div><div class="detail-value">{context["meaning"]}</div></div>',
        unsafe_allow_html=True,
    )


def render_decision_support(control_id: str) -> None:
    """Present fixed, safe decision context for the selected representative finding."""
    context = DEVICE_CONTEXT[control_id]
    st.header("Device security context and decision support")
    st.caption("Representative guidance derived from the displayed sample data. It does not inspect or modify the user’s actual device.")
    st.markdown(
        f'<div class="section-card"><div class="detail-label">Current simulated condition</div><div class="detail-value">{context["condition"]}</div><div class="detail-label">What this weakness can mean</div><div class="detail-value">{context["meaning"]}</div></div>',
        unsafe_allow_html=True,
    )
    decision_column, approve_column, defer_column = st.columns(3)
    with decision_column:
        st.markdown("#### Suggested decision")
        st.info(context["decision"])
    with approve_column:
        st.markdown("#### If approved")
        st.success(context["approve_outcome"])
    with defer_column:
        st.markdown("#### If rejected or delayed")
        st.warning(context["defer_outcome"])


def render_overview() -> None:
    render_page_intro("Dashboard / Overview", "Executive security posture for the latest Windows Server 2022 assessment.")
    columns = st.columns(5)
    values = [
        ("Assessment", "1042", "Original synthetic snapshot"),
        ("Evaluated / selected", f"{SUMMARY.evaluated} / {SUMMARY.selected}", "Evidence coverage"),
        ("Sample compliant", f"{SUMMARY.compliant} / {SUMMARY.evaluated}", f"{SUMMARY.compliance_percent:.0f}% of evaluated controls" if SUMMARY.compliance_percent is not None else "No evaluated evidence"),
        ("Non-compliant", str(SUMMARY.non_compliant), "Original assessment"),
        ("Highest risk", str(max((r['score'] for r in RISKS.values()), default=0)), "Project-defined demo score"),
    ]
    for column, data in zip(columns, values):
        with column:
            st.markdown(metric_card(*data), unsafe_allow_html=True)

    render_current_device_situation()
    st.caption("This view preserves the original assessment. A later verification is shown separately and does not rewrite its history.")
    if st.session_state["agent_phase"] == "Verification Passed":
        st.success("Later simulated verification: DEMO-NLA passed. The original snapshot below still records its earlier non-compliance.")

    st.header("Workflow simulation")
    phase = st.session_state["agent_phase"]
    action_column, summary_column, reset_column = st.columns([0.28, 0.52, 0.20])
    with action_column:
        if phase == "Ready to Scan":
            if st.button("Run sample assessment", type="primary", use_container_width=True, key="run_assessment"):
                run_sample_assessment()
                phase = st.session_state["agent_phase"]
        elif phase == "Awaiting Approval":
            if st.button("Review remediation", type="primary", use_container_width=True, key="review_remediation"):
                request_navigation("Remediation Review")
        else:
            if st.button("View saved workflow", use_container_width=True, key="workflow_complete"):
                request_navigation("Remediation Review")
    with summary_column:
        if phase == "Ready to Scan":
            st.info("Use the five saved synthetic results to prepare a remediation proposal. This does not run a fresh scan or call the model.")
        elif phase == "Awaiting Approval":
            st.warning("The proposal uses saved assessment 1042. DEMO-NLA is waiting for an administrator decision; no remediation has been executed.")
        elif phase == "Verification Passed":
            st.success("The selected sample action has been verified. Review its saved result or start a new demonstration.")
        elif phase == "Rejected":
            st.info("The proposed remediation was rejected. No configuration change was simulated.")
        else:
            st.warning(f"Saved workflow: {phase}. Review the recorded attempt before preparing another proposal.")
    with reset_column:
        if phase != "Ready to Scan" and st.button("New demonstration", use_container_width=True, key="reset_workflow"):
            reset_sample_workflow()
            st.rerun()
    render_agent_activity()
    render_investigation()

    left, right = st.columns([1.24, 0.76], gap="large")
    with left:
        st.header("Assessment information")
        info = [
            {"Field": "Assessment ID", "Value": "1042"},
            {"Field": "Initiated by", "Value": "demo-admin"},
            {"Field": "Start time", "Value": "2026-08-12 09:15:00"},
            {"Field": "End time", "Value": "2026-08-12 09:18:42"},
            {"Field": "Snapshot status", "Value": "Completed synthetic assessment"},
            {"Field": "Workflow simulation", "Value": st.session_state["agent_phase"]},
        ]
        html_table(info, ["Field", "Value"])
    with right:
        st.header("Risk distribution")
        distribution = [
            {"Risk level": level, "Findings": str(sum(r["level"] == level for r in RISKS.values())), "Focus": focus}
            for level, focus in (("Critical", "Immediate"), ("High", "Prioritised"), ("Moderate", "Planned"), ("Low", "Routine"))
        ]
        html_table(distribution, ["Risk level", "Findings", "Focus"], {"Risk level"})
        st.markdown(f'<div class="formula">{len(RISKS)} non-compliant findings are prioritised for review.</div>', unsafe_allow_html=True)

    st.header("Assessment snapshot")
    snapshot = [{"Control": c["id"], "Control title": c["title"], "Status": c["status"]} for c in CONTROLS]
    html_table(snapshot, ["Control", "Control title", "Status"], {"Status"})


def render_investigation() -> None:
    st.header("Local AI investigation")
    st.caption("The model chooses investigative tools over saved synthetic evidence. It cannot approve or execute a change. Limits: 8 model steps, 10 tool calls, 90 seconds per request, 240 seconds total.")
    scenario = st.selectbox("Synthetic client context", ["compatible_clients", "legacy_clients"],
                            format_func=lambda value: "Compatible RDP clients" if value == "compatible_clients" else "Legacy clients need operational review",
                            key="investigation_scenario")
    if st.button("Investigate with local Ollama", key="run_investigation"):
        with st.spinner("Local model investigating saved evidence; the first call may load the model..."):
            run = Coordinator(OllamaClient(), InvestigationTools(WORKFLOWS.assessments, "1042", scenario=scenario)).run()
        proposal_id = run["events"][-1]["data"].get("proposal_id")
        if proposal_id:
            st.session_state["active_proposal_id"] = proposal_id
            st.session_state.pop("review_comment_input", None)
            sync_saved_workflow()
        st.session_state["saved_investigation"] = run["run_id"]
        st.rerun()
    runs = InvestigationLog(WORKFLOWS.assessments).recent("1042")
    if not runs:
        st.info("No model investigation has run in this database. Assessment and manual demonstration remain available.")
        return
    selected = st.selectbox("Saved investigation", [run["run_id"] for run in runs], key="saved_investigation")
    run = next(run for run in runs if run["run_id"] == selected)
    st.caption(f"{run['provenance']} · {run['model']} · {run['scenario']} · started {run['created_at']}")
    finished = next((event["data"] for event in reversed(run["events"]) if event["kind"] == "finished"), None)
    if finished:
        st.text(f"{finished['status']} | {finished['duration_seconds']} seconds | {finished['tool_calls']} requested tool calls")
        st.text(finished["summary"])
        if finished["status"] != "Completed":
            st.warning("Investigation did not complete normally. Stored assessment results and deterministic risk scores remain available.")
        if finished.get("proposal_id") and st.button("Review AI-prepared proposal", key="review_ai_proposal"):
            st.session_state["active_proposal_id"] = finished["proposal_id"]
            st.session_state.pop("review_comment_input", None)
            request_navigation("Remediation Review")
    else:
        st.warning("This saved investigation has no completion record; it may have been interrupted. It is not resumed automatically.")
    with st.expander("Saved tool evidence and decisions"):
        for event in run["events"]:
            if event["kind"] in ("tool", "tool_rejected"):
                st.caption(f"{event['created_at']} · {event['kind']}")
                st.json(event["data"])


def render_results() -> None:
    render_page_intro("Assessment Results", "Detailed evidence captured for assessment 1042.")
    filter_col, summary_col = st.columns([0.62, 0.38])
    with filter_col:
        selected_filter = st.selectbox("Show controls", ["All sample controls", "Non-Compliant only", "Compliant only", "Error / Unknown only"], label_visibility="collapsed")
    with summary_col:
        st.markdown(f'<div class="formula">Original snapshot 1042 · {SUMMARY.compliant} Compliant · {SUMMARY.non_compliant} Non-Compliant · {SUMMARY.errors} Error · {SUMMARY.unknown} Unknown</div>', unsafe_allow_html=True)

    filtered = CONTROLS
    if selected_filter == "Non-Compliant only":
        filtered = [control for control in CONTROLS if control["status"] == "Non-Compliant"]
    elif selected_filter == "Compliant only":
        filtered = [control for control in CONTROLS if control["status"] == "Compliant"]
    elif selected_filter == "Error / Unknown only":
        filtered = [control for control in CONTROLS if control["status"] in ("Error", "Unknown")]
    rows = [
        {
            "Control": item["id"],
            "Control title": item["title"],
            "Observed value": item["observed"],
            "Expected value": item["expected"],
            "Compliance": item["status"],
            "Assessed at": item["assessed_at"],
        }
        for item in filtered
    ]
    html_table(rows, ["Control", "Control title", "Observed value", "Expected value", "Compliance", "Assessed at"], {"Compliance"})
    st.info("All evidence comes from built-in fixtures. These demo comparisons are not a verified CIS assessment.")
    with st.expander("Candidate benchmark references and evidence provenance"):
        for item in CONTROLS:
            st.write(f"{item['id']}: {item['reference']}")
            st.caption(item["source"])


def render_risk() -> None:
    render_page_intro("Risk Findings / Risk Details", "Deterministic prioritisation for non-compliant controls.")
    risk_rows = [
        {"Control": control_id, "Control title": data["title"], "Risk score": str(data["score"]), "Risk level": data["level"]}
        for control_id, data in RISKS.items()
    ]
    html_table(risk_rows, ["Control", "Control title", "Risk score", "Risk level"], {"Risk level"})

    selected = st.selectbox(
        "Finding detail",
        list(RISKS),
        format_func=lambda control_id: f"{control_id} — {RISKS[control_id]['title']}",
    )
    risk = RISKS[selected]
    calculated_score = risk["score"]

    st.markdown(f"### {selected} — {risk['title']}")
    st.markdown(f"Risk score: <strong>{calculated_score}</strong> &nbsp;&nbsp; {badge(risk['level'])}", unsafe_allow_html=True)
    st.markdown(
        f'<div class="formula">R = (I × 6) + (E × 5) + (P × 4) + (L × 3) + (D × 2) = {calculated_score}</div>',
        unsafe_allow_html=True,
    )
    factor_labels = {
        "I": "Impact (I)",
        "E": "Exposure (E)",
        "P": "Privilege impact (P)",
        "L": "Likelihood (L)",
        "D": "Drift (D)",
    }
    factor_columns = st.columns(5)
    for column, factor in zip(factor_columns, ["I", "E", "P", "L", "D"]):
        with column:
            st.markdown(
                f'<div class="factor-card"><div class="factor-name">{factor_labels[factor]}</div><div class="factor-value">{risk["factors"][factor]}</div></div>',
                unsafe_allow_html=True,
            )
    st.markdown("### Supporting explanation")
    st.info(risk["explanation"])
    st.caption("Risk service supporting explanation — simulated prototype content; no local LLM call is made.")
    st.caption("I/P/L baselines and E exposure are illustrative inputs. D is derived from the compatible synthetic history. Scores are project-defined, not CIS or CVSS scores.")
    render_decision_support(selected)


def render_remediation() -> None:
    render_page_intro("Remediation Review", "Human approval checkpoint before a proposed configuration change.")
    phase = st.session_state["agent_phase"]
    decision_available = phase == "Awaiting Approval"
    left, right = st.columns([0.66, 0.34], gap="large")
    with left:
        st.header("Finding information")
        detail_item("Control", "DEMO-NLA — Remote Desktop network authentication")
        detail_item("Risk", f"Score {RISKS['DEMO-NLA']['score']} · {RISKS['DEMO-NLA']['level']}")
        st.header("Proposed remediation")
        detail_item("Proposed action", "Enable Network Level Authentication for Remote Desktop.")
        detail_item("Script reference", "DEMO-ENABLE-NLA")
        detail_item("Current simulation state", phase)
        if st.session_state.get("active_proposal_id"):
            proposal = WORKFLOWS.get(st.session_state["active_proposal_id"]).proposal
            detail_item("Saved proposal", proposal.proposal_id)
            detail_item("Target / assessment", f"{proposal.target_id} / {proposal.assessment_id}")
            detail_item("Exact parameters", proposal.parameters_json)
            st.text(proposal.reason)
    with right:
        safeguard = (
            "The simulated assessment is complete. Your decision is required before the Remediation simulator may continue."
            if decision_available
            else "Only an undecided saved proposal accepts a new decision. Use history to review prior attempts or start a new demonstration."
        )
        st.markdown(f'<div class="section-card"><div class="detail-label">Review safeguard</div><div class="detail-value">{safeguard}</div><div class="scope-label">This prototype does not run scripts or make changes.</div></div>', unsafe_allow_html=True)
        st.markdown("#### Decision impact")
        st.info(DEVICE_CONTEXT["DEMO-NLA"]["approve_outcome"])
        st.warning(DEVICE_CONTEXT["DEMO-NLA"]["defer_outcome"])

    st.header("Administrator decision")
    st.caption("Demo administrator identity only; production authentication is not implemented. Decisions and simulation results are saved in SQLite.")
    if phase in ("Awaiting Approval", "Approved"):
        st.selectbox("Simulation outcome for this demonstration",
                     ["Successful verification", "Verification failure", "Execution failure", "Collection error"],
                     key="simulation_scenario")
    if phase == "Approved" and st.button("Run approved simulation", key="resume_approved"):
        run_approved_simulation()
        st.rerun()
    comment = st.text_area("Review comment (optional)", placeholder="Example: Approved for the next maintenance window.", height=94, disabled=not decision_available, key="review_comment_input")
    if st.session_state["remediation_decision"]:
        st.info(f"Recorded decision: {st.session_state['remediation_decision']}")
        st.text(f"Recorded comment: {st.session_state['decision_comment'] or '(none)'}")
    approve, reject, _ = st.columns([0.26, 0.26, 0.48])
    with approve:
        if st.button("Approve", type="primary", use_container_width=True, disabled=not decision_available, key="approve_remediation"):
            approve_sample_remediation(comment)
            request_navigation("Verification / Remediation Result")
    with reject:
        if st.button("Reject", type="secondary", use_container_width=True, disabled=not decision_available, key="reject_remediation"):
            reject_sample_remediation(comment)
            st.rerun()


def render_verification() -> None:
    render_page_intro("Verification / Remediation Result", "Saved simulation result and independent read-back evidence.")
    proposal_id = st.session_state.get("active_proposal_id")
    state = WORKFLOWS.get(proposal_id) if proposal_id else None
    execution = state.event("execution") if state else None
    if not execution:
        st.warning("No execution result is recorded for this proposal. An interrupted attempt is never retried automatically.")
        render_agent_activity(show_heading=False)
        return
    st.caption("Synthetic evidence only. This result does not describe the laptop or a live Windows Server.")
    st.text(f"Administrator comment: {st.session_state['decision_comment'] or '(none)'}")
    with st.container(border=True):
        st.subheader("Remediation execution result")
        detail_item("Action", state.proposal.action_id)
        detail_item("Proposal", state.proposal.proposal_id)
        detail_item("Result", execution["payload"]["detail"])
        detail_item("Recorded at (UTC)", execution["created_at"])
    verification = state.event("verification")
    if verification:
        result = verification["payload"]
        evidence = result["evidence"]
        with st.container(border=True):
            st.subheader("Independent verification")
            html_table([{"Control": state.proposal.control_id, "Expected value": "Required",
                         "Verified value": display_value(state.proposal.control_id, evidence["value"]),
                         "Status": result["status"]}],
                       ["Control", "Expected value", "Verified value", "Status"], {"Status"})
            st.text(result["detail"])
            st.caption(f"Source: {evidence['source']} | Collected: {evidence['collected_at']}")
        if state.phase == "Verification Passed":
            st.success("Verification Passed in simulation. The original assessment remains unchanged.")
        else:
            st.error("Verification failed or evidence is unavailable. This finding remains unresolved; another attempt needs a new proposal and approval.")
    elif execution["payload"]["success"]:
        st.error("Execution succeeded in simulation but verification is unavailable. The finding remains unresolved; no automatic second write will occur.")
    else:
        st.error("Execution failed. No successful verification is claimed and no automatic second write will occur.")
    render_agent_activity()


def render_drift() -> None:
    render_page_intro("Configuration Drift / Assessment History", "Changes detected between assessment 1042 and the previous comparable assessment.")
    st.header("Configuration changes in synthetic history")
    html_table(DRIFT, ["Control", "Previous value", "Current value", "Description", "Detected at"])
    st.info("NLA and lockout regressed from compliant to non-compliant, so both receive D=5. The firewall change is an improvement. Unchanged password non-compliance receives D=3.")
    st.header("Assessment history")
    html_table(HISTORY, ["Assessment", "Initiated by", "Started", "Status"], {"Status"})
    st.caption("Comparison basis: a previous comparable completed assessment with the same scope.")
    saved = WORKFLOWS.list_for_assessment("1042")
    if saved:
        st.header("Saved remediation attempts (simulation)")
        html_table([{"Proposal": item.proposal.proposal_id, "Created (UTC)": item.proposal.created_at,
                     "Status": item.phase} for item in saved], ["Proposal", "Created (UTC)", "Status"], {"Status"})
        selected = st.selectbox("Open saved proposal", [item.proposal.proposal_id for item in saved], key="saved_proposal")
        if st.button("Review saved proposal", key="open_saved_proposal"):
            st.session_state["active_proposal_id"] = selected
            st.session_state.pop("review_comment_input", None)
            request_navigation("Remediation Review")


def render_sidebar() -> str:
    requested_page = st.session_state.pop("requested_page", None)
    if requested_page:
        st.session_state["navigation"] = requested_page
    with st.sidebar:
        st.markdown('<div class="sidebar-brand">🛡️ CIS Compliance<br>Dashboard</div>', unsafe_allow_html=True)
        st.markdown('<div class="sidebar-subtitle">Windows Server 2022<br>Hardening Framework</div>', unsafe_allow_html=True)
        st.markdown("##### Navigate")
        pages = [
            "Dashboard / Overview",
            "Assessment Results",
            "Risk Findings / Risk Details",
            "Remediation Review",
            "Verification / Remediation Result",
            "Configuration Drift / Assessment History",
        ]
        page = st.radio("Navigate between prototype views", pages, label_visibility="collapsed", key="navigation")
        st.markdown("##### Workflow simulation")
        st.markdown(f'<div class="scope-label">Orchestrator: {badge(st.session_state["agent_phase"])}</div>', unsafe_allow_html=True)
        st.caption("Saved assessments and simulation workflow")
        st.markdown(
            '<div class="sidebar-footer">Assessment 1042<br>Initiated by <strong>demo-admin</strong><br><br>SQLite stores assessments, decisions and verification.<br>All target actions are simulated.</div>',
            unsafe_allow_html=True,
        )
    return page


def main() -> None:
    global CONTROLS, RISKS, DRIFT, HISTORY, SUMMARY, WORKFLOWS
    database_path = Path(os.environ.get("CIS_DASHBOARD_DB", str(Path(__file__).parent / "data" / "preview.sqlite3")))
    try:
        assessments = AssessmentStore(database_path)
        saved = load_demo(assessments)
        WORKFLOWS = WorkflowStore(assessments)
    except (OSError, sqlite3.Error, ValueError, KeyError) as error:
        st.error(f"Assessment storage unavailable ({type(error).__name__}). Check the database path and schema; saved data was not reset.")
        st.stop()
    CONTROLS, RISKS, DRIFT = saved["controls"], saved["risks"], saved["drift"]
    HISTORY, SUMMARY = saved["history"], saved["summary"]
    init_session_state()
    inject_css()
    page = render_sidebar()
    renderers = {
        "Dashboard / Overview": render_overview,
        "Assessment Results": render_results,
        "Risk Findings / Risk Details": render_risk,
        "Remediation Review": render_remediation,
        "Verification / Remediation Result": render_verification,
        "Configuration Drift / Assessment History": render_drift,
    }
    try:
        renderers[page]()
    except (ValueError, KeyError, sqlite3.Error) as error:
        st.error(f"Workflow could not continue ({type(error).__name__}). Reload the saved proposal; no automatic retry will occur.")


if __name__ == "__main__":
    main()
