"""CIS Compliance Dashboard - presentation-only Streamlit prototype.

This application deliberately uses only representative, in-memory sample data.
It does not execute PowerShell, call an LLM, access a database, or use a backend.
"""

from __future__ import annotations

import time

import streamlit as st


st.set_page_config(
    page_title="CIS Compliance Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


CONTROLS = [
    {
        "id": "CIS-1.2.2",
        "title": "Account lockout threshold",
        "observed": "0 invalid attempts",
        "expected": "10 invalid attempts",
        "status": "Non-Compliant",
    },
    {
        "id": "CIS-1.1.4",
        "title": "Minimum password length",
        "observed": "8 characters",
        "expected": "14 characters",
        "status": "Non-Compliant",
    },
    {
        "id": "CIS-2.3.1",
        "title": "Guest account status",
        "observed": "Disabled",
        "expected": "Disabled",
        "status": "Compliant",
    },
    {
        "id": "CIS-9.1.1",
        "title": "Windows Firewall (Domain) state",
        "observed": "On",
        "expected": "On",
        "status": "Compliant",
    },
    {
        "id": "CIS-18.9.1",
        "title": "Remote Desktop network authentication",
        "observed": "Not required",
        "expected": "Required",
        "status": "Non-Compliant",
    },
]

RISKS = {
    "CIS-18.9.1": {
        "title": "Remote Desktop network authentication",
        "score": 85,
        "level": "Critical",
        "factors": {"I": 5, "E": 4, "P": 4, "L": 3, "D": 5},
        "explanation": (
            "Network-level authentication is disabled, allowing Remote Desktop "
            "logon prompts to be exposed to unauthenticated network connections."
        ),
    },
    "CIS-1.2.2": {
        "title": "Account lockout threshold",
        "score": 62,
        "level": "High",
        "factors": {"I": 4, "E": 3, "P": 3, "L": 3, "D": 1},
        "explanation": "A zero lockout threshold permits unlimited password-guessing attempts.",
    },
    "CIS-1.1.4": {
        "title": "Minimum password length",
        "score": 56,
        "level": "Moderate",
        "factors": {"I": 4, "E": 3, "P": 2, "L": 1, "D": 3},
        "explanation": "An eight-character password policy reduces resistance to password attacks.",
    },
}

DEVICE_CONTEXT = {
    "CIS-18.9.1": {
        "condition": "Remote Desktop is configured so that Network Level Authentication is not required.",
        "meaning": "A remote connection can reach the Remote Desktop logon prompt before network-level authentication has been completed.",
        "decision": "Prioritise approval to enable Network Level Authentication after confirming that authorised administrators use supported Remote Desktop clients.",
        "approve_outcome": "Remote Desktop connections must authenticate earlier in the connection process. Older or unmanaged clients that do not support Network Level Authentication may need to be updated before they can connect.",
        "defer_outcome": "The exposed Remote Desktop logon prompt remains available to unauthenticated network connections, so the Critical risk remains open.",
    },
    "CIS-1.2.2": {
        "condition": "The account lockout threshold is 0 invalid attempts, so the server does not lock an account after repeated failed sign-in attempts.",
        "meaning": "Password guessing can continue without the account-lockout safeguard slowing repeated attempts.",
        "decision": "Plan a change to the CIS target of 10 invalid attempts and make sure the administrator account-unlock process is understood.",
        "approve_outcome": "Repeated incorrect passwords are limited by the lockout policy, but legitimate users who repeatedly mistype a password may require support to unlock their account.",
        "defer_outcome": "Repeated password attempts remain unrestricted, which keeps the High risk open.",
    },
    "CIS-1.1.4": {
        "condition": "The minimum password length is 8 characters instead of the CIS target of 14 characters.",
        "meaning": "Shorter passwords generally provide less resistance against password-guessing and cracking attempts.",
        "decision": "Schedule a move to a 14-character minimum and notify affected users before they next change their password.",
        "approve_outcome": "New and changed passwords must meet the stronger length requirement; users may need guidance during the transition.",
        "defer_outcome": "The weaker password-length policy remains in effect, leaving the Moderate risk open.",
    },
}

DRIFT = [
    {
        "Control": "CIS-18.9.1",
        "Previous value": "Required",
        "Current value": "Not required",
        "Description": "Network-level authentication disabled",
        "Detected at": "2026-08-12 09:15:44",
    },
    {
        "Control": "CIS-1.2.2",
        "Previous value": "10 invalid attempts",
        "Current value": "0 invalid attempts",
        "Description": "Lockout threshold reverted to 0",
        "Detected at": "2026-08-12 09:15:48",
    },
    {
        "Control": "CIS-9.1.1",
        "Previous value": "Off",
        "Current value": "On",
        "Description": "Firewall re-enabled after previous remediation",
        "Detected at": "2026-08-12 09:16:05",
    },
]

HISTORY = [
    {"Assessment": "1042", "Initiated by": "admin01", "Started": "2026-08-12 09:15:00", "Status": "Completed"},
    {"Assessment": "1041", "Initiated by": "admin01", "Started": "2026-08-05 11:35:00", "Status": "Completed"},
    {"Assessment": "1040", "Initiated by": "admin02", "Started": "2026-08-01 08:40:00", "Status": "Completed"},
]


INITIAL_AGENT_EVENTS = [
    {
        "Time": "—",
        "Component": "AI Agent Orchestrator",
        "Activity": "Sample workflow ready to replay",
        "State": "Ready to Scan",
    }
]


def init_session_state() -> None:
    """Initialise the presentation-only workflow state for this browser session."""
    st.session_state.setdefault("agent_phase", "Ready to Scan")
    st.session_state.setdefault("agent_events", INITIAL_AGENT_EVENTS.copy())
    st.session_state.setdefault("remediation_decision", None)
    st.session_state.setdefault("navigation", "Dashboard / Overview")


def request_navigation(page: str) -> None:
    """Navigate safely on the next rerun, before the sidebar radio is created."""
    st.session_state["requested_page"] = page
    st.rerun()


def run_sample_assessment() -> None:
    """Visibly replay the report workflow without calling any external component."""
    events = [
        {
            "Time": "09:15:00",
            "Component": "AI Agent Orchestrator",
            "Activity": "Assessment 1042 accepted; Scanner Agent assigned",
            "State": "Scanning",
        }
    ]
    st.session_state["agent_phase"] = "Scanning"
    st.session_state["remediation_decision"] = None

    scan_times = ["09:15:12", "09:15:36", "09:16:03", "09:16:31", "09:17:04"]
    with st.status("AI Agent Orchestrator — assessment requested", expanded=True) as status:
        progress = st.progress(0, text="Preparing sample assessment 1042")
        for index, control in enumerate(CONTROLS, start=1):
            status.update(label=f"Scanner Agent — scanning {control['id']}", state="running")
            status.write(
                f"{control['id']} · {control['title']} — observed: {control['observed']}"
            )
            events.append(
                {
                    "Time": scan_times[index - 1],
                    "Component": "Scanner Agent",
                    "Activity": f"Assessed {control['id']}: {control['status']}",
                    "State": "Completed",
                }
            )
            progress.progress(index / len(CONTROLS), text=f"Scanning {index} of {len(CONTROLS)} controls")
            time.sleep(0.42)

        status.update(label="Analysis Agent — prioritising non-compliant findings", state="running")
        status.write("Deterministic RiskEngine calculated the three sample risk scores.")
        events.append(
            {
                "Time": "09:18:21",
                "Component": "Analysis Agent",
                "Activity": "Prioritised 3 non-compliant findings using the fixed risk formula",
                "State": "Risk Prioritisation",
            }
        )
        time.sleep(0.55)
        status.update(label="Administrator decision required", state="complete", expanded=True)

    events.append(
        {
            "Time": "09:18:42",
            "Component": "AI Agent Orchestrator",
            "Activity": "CIS-18.9.1 remediation prepared for administrator review",
            "State": "Awaiting Approval",
        }
    )
    st.session_state["agent_events"] = events
    st.session_state["agent_phase"] = "Awaiting Approval"


def approve_sample_remediation() -> None:
    """Simulate the approved path; never execute scripts or modify a system."""
    events = list(st.session_state["agent_events"])
    with st.status("Remediation Agent — approved action simulation", expanded=True) as status:
        status.write("Administrator approval recorded for REM-18.9.1.")
        time.sleep(0.35)
        status.update(label="Remediation Agent — executing approved sample action", state="running")
        status.write("Simulation only: no PowerShell script was invoked.")
        time.sleep(0.45)
        status.update(label="Remediation Agent — verification complete", state="complete", expanded=True)

    events.extend(
        [
            {
                "Time": "09:25:00",
                "Component": "Administrator",
                "Activity": "Approved REM-18.9.1",
                "State": "Approved",
            },
            {
                "Time": "09:25:11",
                "Component": "Remediation Agent",
                "Activity": "Executed simulated Network Level Authentication remediation",
                "State": "Executed",
            },
            {
                "Time": "09:26:30",
                "Component": "Remediation Agent",
                "Activity": "Reassessed CIS-18.9.1; verified value: Required",
                "State": "Passed",
            },
        ]
    )
    st.session_state["agent_events"] = events
    st.session_state["agent_phase"] = "Verification Passed"
    st.session_state["remediation_decision"] = "Approved"


def reject_sample_remediation() -> None:
    events = list(st.session_state["agent_events"])
    events.append(
        {
            "Time": "09:25:00",
            "Component": "Administrator",
            "Activity": "Rejected REM-18.9.1; no remediation executed",
            "State": "Rejected",
        }
    )
    st.session_state["agent_events"] = events
    st.session_state["agent_phase"] = "Rejected"
    st.session_state["remediation_decision"] = "Rejected"


def reset_sample_workflow() -> None:
    st.session_state["agent_phase"] = "Ready to Scan"
    st.session_state["agent_events"] = INITIAL_AGENT_EVENTS.copy()
    st.session_state["remediation_decision"] = None


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
    return f'<span class="badge {styles.get(text, "badge-info")}">{text}</span>'


def metric_card(label: str, value: str, note: str = "") -> str:
    return f"""
    <div class="kpi-card">
      <div class="kpi-label">{label}</div>
      <div class="kpi-value">{value}</div>
      <div class="kpi-note">{note}</div>
    </div>
    """


def html_table(rows: list[dict[str, str]], columns: list[str], badge_columns: set[str] | None = None) -> None:
    badge_columns = badge_columns or set()
    headers = "".join(f"<th>{column}</th>" for column in columns)
    body = []
    for row in rows:
        cells = []
        for column in columns:
            value = str(row[column])
            cells.append(f"<td>{badge(value) if column in badge_columns else value}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    st.markdown(f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(body)}</tbody></table>", unsafe_allow_html=True)


def render_page_intro(title: str, subtitle: str) -> None:
    st.markdown('<div class="prototype-banner">Prototype mock-up — representative sample data.</div>', unsafe_allow_html=True)
    st.title(title)
    st.markdown(f'<div class="muted">{subtitle}</div>', unsafe_allow_html=True)
    st.markdown('<div class="scope-label">Sample assessment: 5 of 36 scoped controls shown.</div>', unsafe_allow_html=True)


def detail_item(label: str, value: str) -> None:
    st.markdown(f'<div class="detail-label">{label}</div><div class="detail-value">{value}</div>', unsafe_allow_html=True)


def render_agent_activity(show_heading: bool = True) -> None:
    if show_heading:
        st.header("Agent activity")
    phase = st.session_state["agent_phase"]
    st.markdown(
        f'<div class="formula">AI Agent Orchestrator state: {badge(phase)}</div>',
        unsafe_allow_html=True,
    )
    html_table(
        st.session_state["agent_events"],
        ["Time", "Component", "Activity", "State"],
        {"State"},
    )


def render_current_device_situation() -> None:
    """Describe the sample target's present posture without claiming a live scan."""
    context = DEVICE_CONTEXT["CIS-18.9.1"]
    st.header("Current device situation")
    st.caption("Representative interpretation of the sample assessment only. It is not a live diagnosis of this device.")
    target, posture, urgent = st.columns(3)
    with target:
        st.markdown(metric_card("Sample target", "Server 2022", "CIS hardening scope"), unsafe_allow_html=True)
    with posture:
        st.markdown(metric_card("Observed posture", "3 / 5", "Sample controls non-compliant"), unsafe_allow_html=True)
    with urgent:
        st.markdown(metric_card("Immediate concern", "RDP / NLA", "CIS-18.9.1 · Critical"), unsafe_allow_html=True)
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
        ("Assessment", "1042", "Completed"),
        ("Scoped controls", "36", "Framework selection"),
        ("Sample compliant", "2 / 5", "40% compliance rate"),
        ("Non-compliant", "3", "Requires review"),
        ("Highest risk", "85", "Critical finding"),
    ]
    for column, data in zip(columns, values):
        with column:
            st.markdown(metric_card(*data), unsafe_allow_html=True)

    render_current_device_situation()

    st.header("Agentic workflow replay")
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
            st.button("Workflow complete", disabled=True, use_container_width=True, key="workflow_complete")
    with summary_column:
        if phase == "Ready to Scan":
            st.info("Replay the representative assessment to watch the Orchestrator, Scanner Agent, and Analysis Agent progress through the five controls.")
        elif phase == "Awaiting Approval":
            st.warning("Scanning and analysis are complete. CIS-18.9.1 is now waiting for an administrator decision; no remediation has been executed.")
        elif phase == "Verification Passed":
            st.success("The approved sample action has been verified. Review the verification result or replay the workflow.")
        else:
            st.info("The proposed remediation was rejected. No configuration change was simulated.")
    with reset_column:
        if phase != "Ready to Scan" and st.button("Reset replay", use_container_width=True, key="reset_workflow"):
            reset_sample_workflow()
            st.rerun()
    render_agent_activity()

    left, right = st.columns([1.24, 0.76], gap="large")
    with left:
        st.header("Assessment information")
        info = [
            {"Field": "Assessment ID", "Value": "1042"},
            {"Field": "Initiated by", "Value": "admin01"},
            {"Field": "Start time", "Value": "2026-08-12 09:15:00"},
            {"Field": "End time", "Value": "2026-08-12 09:18:42"},
            {"Field": "Status", "Value": "Completed"},
        ]
        html_table(info, ["Field", "Value"])
    with right:
        st.header("Risk distribution")
        distribution = [
            {"Risk level": "Critical", "Findings": "1", "Focus": "Immediate"},
            {"Risk level": "High", "Findings": "1", "Focus": "Prioritised"},
            {"Risk level": "Moderate", "Findings": "1", "Focus": "Planned"},
        ]
        html_table(distribution, ["Risk level", "Findings", "Focus"], {"Risk level"})
        st.markdown('<div class="formula">3 non-compliant findings are prioritised for review.</div>', unsafe_allow_html=True)

    st.header("Assessment snapshot")
    snapshot = [{"Control": c["id"], "Control title": c["title"], "Status": c["status"]} for c in CONTROLS]
    html_table(snapshot, ["Control", "Control title", "Status"], {"Status"})


def render_results() -> None:
    render_page_intro("Assessment Results", "Detailed evidence captured for assessment 1042.")
    filter_col, summary_col = st.columns([0.62, 0.38])
    with filter_col:
        selected_filter = st.selectbox("Show controls", ["All sample controls", "Non-Compliant only", "Compliant only"], label_visibility="collapsed")
    with summary_col:
        st.markdown('<div class="formula">Assessment 1042 · 2 Compliant · 3 Non-Compliant</div>', unsafe_allow_html=True)

    filtered = CONTROLS
    if selected_filter == "Non-Compliant only":
        filtered = [control for control in CONTROLS if control["status"] == "Non-Compliant"]
    elif selected_filter == "Compliant only":
        filtered = [control for control in CONTROLS if control["status"] == "Compliant"]
    rows = [
        {
            "Control": item["id"],
            "Control title": item["title"],
            "Observed value": item["observed"],
            "Expected value": item["expected"],
            "Compliance": item["status"],
        }
        for item in filtered
    ]
    html_table(rows, ["Control", "Control title", "Observed value", "Expected value", "Compliance"], {"Compliance"})
    st.info("Evidence is representative only. Use the Risk Findings view to inspect the three non-compliant controls.")


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
    calculated_score = sum({"I": 6, "E": 5, "P": 4, "L": 3, "D": 2}[factor] * value for factor, value in risk["factors"].items())

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
    st.caption("Analysis Agent supporting explanation — simulated prototype content; no local LLM call is made.")
    render_decision_support(selected)


def render_remediation() -> None:
    render_page_intro("Remediation Review", "Human approval checkpoint before a proposed configuration change.")
    phase = st.session_state["agent_phase"]
    decision_available = phase == "Awaiting Approval"
    left, right = st.columns([0.66, 0.34], gap="large")
    with left:
        st.header("Finding information")
        detail_item("Control", "CIS-18.9.1 — Remote Desktop network authentication")
        detail_item("Risk", f"Score 85 · {badge('Critical')}")
        st.header("Proposed remediation")
        detail_item("Proposed action", "Enable Network Level Authentication for Remote Desktop.")
        detail_item("Script reference", "REM-18.9.1")
        detail_item("Status before decision", badge(phase))
    with right:
        safeguard = (
            "The simulated assessment is complete. Your decision is required before the Remediation Agent may continue."
            if decision_available
            else "Run the sample assessment from Dashboard / Overview before a remediation decision can be made."
        )
        st.markdown(f'<div class="section-card"><div class="detail-label">Review safeguard</div><div class="detail-value">{safeguard}</div><div class="scope-label">This prototype does not run scripts or make changes.</div></div>', unsafe_allow_html=True)
        st.markdown("#### Decision impact")
        st.info(DEVICE_CONTEXT["CIS-18.9.1"]["approve_outcome"])
        st.warning(DEVICE_CONTEXT["CIS-18.9.1"]["defer_outcome"])

    st.header("Administrator decision")
    st.text_area("Review comment (optional)", placeholder="Example: Approved for the next maintenance window.", height=94, disabled=not decision_available)
    approve, reject, _ = st.columns([0.26, 0.26, 0.48])
    with approve:
        if st.button("Approve", type="primary", use_container_width=True, disabled=not decision_available, key="approve_remediation"):
            approve_sample_remediation()
            request_navigation("Verification / Remediation Result")
    with reject:
        if st.button("Reject", type="secondary", use_container_width=True, disabled=not decision_available, key="reject_remediation"):
            reject_sample_remediation()
            st.toast("Prototype only: remediation rejected; no action was executed.")


def render_verification() -> None:
    render_page_intro("Verification / Remediation Result", "Illustrative post-approval execution and verification outcome.")
    if st.session_state["agent_phase"] != "Verification Passed":
        st.warning("No verification result is available yet. The agent workflow must complete an administrator-approved remediation first.")
        render_agent_activity(show_heading=False)
        return
    st.caption("Verification scope: this view shows one selected approved remediation. Use Assessment Results to review the full five-control sample.")

    with st.container(border=True):
        st.subheader("Remediation execution result")
        row_left, row_right, row_status = st.columns([1.2, 0.9, 0.55])
        with row_left:
            detail_item("Executed action", "Enable Network Level Authentication for Remote Desktop.")
        with row_right:
            detail_item("Script reference", "REM-18.9.1")
        with row_status:
            detail_item("Status", badge("Executed"))
        detail_item("Executed at", "2026-08-12 09:25:11")

    with st.container(border=True):
        st.subheader("Reassessment / verification result")
        verification = [
            {"Control": "CIS-18.9.1", "Expected value": "Required", "Verified value": "Required", "Status": "Passed"},
        ]
        html_table(verification, ["Control", "Expected value", "Verified value", "Status"], {"Status"})
        st.success("Verification Passed — the control now satisfies the expected security configuration.")
        st.caption("Verification time: 2026-08-12 09:26:30")
    render_agent_activity()


def render_drift() -> None:
    render_page_intro("Configuration Drift / Assessment History", "Changes detected between assessment 1042 and the previous comparable assessment.")
    st.header("Detected configuration drift")
    html_table(DRIFT, ["Control", "Previous value", "Current value", "Description", "Detected at"])
    st.info("CIS-18.9.1 changed from Required to Not required; this is the configuration drift evidence supporting the D=5 risk factor.")
    st.header("Assessment history")
    html_table(HISTORY, ["Assessment", "Initiated by", "Started", "Status"], {"Status"})
    st.caption("Comparison basis: a previous comparable completed assessment with the same scope.")


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
        st.markdown("##### Agentic workflow")
        st.markdown(f'<div class="scope-label">Orchestrator: {badge(st.session_state["agent_phase"])}</div>', unsafe_allow_html=True)
        st.caption("In-memory simulation only")
        st.markdown(
            '<div class="sidebar-footer">Assessment 1042<br>Initiated by <strong>admin01</strong><br><br>In-memory prototype only.<br>No scripts, services, or databases are connected.</div>',
            unsafe_allow_html=True,
        )
    return page


def main() -> None:
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
    renderers[page]()


if __name__ == "__main__":
    main()
