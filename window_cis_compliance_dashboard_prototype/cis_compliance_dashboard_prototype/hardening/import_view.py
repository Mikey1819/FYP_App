"""Real imported VM evidence, investigation and approved action exchange."""

from pathlib import Path
import sqlite3

import streamlit as st

from .domain import summarise
from .evidence_import import MAX_BYTES, load_evidence, effective_context
from .import_storage import ImportedEvidenceStore
from .framework import AssessmentOrchestrator
from .lifecycle import RemediationLifecycle
from .vm_bridge import BridgeStore
from .vm_bridge_view import render_bridge
from .server2022_catalogue import LATEST_CATALOGUE
from .scan_view import render_live_scan, render_scan_queue


def show_assessment(assessment):
    summary = summarise(assessment.results)
    st.write(f'Target: {assessment.hostname}')
    st.code(assessment.target_id, language=None)
    st.caption(f'Imported evidence collected at {assessment.collected_at.isoformat()}; '
               'this is a historical snapshot, not a current live scan.')
    st.caption(f'Catalogue: {assessment.results[0].control.catalogue_version} | '
               f'Profile: {assessment.results[0].control.profile}')
    columns = st.columns(4)
    columns[0].metric('Evaluated / selected', f'{summary.evaluated} / {summary.selected}')
    percent = f'{summary.compliance_percent:.0f}%' if summary.compliance_percent is not None else 'Unavailable'
    columns[1].metric('Compliant among evaluated', percent)
    columns[2].metric('Collection errors', summary.errors)
    columns[3].metric('Unknown', summary.unknown)
    if summary.evaluated < summary.selected:
        st.warning('Incomplete coverage: Error/Unknown checks are excluded from the percentage and remain unresolved.')
    if summary.selected < len(LATEST_CATALOGUE):
        st.info(f'This file contains an earlier {summary.selected}-control assessment. '
                f'Run the updated collector in the VM and upload a new file to assess all {len(LATEST_CATALOGUE)} supported controls.')
    if summary.selected >= 12:
        st.caption('Account-policy checks compare each exported setting independently. '
                   'Lockout timing only takes effect when the lockout threshold is enabled.')
    key = 'assessment_filter_' + assessment.source_sha256
    with st.expander('Filter assessment results'):
        status = st.selectbox('Result status', ['All statuses', 'Non-Compliant', 'Error', 'Unknown', 'Compliant'],
                              key=key + '_status')
        area = st.selectbox('Security area', ['All areas'] + sorted({r.control.area for r in assessment.results}),
                            key=key + '_area')
    visible = [r for r in assessment.results
               if (status == 'All statuses' or r.status.value == status)
               and (area == 'All areas' or r.control.area == area)]
    st.caption(f'Showing {len(visible)} of {summary.selected} checks. Coverage metrics above include the entire assessment.')
    if not visible:
        st.info('No checks match these filters.')
    st.dataframe([{'Control': r.control.control_id, 'Check': r.control.title,
                   'Area': r.control.area,
                   'Observed': repr(r.evidence.value) if r.evidence.value is not None else 'Not collected',
                   'Rule': f'{r.control.rule.operator.value} {r.control.rule.expected}',
                   'Status': r.status.value, 'Detail': r.detail,
                   'Collected': r.evidence.collected_at.isoformat(), 'Source': r.evidence.source}
                  for r in visible], hide_index=True)
    with st.expander('Reviewed benchmark references'):
        for r in assessment.results:
            st.text(r.control.source_reference)
    if any(r.evidence.value == -1 for r in assessment.results):
        st.caption('Export value -1 means passwords never expire (maximum age) or accounts remain locked '
                   'until an administrator unlocks them (lockout duration). These do not satisfy the '
                   'configured finite-duration benchmark rules.')
    st.caption('File SHA-256: ' + assessment.source_sha256)


def reset_test():
    for key in list(st.session_state):
        if key.startswith(("vm_cycle_", "vm_context_")):
            del st.session_state[key]
    st.session_state["vm_upload_generation"] = st.session_state.get("vm_upload_generation", 0) + 1


def show_record(record):
    show_assessment(record.assessment)
    context = effective_context(record.raw)
    if context:
        with st.expander("Effective firewall and NLA readings"):
            st.dataframe([{**row, "value": repr(row["value"]) if row["state"] == "ok" else "Unavailable"}
                          for row in context], hide_index=True)
            st.caption("Firewall True = enabled; NLA required 1 = enabled; NLA source 0 = local server. "
                       "Effective protection and explicit policy checks are separate.")


def render_imported_evidence(database_path: Path):
    st.title("VM hardening test")
    st.caption("Upload evidence -> analyze -> review solution -> run in VM -> return receipt")
    digest = st.session_state.get("vm_cycle_digest")
    if not digest:
        st.subheader("1. Upload evidence from this test")
        st.info("Start with a fresh collector JSON from your VM. No previous assessment is loaded automatically.")
        generation = st.session_state.get("vm_upload_generation", 0)
        uploaded = st.file_uploader("Evidence JSON (maximum 64 KiB)", type=["json"],
                                   key=f"vm_evidence_upload_{generation}")
        host = st.text_input("Expected VM computer name (from the VM console)", key="vm_expected_host")
        machine_uuid = st.text_input("Expected machine UUID (from the VM console)", key="vm_expected_uuid")
        render_live_scan(database_path, host, machine_uuid)
        render_scan_queue(database_path, host, machine_uuid)
        if uploaded is None:
            return
        if uploaded.size > MAX_BYTES:
            st.error("Evidence rejected: maximum size is 64 KiB.")
            return
        if not host.strip() or not machine_uuid.strip():
            st.info("Enter the VM name and UUID, then analyze the uploaded file.")
            return
        if st.button("Analyze uploaded evidence", key="analyze_vm_evidence"):
            try:
                raw = uploaded.getvalue()
                load_evidence(raw, expected_hostname=host.strip(), expected_machine_uuid=machine_uuid.strip())
                store = ImportedEvidenceStore(database_path)
                runtime = AssessmentOrchestrator(store)
                run = runtime.start(raw, expected_hostname=host.strip(), expected_machine_uuid=machine_uuid.strip())
                run = runtime.complete_assessment(run.run_id)
                st.session_state["vm_cycle_digest"] = run.evidence_sha256
                st.session_state["vm_cycle_framework_run"] = run.run_id
                st.rerun()
            except (OSError, ValueError, sqlite3.Error) as exc:
                st.error(f"Evidence could not be analyzed: {exc}")
        return

    st.button("Start new test", key="new_vm_test", on_click=reset_test)
    try:
        store = ImportedEvidenceStore(database_path)
        original = store.get(digest)
        run_id = st.session_state.get("vm_cycle_framework_run")
        if not run_id:
            raise ValueError("Start a new test to create its framework run")
        runtime = AssessmentOrchestrator(store)
        run = runtime.get(run_id)
        if run.evidence_sha256 != digest or run.target_id != original.assessment.target_id:
            raise ValueError("Framework run does not belong to this test's evidence")
        lifecycle = RemediationLifecycle(runtime, BridgeStore(
            database_path.with_name(database_path.stem + "_bridge.sqlite3"), store))
        workflow = lifecycle.get(run_id)
        latest = workflow['attempts'][-1] if workflow['attempts'] else None
        if latest and latest['outcome'] in ('verified', 'unresolved'):
            verdict = latest['verdict']
            verification = latest['verification_evidence_sha256'] or latest['before_evidence_sha256']
            st.subheader("4. Verification result for this test")
            if verdict == "Verified compliant":
                st.success("This test completed: minimum password length verified compliant in the returned evidence.")
            else:
                st.warning("This test remains unresolved: " + verdict + ". No automatic retry.")
            if latest['verification_evidence_sha256'] is None:
                st.warning("No post-action evidence was returned. The readings below are the pre-action check.")
            show_record(store.get(verification))
            with st.expander("Evidence uploaded at the start of this test"):
                show_record(original)
            st.info("To test again after changing the VM, choose Start new test and upload freshly collected evidence.")
            return
        st.subheader("2. Results from your uploaded evidence")
        show_record(original)
        with st.expander("Assessment steps for this test"):
            st.caption("These are recorded rule-based steps. Local AI investigation is a separate action below. "
                       "An eligible action still needs your review and approval.")
            st.table([{"Role": task["role"], "Task": task["operation"].replace("_", " "),
                       "Status": task["state"]} for task in run.tasks])
        render_bridge(lifecycle, run_id, original)
        render_live_scan(database_path, original.assessment.hostname,
                         original.assessment.target_id.removeprefix('windows:'), origin_run_id=run_id)
        render_scan_queue(database_path, original.assessment.hostname,
                          original.assessment.target_id.removeprefix('windows:'), origin_run_id=run_id)
    except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
        st.error(f"This test could not continue: {exc}")
