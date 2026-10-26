"""Human-approved file exchange. The Streamlit host never runs the VM executor."""
import hashlib
import json
import sqlite3
import streamlit as st

from .investigation import Coordinator, InvestigationLog
from .ollama_client import OllamaClient
from .vm_bridge import IMPACT, finding
from .vm_paths import runner_command
from .agent_team_view import render_agent_team


def render_bridge(lifecycle, run_id, record):
    st.subheader("3. Review a solution and run it in the VM")
    st.info("Prototype scope: Minimum Password Length (1.1.4) → 14 is the single executable remediation. "
            "All other checks are assessment-only in this milestone.")
    st.caption("File-mediated lab connection. Local AI investigates imported evidence; only you can approve. "
               "The VM runner must be launched inside the VM. The Streamlit computer performs no hardening.")
    try:
        store = lifecycle.bridge
        try:
            finding(record)
            eligible = True
        except ValueError:
            eligible = False
        digest = record.assessment.source_sha256
        workflow = lifecycle.get(run_id)
        if workflow['outcome'] == 'receipt_import_incomplete':
            st.warning("Receipt storage was interrupted before all evidence was saved. "
                       "Upload the same receipt below to finish importing it; do not run the VM action again.")
        current_id = workflow['attempts'][-1]['proposal_id'] if workflow['attempts'] else None
        st.session_state['vm_cycle_proposal'] = current_id
        current = store.get(current_id) if current_id else None
        if current and current["proposal"]["evidence_sha256"] != digest:
            raise ValueError("Proposal does not belong to this test's evidence")
        context = lifecycle.context(run_id)
        if eligible:
            with st.expander('Password provisioning compatibility', expanded=context['compatibility'] != 'compatible'):
                st.caption('Report whether account provisioning scripts and applications support passwords of at least '
                           '14 characters. This is your operational report, not collected evidence or approval.')
                st.write('Saved compatibility: ' + context['compatibility'])
                st.text(context['note'])
                if context.get('operator'):
                    st.caption('Reported by ' + context['operator'] + ' at ' + context['recorded_at'])
                if current is None or current['decision'] == 'rejected':
                    compatibility = st.selectbox('Provisioning compatibility', ['unknown', 'compatible', 'incompatible'],
                        index=['unknown', 'compatible', 'incompatible'].index(context['compatibility']), key='vm_context_status')
                    context_operator = st.text_input('Context reported by', key='vm_context_operator')
                    context_note = st.text_area('Compatibility evidence or dependency to review', max_chars=500, key='vm_context_note')
                    if st.button('Save compatibility report', key='vm_context_save',
                                 disabled=not (context_operator.strip() and context_note.strip())):
                        context = lifecycle.save_context(run_id, compatibility=compatibility,
                            operator=context_operator, note=context_note)
                        st.success('Compatibility report saved; approval is still separate.')
                else:
                    st.caption('Context is fixed for this proposal. Reject a pending proposal before correcting it.')
        directory = store.workspace(digest)
        with st.expander("Device working directory", expanded=directory is None):
            st.caption("Directory inside this VM containing both scripts and request files. "
                       "Saved by machine UUID, separately for each device; this does not broaden supported OS/actions.")
            proposed_directory = st.text_input("VM working directory", value=directory or "",
                placeholder="D:\\Lab Workspace", key="workspace_" + record.assessment.target_id)
            if st.button("Save device working directory", key="save_workspace"):
                directory = store.save_workspace(digest, proposed_directory)
                st.success("Device working directory saved.")
            if directory:
                st.caption("Commands use saved directory: " + directory)
        if eligible:
            st.info(IMPACT)
        render_agent_team(lifecycle, run_id, current_id=current_id,
                          can_start=current is None or current['decision'] == 'rejected')
        if current is None or current["decision"] == "rejected":
            if st.button("Investigate this VM finding with local Ollama", key="vm_ai"):
                with st.spinner("Local model is investigating imported evidence (up to four minutes)…"):
                    run = Coordinator(OllamaClient(), lifecycle.investigation_tools(
                        run_id, expected_previous_id=current_id)).run()
                    st.session_state["vm_cycle_run"] = run["run_id"]
                    proposal_id = run["events"][-1]["data"]["proposal_id"]
                    if proposal_id:
                        st.session_state["vm_cycle_proposal"] = proposal_id
            if eligible and st.button("Prepare deterministic password-length proposal", key="vm_propose",
                                      disabled=context['compatibility'] != 'compatible'):
                st.session_state["vm_cycle_proposal"] = lifecycle.prepare(
                    run_id, expected_previous_id=current_id)
        if not eligible:
            st.caption("No supported actionable password-length finding in this snapshot. "
                       "Unknown/error findings cannot be remediated through this bridge.")
        investigation_id = st.session_state.get("vm_cycle_run")
        if investigation_id:
            with st.expander("AI investigation for this test"):
                run = InvestigationLog(store).get(investigation_id)
                if run.get('framework_run_id') != workflow['run_id']:
                    raise ValueError("AI investigation does not belong to this test")
                outcome = run['events'][-1]['data'].get('outcome')
                if outcome:
                    st.write('Investigation outcome: ' + outcome['outcome'].replace('_', ' '))
                    st.write(outcome['reason'])
                    if outcome.get('context_id') != context['context_id']:
                        st.caption('This investigation used an earlier compatibility report. Investigate again for the updated context.')
                else:
                    st.warning('No structured investigation decision was saved. Status: ' + run['events'][-1]['data']['status'])
                st.write(f"{run['created_at']} | {run['model']} | {run['provenance']} | Imported")
                for event in run["events"]:
                    if event["kind"] in ("tool", "tool_rejected", "finished"):
                        st.json(event)
        current_id = st.session_state.get("vm_cycle_proposal")
        proposals = [store.get(current_id)] if current_id else []
        for item in proposals:
            proposal = item["proposal"]
            identifier = proposal["request_id"]
            with st.expander(f"Password-length proposal {identifier[:12]}", expanded=item["decision"] is None):
                st.json(proposal)
                st.caption("Operator name is a local audit label, not authenticated identity. "
                           "The request file is not signed; verify its hash independently at the VM console.")
                if item["decision"] is None:
                    operator = st.text_input("Administrator name", key="operator_" + identifier)
                    confirmed = st.checkbox("I reviewed the exact VM, action and operational impact", key="confirm_" + identifier)
                    if st.button("Approve and create VM request", key="approve_" + identifier,
                                 disabled=not (operator.strip() and confirmed)):
                        lifecycle.decide(workflow['run_id'], identifier, approve=True, operator=operator)
                        st.rerun()
                    if st.button("Reject proposal", key="reject_" + identifier, disabled=not operator.strip()):
                        lifecycle.decide(workflow['run_id'], identifier, approve=False, operator=operator)
                        st.rerun()
                else:
                    st.write("Decision: " + item["decision"])
                if item["request"] and not item["verdict"]:
                    raw = item["request"]
                    st.download_button("Download approved VM request", raw,
                                       file_name=identifier + "-request.json", mime="application/json",
                                       key="request_" + identifier)
                    st.write("Copy this request SHA-256 directly from the dashboard to the VM command:")
                    st.code(hashlib.sha256(raw).hexdigest(), language=None)
                    request = json.loads(raw)
                    st.caption("Approval expires: " + request["expires_at"])
                    if directory:
                        st.write(f"Copy both scripts and this request into {directory} inside the VM, then run:")
                        st.code(runner_command(raw, directory), language="powershell")
                    else:
                        st.warning("Save this device's working directory above to generate its VM command.")
                    st.caption("Expires 24 hours after approval. See docs/archive/legacy/VM_BRIDGE.md for the VM command. "
                               "An attempted request cannot be replayed, even if verification failed.")
                if item["verdict"] and workflow['outcome'] != 'receipt_import_incomplete':
                    st.write("Returned result: " + item["verdict"])
        if not current_id or store.get(current_id)["decision"] != "approved":
            return
        st.subheader("4. Return the receipt from this test")
        receipt = st.file_uploader("Return VM receipt JSON (maximum 200 KB)", type=["json"], key="vm_receipt_" + current_id)
        if receipt is not None and st.button("Verify and save VM receipt", key="save_vm_receipt"):
            if receipt.size > 200000:
                raise ValueError("VM receipt exceeds size limit")
            lifecycle.accept_receipt(workflow['run_id'], current_id, receipt.getvalue())
            st.rerun()
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        st.error(f"VM exchange could not complete: {exc}")
