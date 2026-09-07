# CIS Compliance Dashboard

Local Streamlit prototype for a Windows Server 2022 Hardening Framework. It contains only representative in-memory sample data; it does not execute PowerShell, use local LLMs, access a database, or integrate with a backend.

## Run locally

1. Open PowerShell in this folder and create a local environment (once):

   ```powershell
   py -m venv .venv
   ```

2. Install the dependency:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

3. Start the dashboard:

   ```powershell
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

4. Open the local address shown by Streamlit, normally `http://localhost:8501`.

## Demonstrate the agentic workflow

1. Open **Dashboard / Overview** and select **Run sample assessment**.
2. Watch the AI Agent Orchestrator assign the Scanner Agent through all five representative controls.
3. The Analysis Agent prioritises the non-compliant findings using the deterministic risk formula.
4. The workflow stops at **Awaiting Approval**. Select **Review remediation** and choose **Approve** or **Reject**.
5. Approve simulates the Remediation Agent execution and verification path; Reject records that no action was taken.

The dashboard’s **Current device situation** and **Device security context and decision support** sections translate each sample weakness into plain language, an administrator decision, and the likely consequences of approving or delaying that decision.

This is a presentation-only simulation. It does not execute PowerShell, invoke a local LLM, modify Windows Server, or use a database.

## Contents

- `app.py` - the complete Streamlit prototype and representative data.
- `screenshots/` - verified PNG captures of all six views.
