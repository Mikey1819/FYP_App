# CIS compliance hardening prototypes

This repository holds two separate Final Year Project prototypes:

- **[Windows: Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment](window_cis_compliance_dashboard_prototype/README.md).** Four local-LLM agents (Orchestrator, Scanner, Analysis, Remediation) assess a standalone Windows Server 2022 (the lab VM, or a client's server paired by a one-time code) against 32 CIS Stand-alone v2.0.0 controls over WinRM. They rank findings deterministically, propose library fixes for administrator approval, execute the approved ones, and verify the results.
- **[Ubuntu prototype](ubuntu_cis_compliance_dashboard_prototype/README.md)**, the separate Linux project.

## Run the Windows dashboard

From this repository root in PowerShell:

```powershell
cd window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype
.\.venv\Scripts\python.exe -s launch.py
```

Then open **Servers**: pair a server with the code its server access helper shows, or add the lab VM by address (`127.0.0.1`, port `55985`). Start rounds in **Agentic hardening**. Setup and pairing are in [VM_CONNECTION_SETUP.md](window_cis_compliance_dashboard_prototype/docs/vm/VM_CONNECTION_SETUP.md). A ready-to-run client package (`Start.cmd`, nothing to install) is built by `scripts\packaging\build_client_package.py`. Current status and next tasks are in [PROGRESS.md](window_cis_compliance_dashboard_prototype/PROGRESS.md).
