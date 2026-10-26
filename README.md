# CIS compliance hardening prototypes

This repository holds two separate Final Year Project prototypes:

- **[Windows: Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment](window_cis_compliance_dashboard_prototype/README.md).** Four local-LLM agents (Orchestrator, Scanner, Analysis, Remediation) assess a standalone Windows Server 2022 VM against 32 CIS Stand-alone v2.0.0 controls over WinRM. They rank findings deterministically, propose library fixes for administrator approval, execute the approved ones, and verify the results.
- **[Ubuntu prototype](ubuntu_cis_compliance_dashboard_prototype/README.md)**, the separate Linux project.

## Run the Windows dashboard

From this repository root in PowerShell:

```powershell
cd window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Then open **Agentic hardening** and connect to the VM. One-time VM setup is in [VM_CONNECTION.md](window_cis_compliance_dashboard_prototype/VM_CONNECTION.md). Current status and next tasks are in [PROGRESS.md](window_cis_compliance_dashboard_prototype/PROGRESS.md).
