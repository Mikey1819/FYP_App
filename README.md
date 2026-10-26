# CIS compliance dashboard prototypes

This repository contains separate Windows and Ubuntu prototypes:

- [Windows Server preview](window_cis_compliance_dashboard_prototype/README.md): synthetic assessment/approval demonstration, local Ollama investigation, and a separate imported-evidence page for the standalone Server 2022 lab.
- [Ubuntu prototype](ubuntu_cis_compliance_dashboard_prototype/README.md).

The Windows project's [complete documentation and report coverage](window_cis_compliance_dashboard_prototype/REPORT_REQUIREMENTS_AND_COVERAGE.md) records the agreed target, scope, requirements, 36 candidate controls, design, evaluation and remaining gaps. It links the complete original report text and the framework development plan.

## Run the Windows dashboard

From this repository root in PowerShell:

```powershell
cd window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Use the existing virtual environment. For first-time dependency setup, see the Windows README. Other Windows scripts and documents are now inside `window_cis_compliance_dashboard_prototype`; older root-relative paths need that additional folder.

## Next Windows lab step

Follow [VM_EVIDENCE.md](window_cis_compliance_dashboard_prototype/VM_EVIDENCE.md) to configure VirtualBox file transfer and collect read-only evidence. The shared host folder is now:

```text
C:\Users\User\Documents\Degree\FYP 1\FYP_App\window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype\data\vm_exchange
```

In the dashboard, choose **Imported VM Assessments**, upload the collector JSON, enter the VM computer name and UUID from its console, review the validation results, then save. Imported evidence is stored separately from the synthetic demo; it does not authorize or execute hardening.

See [progress](window_cis_compliance_dashboard_prototype/PROGRESS.md), [teacher walkthrough](window_cis_compliance_dashboard_prototype/TEACHER_PREVIEW.md), and [reviewed benchmark subset](window_cis_compliance_dashboard_prototype/BENCHMARK_MAPPING.md). The first real VM export is saved in Imported VM Assessments; independent manual comparisons remain pending; the app's original 40% fixture score is not the VM's posture.
