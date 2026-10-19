# Ubuntu CIS Compliance Dashboard Prototype

This Streamlit application is an Ubuntu-only visual prototype for the FYP project **Agentic AI Framework for Linux Server Hardening and CIS Compliance Assessment**. Its interface is a direct platform-matched version of the companion Windows Server prototype: both use the same six-page structure, CSS, spacing, cards, tables, controls and workflow presentation. Only the representative platform data differs.

## Important prototype limitation

The application is not connected to a server or backend. It does not perform a live OpenSCAP or Lynis scan, execute Linux commands or Ansible remediation, call Ollama or another LLM, start agent services, or read and write SQLite. Buttons update only Streamlit session state.

All pages identify their contents as representative sample data. The values are internally consistent but must not be presented as measurements from a real server.

## Canonical sample

- Assessment: `2042`
- Target: `ubuntu-fyp`
- Platform: Ubuntu Server 22.04 LTS
- Security profile: CIS Ubuntu Linux 22.04 LTS Level 1 Server
- Version boundary: v2.0.0 ComplianceAsCode profile alignment
- Project scope: 30 selected CIS-aligned controls
- Representative controls shown: 5
- Compliance snapshot: 2 compliant, 3 non-compliant, 40%
- Primary finding: `CIS-4.1.3 Verify ufw Enabled`
- Deterministic risk: 86 Critical
- Remediation: `REM-4.1.3`
- Initial remediation status: Awaiting Approval

The ComplianceAsCode Ubuntu 22.04 Level 1 Server profile maps its control references to CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0. Although CIS currently lists a newer Ubuntu 22.04 benchmark, this prototype deliberately retains the v2.0.0 mapping used by the selected machine-readable profile and the FYP report.

## Pages

1. Dashboard / Overview
2. Assessment Results
3. Risk Findings / Risk Details
4. Remediation Review
5. Verification / Remediation Result
6. Configuration Drift / Assessment History

The Compliance Report and Export page is not included in this version because it is absent from both the current Windows prototype and the current Chapter 4.7 page list. Add it later as a coordinated change to both platform prototypes and the report.

## Run on Windows PowerShell

```powershell
cd "C:\Users\teohk\OneDrive\Documents\GitHub\FYP_App\ubuntu_cis_compliance_dashboard_prototype"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
streamlit run app.py
```

Streamlit normally opens the interface at `http://localhost:8501`.

## Report screenshots

For a consistent screenshot sequence:

1. Select **Reset sample workflow** after completing any approval or rejection demonstration.
2. Capture Dashboard, Assessment Results, Risk Findings, and Remediation Review while the status is **Awaiting Approval**.
3. Approve the representative remediation.
4. Capture Verification and Configuration Drift after the status becomes **Executed** and verification becomes **Passed**.
5. Label every report figure as a prototype using representative sample data.

Save final screenshots in the `screenshots` folder.

## Traceability references

- ComplianceAsCode profile: https://complianceascode.github.io/content-pages/guides/ssg-ubuntu2204-guide-cis_level1_server.html
- CIS Ubuntu Linux benchmarks: https://www.cisecurity.org/benchmark/ubuntu_linux
