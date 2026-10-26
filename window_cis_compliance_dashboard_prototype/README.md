# VM Hardening Workspace

For the complete project target, requirements, all 36 proposed controls, report-section coverage and final evaluation criteria, start with [Complete project requirements and report coverage](REPORT_REQUIREMENTS_AND_COVERAGE.md). The [original report text and tables](REPORT_SOURCE_REFERENCE.md) preserve the source details; the [framework plan](REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md) records the agreed three objectives and development milestones. Documented targets are not claims of completed implementation.

The initial preview was accepted as completed by the user on 22 October 2026. The next phase now includes a tested [imported-assessment framework foundation](FRAMEWORK_RUNTIME.md), shared by Streamlit and a command-line client. Full adaptive orchestration remains unfinished; see [REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md](REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md) for objective/use-case mapping and remaining milestones.

The normal Streamlit app starts blank and follows one test: upload evidence, analyze, review a solution, execute in the VM, then return its receipt. It only displays the current test. It does not seed sample assessments or display synthetic scores. The target is the selected standalone Server 2022 VM, never the Streamlit host.

## Run

From `window_cis_compliance_dashboard_prototype/cis_compliance_dashboard_prototype`:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

The existing environment is sufficient. If setting up a new checkout, create a virtual environment and install `requirements.txt` first.

## Current program scope

**Start here: the "Agentic hardening" page** (default page). Connect to the VM, then **Start agentic round**. The AI Orchestrator delegates the Scanner Agent (live WinRM scan) and the Analysis Agent (deterministic risk ranking), then submits a plan of fixes (with fact-checked reason codes) from a 20-action pre-approved library across 32 assessed controls. Approve or reject each proposal. **Execute approved fixes** has the Remediation Agent apply them in the VM and verify them; a fresh rescan shows what changed. Design and guarantees: [ARCHITECTURE.md](ARCHITECTURE.md). The sections below describe the older **Evidence upload (legacy)** page.

The Scanner Agent now reaches the VM itself over **PowerShell Remoting (WinRM)**; see [VM_CONNECTION.md](VM_CONNECTION.md). It needs a one-time `Enable-PSRemoting` inside the VM. Then use **Connect and check identity** and **Scan VM now**. While connected, the AI Scanner's recollection tool collects live into a new assessment. Fake-session tests pass; the first real VM trial is pending. The older shared-folder worker ([SCANNER_CONNECTION.md](SCANNER_CONNECTION.md)) remains as a fallback.

The dashboard now includes an [AI agent team](AGENT_TEAM.md): separate Scanner, Analysis and Remediation conversations coordinated by an AI Orchestrator, with distinct tools and recorded handoffs. Choose **Run multi-agent hardening review** after assessment. Agents share the installed local model but have isolated conversations and responsibilities. PowerShell is still the restricted VM collection/execution tool; collection uses the shared-folder worker when started inside the VM, and human approval is required for the single supported action.

Sixteen source-reviewed checks are assessed with collector v4: the original five, seven additional account policies, and four local security options covering blank-password restrictions and anonymous access. **Minimum Password Length (1.1.4) to 14 is the only executable remediation**. All other checks are assessment-only. Missing/error evidence cannot authorize a change. Imported numeric risk scoring is not implemented. The eleven additions are fixture-tested; independent VM comparison remains pending. Filter results by status and security area; coverage metrics always describe the entire uploaded assessment.

Collector v4 emits schema 4 with the 16-control `local1` catalogue and separate effective Public firewall/NLA context. Legacy v1/v2 files remain five-control snapshots; v3 retains twelve controls. Copy the updated [collector](scripts/Collect-Server2022Evidence.ps1) into the VM and collect a new JSON to see the expanded assessment. Local `qwen3:8b` can investigate the imported password finding with bounded tools and save a proposal. The deterministic proposal alternative is labelled. Neither path can approve or execute a change by itself.

Before preparing a proposal, save the current test's **Password provisioning compatibility** report. Unknown or incompatible provisioning withholds proposals; a compatible report still requires separate approval. The [adaptive investigator](ADAPTIVE_INVESTIGATION.md) can request clarification, defer for a dependency, close a compliant password finding or prepare an eligible unapproved proposal. Collected VM evidence and administrator-reported context remain distinct.

Follow [VM_BRIDGE.md](VM_BRIDGE.md) for the shared-folder exchange. Save **Device working directory** for each VM; paths are stored by machine UUID. Generated commands use that saved directory, including paths with spaces. The runner resolves relative request filenames and its default output directory from its own script location. This prepares different device workspaces without expanding supported OS versions or permitted actions.

The runner applies a fixed approved action inside the VM only, with identity, digest, expiry, precondition, exclusive-lock and replay guards. It collects fresh evidence afterwards. Importing its receipt evaluates only the current approved request and displays its returned evidence. Choose **Start new test** to clear the displayed workflow before collecting/uploading another baseline. No history selector or automatic old-result loading is shown.

Each new test now links its framework run to its proposals, administrator decisions and returned evidence through the [lifecycle service](FRAMEWORK_RUNTIME.md#remediation-lifecycle-service). Current results are recovered from those records on rerun. If receipt storage is interrupted, reupload the same receipt to finish importing it; do not rerun the VM action. Missing post-action evidence is shown as unresolved, with any pre-action readings clearly labelled.

## Historical VM result and repeat testing

The saved request `a7f9ce7846df45dd936bd474d3703cb1` returned minimum password length **0 → 14**, with verdict **Verified compliant**. That was a historical user-run test. The user subsequently reset the VM setting to 0 for another test; a newer export confirms 0. It is not evidence of the current VM setting. The assistant did not execute a security command. See [VM_VALIDATION.md](VM_VALIDATION.md). Do not replay that request.

## Internal request matching

SQLite remains internal to bind exact approvals and receipts and prevent accidental reuse. Historical rows are not shown or automatically loaded. Existing files were preserved, not deleted. Default files under application `data/`:

- `preview_imports.sqlite3`: immutable imported snapshots and original bytes.
- `preview_imports_framework.sqlite3`: assessment runs and recorded Scanner, Analysis and Remediation eligibility tasks.
- `preview_imports_bridge.sqlite3`: immutable run/proposal links, proposals, decisions, receipts, AI traces and per-device workspace settings.
- `preview.sqlite3`: historical synthetic demonstration database; normal app does not open it.

`CIS_DASHBOARD_DB` supplies the base path/stem; imports and bridge use `_imports` and `_imports_bridge` suffixes. Back up databases with Streamlit stopped. Workspace settings can change; saved evidence/approval audit records remain unchanged.

## Checks

From the application folder:

```powershell
$env:TEMP = Join-Path (Get-Location) 'data\test_tmp'
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

From the Windows project folder:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test_vm_runner.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test_collector_helpers.ps1
```

These tests use fixtures/mocked execution. They do not harden the host. The suite includes a Python-request → PowerShell-helper → receipt → deterministic-verification round trip for both passing and unchanged settings.

The former six-view synthetic prototype is preserved in `synthetic_demo_app.py` solely as a separately launched legacy demonstration/regression entry point. It is not exposed in normal navigation. No previous database or audit history was deleted.

See [AGENTS.md](AGENTS.md) for decisions and rules and [PROGRESS.md](PROGRESS.md) for current status. Superseded preview-era documents are kept in [docs/archive/](docs/archive/).
