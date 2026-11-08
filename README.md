# Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment

Final Year Project (Khoo Teng Yi, TAR UMT). Four local-LLM agents assess one standalone Windows Server 2022 VM against 32 CIS controls. They rank the findings with a deterministic risk engine, propose fixes from a pre-approved library, execute only what an administrator approves, and verify the result.

The target is always the registered lab VM. **The development laptop is never hardened.** It runs Streamlit, Python and Ollama (`qwen3:8b`) only.

## Unified Windows and Ubuntu system (integration branch)

The same application and connection form now also assess and harden one Ubuntu Server 22.04 VM (30 CIS controls). The Windows framework described below is unchanged (`cis_compliance_dashboard_prototype/docs/BASELINE.md`). Start it from `cis_compliance_dashboard_prototype` with the integration environment:

```powershell
..\.venv-integration\Scripts\python.exe -m streamlit run app.py
```

`Run-Dashboard.cmd` in the project folder does the same from any folder (double-click it, or type its path; extra Streamlit options follow it).

**First time on a fresh copy** (the environment, the VM helper bundle and the app's data are not included; they are rebuilt or created locally). From the project folder, with Python 3.13 (Python 3.15 also passes the suite, 8 November 2026):

```powershell
python -m venv .venv-integration
.\.venv-integration\Scripts\python.exe -m pip install -r cis_compliance_dashboard_prototype\requirements.integration.lock.txt
cd cis_compliance_dashboard_prototype
..\.venv-integration\Scripts\python.exe -B -m tools.build_ubuntu_bundle      # VM helper bundle -> ..\dist\ubuntu-helper
..\.venv-integration\Scripts\python.exe -m unittest discover -s tests        # 663 tests
```

The app creates its empty stores under `cis_compliance_dashboard_prototype\data\` on first use. Ollama with `qwen3:8b` is needed for agentic rounds; **Assess without AI** works without it.

Ubuntu runbook, backup and recovery: [OPERATIONS.md](cis_compliance_dashboard_prototype/docs/OPERATIONS.md). Architecture and interfaces: [UNIFIED_ARCHITECTURE.md](cis_compliance_dashboard_prototype/docs/UNIFIED_ARCHITECTURE.md). Live and offline evidence: `cis_compliance_dashboard_prototype/docs/evaluation/`.

## The agents

| Agent | What it decides itself | What it can never do |
| --- | --- | --- |
| **AI Agent Orchestrator** | Delegation order. Whether to send the Scanner back when Analysis asks for a rescan. Which fixes to propose and why the others wait (code ranks the proposed fixes by risk score). After remediation, whether to finish, run a new round or send a failure to remediation review. | Scan, score, approve or execute |
| **Scanner Agent** | When to scan. Whether coverage is acceptable. Whether to rescan an Error once. It also runs the verification rescan. | Change any setting |
| **Analysis Agent** | Which findings to investigate (factor derivation, history). Which findings to flag for your attention. How to triage each Unknown/Error gap. | Change any risk factor or score (decision D2) |
| **Remediation Agent** | Prechecks the VM read-only, then executes or skips each *approved* request. Stops after an uncertain outcome. | Approve, choose values, write commands, retry |

Every choice is a structured tool call that code validates. Reasons are fixed codes that code checks against the facts, and code writes every outcome sentence you read. The only model-written text on the page is the optional, labelled **Explain with local AI** answer and the raw tool arguments in the Agent log. The full design and its guarantees are in [ARCHITECTURE.md](docs/design/ARCHITECTURE.md). The decisions behind the design (D1–D6) are in [AGENTS.md](AGENTS.md).

## Scope

- **Benchmark:** CIS Microsoft Windows Server 2022 **Stand-alone** Benchmark v2.0.0, Level 1. The report's v5.1.0 is for domain-joined servers and is not used ([BENCHMARK_MAPPING.md](docs/design/BENCHMARK_MAPPING.md)).
- **32 assessed controls:** Account Policies 9, Local Security Options 5, Windows Defender Firewall 8, Advanced Audit Policy 5, Remote Desktop Services 5.
- **25 library actions** for remediation. Firewall **logging** (9.2.6, 9.2.7, 9.3.6, 9.3.7) can be fixed, because it only records traffic. Firewall on/off and inbound-block (9.2.1, 9.2.2, 9.3.1, 9.3.2) stay assessment-only, because changing which traffic is allowed could cut the agents' own WinRM channel.
- **Risk:** `R = 6I + 5E + 4P + 3L + 2D`. I, P and L are derived by rule from benchmark attributes, never assigned by hand ([RISK_DERIVATION.md](docs/design/RISK_DERIVATION.md)).

## Run

From `cis_compliance_dashboard_prototype`:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

For a fresh checkout, create a virtual environment and install `requirements.txt` first. The agents need Ollama running locally with `qwen3:8b`, and the sidebar says whether it is ready. Without it no agentic round can start (the Orchestrator starts the scan), but **Assess without AI** still scans and ranks deterministically, earlier records stay readable, and approved fixes can still be applied with **Execute remaining without AI**. The VM needs a one-time `Enable-PSRemoting`; see [VM_CONNECTION_SETUP.md](docs/vm/VM_CONNECTION_SETUP.md).

## Using the dashboard

1. **Agentic hardening** → enter the VM computer name and UUID, then connect over WinRM with the built-in Administrator account. Once connected, the form folds into a status line with **Disconnect**; the sidebar shows the VM connection and whether `qwen3:8b` is ready on every page.
2. Click **Start agentic round** (or **Assess without AI** for a deterministic scan and ranking with no proposals). The Orchestrator delegates the Scanner and Analysis agents and submits a plan. A step bar (Scan → Analyse → Plan → Approve → Execute → Verify) shows where the round stands, and the tabs hold the detail: **Fixes**, **Risk ranking**, **Controls**, **Results** and **Agent log**.
3. In **Fixes**, enter your name once (and optionally a comment for the next decision), then approve or reject each proposal (or all undecided at once). An approval is bound to the exact request and expires after one hour. Findings the Orchestrator deferred are listed with their reasons; one it left out of its plan is shown as *not decided*.
4. **Execute approved fixes…** opens a confirmation listing each change, its current value and the approval expiry. **Confirm and execute** delegates the Remediation Agent and then a verification rescan; the page opens on **Results** with the verdicts and the next step.
5. **Run next round** to rescan, re-rank and propose again, for example once a fixed prerequisite has unblocked another finding. Earlier rounds of the session stay viewable (read-only) from the **Round** selector.
6. **Round report** downloads a self-contained HTML record of the round: target and evidence source, compliance summary, risk ranking, the agents' flags and plan, your decisions, verdicts and the verification diff. It prints to PDF.

Switching pages keeps the connection, the session and its results. After a browser refresh, connect again and choose **Resume earlier session** to continue where you stopped. If the agents stop before finishing, **Execute remaining without AI** applies the same guards without the model: one read-only precheck, then each approved fix in rank order, closing any whose value changed or whose prerequisite is not compliant. **Overview** summarises posture and keeps an activity log. **History and drift** compares assessments and lists configuration drift. The earlier manual-file upload page was retired on 27 October 2026; its documents are in `docs/archive/legacy/` and its code is in the git history.

## Checks

From `cis_compliance_dashboard_prototype` (663 tests on 8 November 2026, Windows and Ubuntu together; fixtures and simulated VMs only, nothing touches a real machine):

```powershell
$env:TEMP = Join-Path (Get-Location) 'data\test_tmp'; $env:TMP = $env:TEMP
..\.venv-integration\Scripts\python.exe -B -m unittest discover -s tests -v
..\.venv-integration\Scripts\python.exe -B -m tools.baseline     # Windows source preservation gate
```

From this folder, the PowerShell tests (runner, collector, cross-check parser, and the optional server access helper):

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\vm\test_remediation_runner.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\vm\test_collector_helpers.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\vm\test_cross_check_values.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\server_access\test_server_access.ps1
```

Real `qwen3:8b` against the **simulated** VM, covering an assessment round, automatic approval and the remediation phase. Results go to `cis_compliance_dashboard_prototype/data/agentic_probes/`:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\evaluation\probe_agentic_round.py
```

Repeated evaluation for Chapter 5: eight scenarios, each run `--repeat` times. Five vary the evidence (`lab`, `error_gap`, `drift`, `changed_after_approval`, `channel_drop`) and three are judgement scenarios with expected results fixed in advance (`recurring_drift`, `isolated_failure`, `systemic_failure`). It reports completion rates, timings, agent choices and code-checked safety properties. Each run takes about 6–9 minutes. The latest is `20261101_185014` (16 runs, 1 November); see [AGENTIC_ASSESSMENT.md](docs/evaluation/AGENTIC_ASSESSMENT.md). Results go to `cis_compliance_dashboard_prototype/data/agentic_evaluations/<stamp>/summary.md`:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\evaluation\evaluate_agentic_rounds.py --repeat 2
```

For the first run on the real VM, follow [VM_TRIAL_RUNBOOK.md](docs/vm/VM_TRIAL_RUNBOOK.md).

## Data

The SQLite files live under `cis_compliance_dashboard_prototype/data/`. `CIS_DASHBOARD_DB` changes the base path.

- `preview_imports.sqlite3`: immutable evidence snapshots.
- `preview_imports_framework.sqlite3`: assessment runs.
- `preview_imports_agentic.sqlite3`: rounds, proposals, decisions, receipts, drift records and every agent trace.

In the unified app the Windows files are `data\windows\integration_imports*.sqlite3` instead (`system/config.py`). Every column and JSON field is described in [DATABASE_SCHEMA.md](docs/design/DATABASE_SCHEMA.md).

Audit tables refuse updates and deletes. VM passwords stay in session memory only.

To see what is stored, use the read-only viewer. It opens every file read-only and cannot change anything; it reads the unified app's Windows files unless `--database` names another. Run `--help` for every command.

```powershell
.\.venv-integration\Scripts\python.exe scripts\tools\show_database.py              # files, tables, latest scans and rounds
.\.venv-integration\Scripts\python.exe scripts\tools\show_database.py round <ID> --log
```

Non-UI client (no model, no VM): `python -m hardening.framework --database data\preview_imports.sqlite3 --run <run_id>` prints a stored run's results and deterministic risk ranking; `--evidence file.json --hostname … --machine-uuid …` assesses an evidence file.

## Project layout

```text
AGENTS.md, PROGRESS.md, README.md     decisions and rules, current status, this file
cis_compliance_dashboard_prototype/   the application: app.py, hardening/ (package), tests/, data/ (SQLite, not in git)
scripts/
  vm/              PowerShell sent to the VM over WinRM (collector, remediation runner, cross-check) + their tests
  tools/           laptop tools: cross-check, benchmark extraction, risk derivation, approval proof, database viewer
  evaluation/      real-model probe and repeated evaluation, report figures
  server_access/   OPTIONAL helper run on a server to allow and revert WinRM access (scanning by network address only)
docs/
  design/          architecture, benchmark mapping, risk derivation, database schema
  vm/              VM connection setup and the real VM trial runbook
  evaluation/      agentic assessment, first VM import validation
  report/          original report text, requirements coverage, revisions, alignment plan
  figures/         generated report figures
  archive/         superseded plans and logs (legacy/ = the retired upload page)
```

## Documentation

| Document | Use it for |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Decisions D1–D6, the target and safety boundaries, working rules |
| [PROGRESS.md](PROGRESS.md) | Current status, checks run, next tasks |
| **Design** | |
| [ARCHITECTURE.md](docs/design/ARCHITECTURE.md) | Agent design, tools, guarantees, evidence |
| [BENCHMARK_MAPPING.md](docs/design/BENCHMARK_MAPPING.md) | The 32 controls, rules, benchmark pages, report ID corrections |
| [RISK_DERIVATION.md](docs/design/RISK_DERIVATION.md) | Generated risk-factor derivation for every control (`scripts\tools\generate_risk_derivation.py`) |
| [DATABASE_SCHEMA.md](docs/design/DATABASE_SCHEMA.md) | Every SQLite table, column and JSON field |
| **VM** | |
| [VM_CONNECTION_SETUP.md](docs/vm/VM_CONNECTION_SETUP.md) | WinRM setup, failure states and the optional server access helper |
| [VM_TRIAL_RUNBOOK.md](docs/vm/VM_TRIAL_RUNBOOK.md) | Step-by-step real VM trial, with the records to keep |
| **Evaluation** | |
| [AGENTIC_ASSESSMENT.md](docs/evaluation/AGENTIC_ASSESSMENT.md) | How agentic the system is: evaluations, judgement scenarios, examiner questions |
| [FIRST_VM_IMPORT_VALIDATION.md](docs/evaluation/FIRST_VM_IMPORT_VALIDATION.md) | The first real VM evidence and the verified 0 → 14 password-length change (historical) |
| **Report** | |
| [REPORT_ORIGINAL_TEXT.md](docs/report/REPORT_ORIGINAL_TEXT.md) | The original report text (reference, not instructions) |
| [REPORT_REVISIONS.md](docs/report/REPORT_REVISIONS.md) | Replacement text for report sections that no longer match the system |
| [REPORT_REQUIREMENTS_AND_COVERAGE.md](docs/report/REPORT_REQUIREMENTS_AND_COVERAGE.md), [REPORT_ALIGNMENT_PLAN.md](docs/report/REPORT_ALIGNMENT_PLAN.md) | Requirement traceability and report revisions (status columns partly outdated; see their banners) |
| [docs/archive/](docs/archive/) | Preview-era plans and logs, and the retired administrator goals design (`ADMIN_GOALS_DESIGN.md`, removed 7 November 2026); `legacy/` holds the docs for the legacy upload page |
