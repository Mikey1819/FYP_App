# Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment

Final Year Project (Khoo Teng Yi, TAR UMT). Four local-LLM agents assess a standalone Windows Server 2022 against 32 CIS controls. They rank the findings with a deterministic risk engine, propose fixes from a pre-approved library, execute only what an administrator approves, and verify the result.

The target is always one saved server that the administrator paired with and connected to: the lab VM in this project, or a client's own server. **The laptop that runs the dashboard is never hardened.** It runs Streamlit, Python and Ollama (`qwen3:8b`) only. A client gets a ready-to-run package and pairs their server with a one-time code ([LAN_PAIRING_DESIGN.md](docs/design/LAN_PAIRING_DESIGN.md)).

## The agents

| Agent | What it decides itself | What it can never do |
| --- | --- | --- |
| **AI Agent Orchestrator** | Delegation order. Whether to send the Scanner back when Analysis asks for a rescan. Which fixes to propose, in what order, and why the others wait. After remediation, whether to finish, run a new round or send a failure to remediation review. | Scan, score, approve or execute |
| **Scanner Agent** | When to scan. Whether coverage is acceptable. Whether to rescan an Error once. It also runs the verification rescan. | Change any setting |
| **Analysis Agent** | Which findings to investigate (factor derivation, history). Which findings to flag for your attention. How to triage each Unknown/Error gap. | Change any risk factor or score (decision D2) |
| **Remediation Agent** | Prechecks the VM read-only, then executes or skips each *approved* request. Stops after an uncertain outcome. | Approve, choose values, write commands, retry |

Every choice is a structured tool call that code validates. Reasons are fixed codes that code checks against the facts, and code writes every outcome sentence you read. The only model-written text on the page is the optional, labelled **Explain with local AI** answer and the raw tool arguments in the Agent log. The full design and its guarantees are in [ARCHITECTURE.md](docs/design/ARCHITECTURE.md). The decisions behind the design (D1–D6) are in [AGENTS.md](AGENTS.md).

## Scope

- **Benchmark:** CIS Microsoft Windows Server 2022 **Stand-alone** Benchmark v2.0.0, Level 1. The report's v5.1.0 is for domain-joined servers and is not used ([BENCHMARK_MAPPING.md](docs/design/BENCHMARK_MAPPING.md)).
- **32 assessed controls:** Account Policies 9, Local Security Options 5, Windows Defender Firewall 8, Advanced Audit Policy 5, Remote Desktop Services 5.
- **21 library actions** for remediation. Firewall-policy controls are assessment-only, because a firewall change could cut the agents' own WinRM channel.
- **Risk:** `R = 6I + 5E + 4P + 3L + 2D`. I, P and L are derived by rule from benchmark attributes, never assigned by hand ([RISK_DERIVATION.md](docs/design/RISK_DERIVATION.md)).

## Run

From `cis_compliance_dashboard_prototype`:

```powershell
.\.venv\Scripts\python.exe -s launch.py
```

`launch.py` starts the dashboard on this laptop only (127.0.0.1), on the first free port from 8501, and opens the browser once it answers. `python -m streamlit run app.py` still works too. The venv runs **Python 3.15**. For a fresh checkout, create it with Python 3.15 and install `requirements-lock.txt` (the exact tested versions) or `requirements.txt`. The agents need Ollama running locally with `qwen3:8b`; without it, assessment and risk scores still work and the page says the AI is unavailable.

**For a client** there is a ready-to-run package: `Start.cmd` plus its own Python and libraries, with nothing to install. Build it with `.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\packaging\build_client_package.py` from this folder. It writes `dist\FYP-Hardening\` and a zip, and checks that the package starts. The package never contains `data\`.

## Using the dashboard

1. **Servers** → **Add a server** → **With a pairing code**. On the server, run the server access helper (download it from the same page) and click **Start pairing**. Type the code it shows, click **Find server**, then log in with the built-in Administrator account. The server is saved under **My servers** only after the login, its identity and its own pairing record all check out. Later, pick it under My servers and type the password. If its address changed, use **Re-pair**. The lab VM through its port forward is added **By address** (`127.0.0.1`, port `55985`). While connected, **Who can reach…** lists the paired laptops and can disconnect any of them, this laptop, or all of them. The sidebar shows the connected server and whether `qwen3:8b` is ready on every page. Details: [VM_CONNECTION_SETUP.md](docs/vm/VM_CONNECTION_SETUP.md) and [LAN_PAIRING_DESIGN.md](docs/design/LAN_PAIRING_DESIGN.md).
2. Optionally type a **goal for this round**, for example *Keep RDP usable for remote support this week*. Then click **Start agentic round**. With a goal, the Orchestrator first reads it into fixed constraints that code enforces; the Fixes tab shows how it was read. The Orchestrator delegates the Scanner and Analysis agents and submits a plan. A step bar (Scan → Analyse → Plan → Approve → Execute → Verify) shows where the round stands, and the tabs hold the detail: **Fixes**, **Risk ranking**, **Controls**, **Results** and **Agent log**.
3. In **Fixes**, enter your name once (and optionally a comment for the next decision), then approve or reject each proposal (or all undecided at once). An approval is bound to the exact request and expires after one hour. Findings the Orchestrator deferred are listed with their reasons; one it left out of its plan is shown as *not decided*.
4. **Execute approved fixes…** opens a confirmation listing each change, its current value and the approval expiry. **Confirm and execute** delegates the Remediation Agent and then a verification rescan; the page opens on **Results** with the verdicts and the next step.
5. **Run next round** to rescan, re-rank and propose again, for example once a fixed prerequisite has unblocked another finding. Earlier rounds of the session stay viewable (read-only) from the **Round** selector.
6. **Round report** downloads a self-contained HTML record of the round: target and evidence source, compliance summary, risk ranking, the agents' flags and plan, your decisions, verdicts and the verification diff. It prints to PDF.

The agentic steps happen on **Agentic hardening** once a server is connected. Switching pages keeps the connection, the session and its results. After a browser refresh, connect again and choose **Resume earlier session** to continue where you stopped. If the agents stop before finishing, **Execute remaining without AI** applies the same guards without the model: one read-only precheck, then each approved fix in rank order, closing any whose value changed or whose prerequisite is not compliant. **Overview** summarises posture and keeps an activity log. **History and drift** compares assessments and lists configuration drift. The earlier manual-file upload page was retired on 27 October 2026; its documents are in `docs/archive/legacy/` and its code is in the git history.

## Checks

From `cis_compliance_dashboard_prototype` (225 tests on 5 November 2026; fixtures, a simulated VM and UDP on this laptop's own address only, nothing touches a real server or the firewall):

```powershell
$env:TEMP = Join-Path (Get-Location) 'data\test_tmp'; $env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

From this folder, the PowerShell tests (runner, collector, cross-check parser, and the server access helper with its pairing rules):

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
- `preview_imports_servers.sqlite3`: saved servers ("My servers") and their pairing. No passwords.

In the client package the files live in `%LOCALAPPDATA%\FYP-Hardening\data` instead (set by `Start.cmd`).

Every column and JSON field is described in [DATABASE_SCHEMA.md](docs/design/DATABASE_SCHEMA.md).

Audit tables refuse updates and deletes. Server passwords stay in session memory only.

To see what is stored, use the read-only viewer. It opens every file read-only and cannot change anything. Run `--help` for every command.

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\tools\show_database.py              # files, tables, latest scans and rounds
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe scripts\tools\show_database.py round <ID> --log
```

Non-UI client (no model, no VM): `python -m hardening.framework --database data\preview_imports.sqlite3 --run <run_id>` prints a stored run's results and deterministic risk ranking; `--evidence file.json --hostname … --machine-uuid …` assesses an evidence file.

## Project layout

```text
AGENTS.md, PROGRESS.md, README.md     decisions and rules, current status, this file
cis_compliance_dashboard_prototype/   the application: app.py, launch.py, hardening/ (package), tests/, data/ (SQLite, not in git)
scripts/
  vm/              PowerShell sent to the server over WinRM (collector, remediation runner, cross-check) + their tests
  server_access/   helper run on a server: pairing by code, paired laptops, Revert; also sent over WinRM to list or
                   disconnect paired laptops
  packaging/       builds the client package (dist/, not in git)
  tools/           laptop tools: cross-check, benchmark extraction, risk derivation, approval proof, database viewer
  evaluation/      real-model probe and repeated evaluation, report figures
docs/
  design/          architecture, benchmark mapping, risk derivation, administrator goals, pairing, database schema
  vm/              VM connection setup and the real VM trial runbook
  evaluation/      agentic assessment, first VM import validation
  report/          original report text, requirements coverage, revisions, alignment plan
  figures/         generated report figures
  archive/         superseded plans and logs (legacy/ = the retired upload page)
```

## Documentation

| Document | Use it for |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Decisions D1–D7, the target and safety boundaries, working rules |
| [PROGRESS.md](PROGRESS.md) | Current status, checks run, next tasks |
| **Design** | |
| [ARCHITECTURE.md](docs/design/ARCHITECTURE.md) | Agent design, tools, guarantees, evidence |
| [BENCHMARK_MAPPING.md](docs/design/BENCHMARK_MAPPING.md) | The 32 controls, rules, benchmark pages, report ID corrections |
| [RISK_DERIVATION.md](docs/design/RISK_DERIVATION.md) | Generated risk-factor derivation for every control (`scripts\tools\generate_risk_derivation.py`) |
| [ADMIN_GOALS_DESIGN.md](docs/design/ADMIN_GOALS_DESIGN.md) | Administrator goals: design, safeguards and evaluation plan |
| [LAN_PAIRING_DESIGN.md](docs/design/LAN_PAIRING_DESIGN.md) | Pairing a server by code, paired laptops and Disconnect, the client package (D7) |
| [DATABASE_SCHEMA.md](docs/design/DATABASE_SCHEMA.md) | Every SQLite table, column and JSON field |
| **VM** | |
| [VM_CONNECTION_SETUP.md](docs/vm/VM_CONNECTION_SETUP.md) | WinRM setup, pairing with the server access helper, failure states |
| [VM_TRIAL_RUNBOOK.md](docs/vm/VM_TRIAL_RUNBOOK.md) | Step-by-step real VM trial, with the records to keep |
| **Evaluation** | |
| [AGENTIC_ASSESSMENT.md](docs/evaluation/AGENTIC_ASSESSMENT.md) | How agentic the system is: evaluations, judgement scenarios, examiner questions |
| [FIRST_VM_IMPORT_VALIDATION.md](docs/evaluation/FIRST_VM_IMPORT_VALIDATION.md) | The first real VM evidence and the verified 0 → 14 password-length change (historical) |
| **Report** | |
| [REPORT_ORIGINAL_TEXT.md](docs/report/REPORT_ORIGINAL_TEXT.md) | The original report text (reference, not instructions) |
| [REPORT_REVISIONS.md](docs/report/REPORT_REVISIONS.md) | Replacement text for report sections that no longer match the system |
| [REPORT_REQUIREMENTS_AND_COVERAGE.md](docs/report/REPORT_REQUIREMENTS_AND_COVERAGE.md), [REPORT_ALIGNMENT_PLAN.md](docs/report/REPORT_ALIGNMENT_PLAN.md) | Requirement traceability and report revisions (status columns partly outdated; see their banners) |
| [docs/archive/](docs/archive/) | Preview-era plans and logs; `legacy/` holds the docs for the legacy upload page |
