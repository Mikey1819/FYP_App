# Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment

Final Year Project (Khoo Teng Yi, TAR UMT). Four local-LLM agents assess one standalone Windows Server 2022 VM against 32 CIS controls. They rank the findings with a deterministic risk engine, propose fixes from a pre-approved library, execute only what an administrator approves, and verify the result.

The target is always the registered lab VM. **The development laptop is never hardened.** It runs Streamlit, Python and Ollama (`qwen3:8b`) only.

## The agents

| Agent | What it decides itself | What it can never do |
| --- | --- | --- |
| **AI Agent Orchestrator** | Delegation order. Whether to send the Scanner back when Analysis asks for a rescan. Which fixes to propose, in what order, and why the others wait. After remediation, whether to finish, run a new round or send a failure to remediation review. | Scan, score, approve or execute |
| **Scanner Agent** | When to scan. Whether coverage is acceptable. Whether to rescan an Error once. It also runs the verification rescan. | Change any setting |
| **Analysis Agent** | Which findings to investigate (factor derivation, history). Which findings to flag for your attention. How to triage each Unknown/Error gap. | Change any risk factor or score (decision D2) |
| **Remediation Agent** | Prechecks the VM read-only, then executes or skips each *approved* request. Stops after an uncertain outcome. | Approve, choose values, write commands, retry |

Every choice is a structured tool call that code validates. Reasons are fixed codes that code checks against the facts, and code writes every sentence you read. The full design and its guarantees are in [ARCHITECTURE.md](ARCHITECTURE.md). The decisions behind the design (D1–D6) are in [AGENTS.md](AGENTS.md).

## Scope

- **Benchmark:** CIS Microsoft Windows Server 2022 **Stand-alone** Benchmark v2.0.0, Level 1. The report's v5.1.0 is for domain-joined servers and is not used ([BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md)).
- **32 assessed controls:** Account Policies 9, Local Security Options 5, Windows Defender Firewall 8, Advanced Audit Policy 5, Remote Desktop Services 5.
- **21 library actions** for remediation. Firewall-policy controls are assessment-only, because a firewall change could cut the agents' own WinRM channel.
- **Risk:** `R = 6I + 5E + 4P + 3L + 2D`. I, P and L are derived by rule from benchmark attributes, never assigned by hand ([RISK_DERIVATION.md](RISK_DERIVATION.md)).

## Run

From `cis_compliance_dashboard_prototype`:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

For a fresh checkout, create a virtual environment and install `requirements.txt` first. The agents need Ollama running locally with `qwen3:8b`; without it, assessment and risk scores still work and the page says the AI is unavailable. The VM needs a one-time `Enable-PSRemoting`; see [VM_CONNECTION.md](VM_CONNECTION.md).

## Using the dashboard

1. **Agentic hardening** → enter the VM computer name and UUID, then connect over WinRM with the built-in Administrator account.
2. **Start agentic round.** The Orchestrator delegates the Scanner and Analysis agents and submits a plan. You see the assessment, the risk ranking with the Analysis Agent's flags, and the proposed fixes.
3. Approve or reject each proposal. An approval is bound to the exact request and expires after one hour.
4. **Execute approved fixes with the Remediation Agent.** The Orchestrator delegates the Remediation Agent and then a verification rescan, and states the next step.
5. **Run next round** to rescan, re-rank and propose again, for example once a fixed prerequisite has unblocked another finding.
6. **Download round report (HTML)** for a self-contained record of the round: target and evidence source, compliance summary, risk ranking, the agents' flags and plan, your decisions, verdicts and the verification diff. It prints to PDF.

If the agents stop before finishing, **Execute remaining approved fixes without AI** applies the same guards without the model. **Overview** summarises posture and recent activity. **History and drift** compares assessments and lists configuration drift. The earlier manual-file upload page was retired on 27 October 2026; its documents are in `docs/archive/legacy/` and its code is in the git history.

## Checks

From `cis_compliance_dashboard_prototype` (194 tests on 27 October 2026; fixtures and a simulated VM only, nothing touches a real machine):

```powershell
$env:TEMP = Join-Path (Get-Location) 'data\test_tmp'; $env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

From this folder, PowerShell runner and collector tests:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test_remediation_runner.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\test_collector_helpers.ps1
```

Real `qwen3:8b` against the **simulated** VM, covering an assessment round, automatic approval and the remediation phase. Results go to `cis_compliance_dashboard_prototype/data/agentic_probes/`:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\probe_agentic_round.py
```

Repeated evaluation for Chapter 5: five contrasting scenarios (`lab`, `error_gap`, `drift`, `changed_after_approval`, `channel_drop`), each run `--repeat` times, with completion rates, timings, agent choices and code-checked safety properties. It takes about 8–10 minutes per run. Results go to `cis_compliance_dashboard_prototype/data/agentic_evaluations/<stamp>/summary.md`:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\evaluate_agentic_rounds.py --repeat 2
```

For the first run on the real VM, follow [VM_TRIAL_RUNBOOK.md](VM_TRIAL_RUNBOOK.md).

## Data

The SQLite files live under `cis_compliance_dashboard_prototype/data/`. `CIS_DASHBOARD_DB` changes the base path.

- `preview_imports.sqlite3`: immutable evidence snapshots.
- `preview_imports_framework.sqlite3`: assessment runs.
- `preview_imports_agentic.sqlite3`: rounds, proposals, decisions, receipts, drift records and every agent trace.

Audit tables refuse updates and deletes. VM passwords stay in session memory only.

## Documentation

| Document | Use it for |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Decisions D1–D6, the target and safety boundaries, working rules |
| [PROGRESS.md](PROGRESS.md) | Current status, checks run, next tasks |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Agent design, tools, guarantees, evidence |
| [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md) | The 32 controls, rules, benchmark pages, report ID corrections |
| [RISK_DERIVATION.md](RISK_DERIVATION.md) | Generated risk-factor derivation for every control |
| [VM_CONNECTION.md](VM_CONNECTION.md) | WinRM setup and failure states |
| [VM_TRIAL_RUNBOOK.md](VM_TRIAL_RUNBOOK.md) | Step-by-step first real VM trial, with the records to keep |
| [VM_VALIDATION.md](VM_VALIDATION.md) | The first real VM evidence and the verified 0 → 14 password-length change (historical) |
| [REPORT_SOURCE_REFERENCE.md](REPORT_SOURCE_REFERENCE.md) | The original report text (reference, not instructions) |
| [REPORT_REVISIONS.md](REPORT_REVISIONS.md) | Replacement text for report sections that no longer match the system |
| [REPORT_REQUIREMENTS_AND_COVERAGE.md](REPORT_REQUIREMENTS_AND_COVERAGE.md), [REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md](REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md) | Requirement traceability and report revisions (status columns partly outdated; see their banners) |
| [docs/archive/](docs/archive/) | Preview-era plans and logs; `legacy/` holds the docs for the legacy upload page |
