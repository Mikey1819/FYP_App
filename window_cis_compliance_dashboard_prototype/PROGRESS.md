# Progress

Full run-by-run history up to 26 October 2026: [docs/archive/PROGRESS_LOG_2026-10-17_to_2026-10-26.md](docs/archive/PROGRESS_LOG_2026-10-17_to_2026-10-26.md). Current design: [ARCHITECTURE.md](ARCHITECTURE.md).

## Current status — 26 October 2026, evening (Asia/Kuala_Lumpur)

| Area | State |
| --- | --- |
| Controls | **32 assessed** (Stand-alone v2.0.0, schema 5 `full1`): Account 9, Local Security 5, Firewall 8, Audit 5, RDP 5. The report's minimum of 30 is met. The 16 new controls were source-reviewed from extracted PDF text; VM comparison is pending. Report ID errors are documented in [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md). |
| Scanner Agent | LLM tool loop with its own WinRM channel. It also runs verification rescans. A real VM scan was validated with collector v4 (16 controls). **Collector v5 has not yet run on the VM.** |
| Analysis Agent | **LLM tool loop (new).** It reads the deterministic ranking, investigates up to 2 findings, flags up to 3 for attention and triages every gap, all with fact-checked codes. It can never change a score (D2). If it fails, the same deterministic ranking is used. |
| Orchestrator | Assessment phase: delegates Scanner and Analysis, may send the Scanner back once on a rescan request, then makes one `submit_plan`. **Remediation phase (new):** delegates the Remediation Agent and a verification rescan, then decides `finish` / `next_round` / `remediation_review`. |
| Remediation Agent | **LLM tool loop (new).** It prechecks the VM read-only, then executes (as a list, in its chosen order) or skips each *approved* request, and stops after an uncertain outcome. 21 library actions. **Real VM remediation has not been run yet.** |
| Legacy | The upload/manual-exchange page (`legacy_app.py`) and its modules are kept. Their docs moved to [docs/archive/legacy/](docs/archive/legacy/). |

## 26 October 2026, evening: Analysis and Remediation became agents; the loop is closed

**Why.** Under D6 only the Orchestrator and Scanner were agents. Analysis was a single function call, and Remediation was a button-driven loop. Nobody observed the verification result, and there was no Remediation Review state (report Figure 4.4).

**What changed** ([agentic.py](cis_compliance_dashboard_prototype/hardening/agentic.py); design in [ARCHITECTURE.md](ARCHITECTURE.md)):

- **Analysis Agent tools:** `score_findings` (deterministic engine), `inspect_finding`, `check_history`, `submit_analysis` (attention codes `regression` / `high_risk` / `unblocks_other` / `manual_fix_needed`; triage codes `rescan` / `resolves_with_prerequisite` / `manual_review`). A `rescan` triage lets the Orchestrator send the Scanner back once and re-run analysis.
- **Remediation Agent tools:** `list_approved`, `precheck` (read-only `LiveScanner.observe()`, no stored run), `execute_fixes` (control IDs, validated as a whole list before anything runs), `skip_fix` (codes `precondition_changed` / `prerequisite_not_met` / `expired` / `stop_after_failure`; records a refusal so a stale approval can never run later), `report_results`.
- **Orchestrator remediation phase:** `delegate_remediation`, `delegate_verification` (Scanner Agent rescan), `submit_review`. Fact-checked codes: `finish` and `next_round` are impossible while any fix failed, is uncertain or was not attempted.
- **Fallbacks:** code runs the verification rescan if fixes were executed but the agents never verified. **Execute remaining approved fixes without AI** is the administrator's no-model path, with the same guards.
- **Executor renamed:** `RemediationAgent` → `ApprovedActionExecutor` (it is the agent's tool, not the agent).
- **Coordinator:** tools can declare repeatable calls; one reminder when an agent answers without a tool call (`nudge`). `Limits` now allows 600 s per phase (NFR06) and 240 s per request.
- **Dashboard:** the Analysis Agent's attention flags and gap triage are shown with the ranking. Section 6 now shows the remediation-phase timeline, verdicts and the Orchestrator's next step. A no-AI fallback button appears when the agents stop early. Overview activity shows the next step.

**Real-model probes** (`scripts/probe_agentic_round.py`: real `qwen3:8b` for all four roles, **simulated VM**, all proposals auto-approved). Each failure led to one change:

| Run | Assessment | Remediation phase | What went wrong → change |
| --- | --- | --- | --- |
| 1 | Incomplete (300 s budget) | — | Analysis decision timed out after a 3 KB `score_findings` result; Orchestrator plan exceeded 120 s → compact outputs, budgets raised within NFR06 |
| 2 | 356 s, 12 proposals | 458 s: 9 verified, 3 not attempted → `remediation_review` | Analysis inspected one finding per step until its step limit; Remediation executed one fix per step and ran out of steps → investigations capped, `execute_fixes` takes a list |
| 3 | Incomplete (540 s) | — | Analysis called a 4th inspection after `investigations_left: 0`; plan included gap 1.2.1 → only currently-valid tools are offered |
| 4 | Incomplete | — | Analysis answered with nothing; Orchestrator again skipped gap 1.2.1 → one nudge; a no-op skip of a gap is ignored and recorded |
| 5 | 420 s, 12 proposals | Remediation timed out writing 12 × 32-hex request IDs | Generation runs at a few tokens/s (2.3 of 6 GB on GPU) → requests named by control ID |
| 6 | 500 s, 12 proposals (Analysis flagged too many → refused, timed out) | **131 s: 12/12 verified → `finish`** | Attention > 3 refused → extra flags dropped after fact-check; `framework_run_id` argument accepted only if it matches the current scan |
| 7 | **343 s, 12 proposals, Analysis complete** | **131 s: 12/12 verified → `finish`** | **Zero rejected calls in either phase** |

The safety properties held in every run: no write without approval, nothing executed after an uncertain outcome, and no `finish` while a fix was unattempted (run 2). Run 7 is one clean run, not a reliability rate. Probe folders: `cis_compliance_dashboard_prototype/data/agentic_probes/` (run 7: `f48a9f54…`).

**Checks.** Python suite: **241 passed** (227 before this work). New tests cover:

- Analysis investigation, flags and triage
- Contradicting codes, and the ranking surviving a failed Analysis Agent
- The rescan loop and the investigation limit
- Remediation skip, precheck and approval guards, and a list with an unready request executing nothing
- Uncertain-outcome stop and next-step code checking
- Orchestrator outage, the no-AI fallback, the nudge, ignored gap skips and dropped extra flags

PowerShell script tests were **not re-run**: the `-ExecutionPolicy Bypass` command was blocked by the session's permission policy. No PowerShell script was changed.

**Docs.** The six legacy-page docs moved to [docs/archive/legacy/](docs/archive/legacy/) with banners and fixed links. Both READMEs were rewritten. [ARCHITECTURE.md](ARCHITECTURE.md) was rewritten for the four-agent design. Stale lines in [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md) and [VM_CONNECTION.md](VM_CONNECTION.md) were corrected. Status banners were added to the two report-planning docs.

## Earlier on 26 October 2026

- Decisions D1–D6 recorded ([AGENTS.md](AGENTS.md)); scheduled automation retired; preview-era docs archived.
- WinRM channel ([VM_CONNECTION.md](VM_CONNECTION.md)). First real live scan succeeded (run `34d6be89…`, schema 4): 8 Compliant, 4 Non-Compliant (1.2.2, 1.1.1, 1.1.3, 2.3.10.3), 4 Unknown (9.3.1, NLA, 1.2.1, 1.2.4).
- **Risk derivation** (user-approved): I/P/L derived by rule from `ControlAttributes`; [RISK_DERIVATION.md](RISK_DERIVATION.md) is generated from code.
- **History and drift** (FR12/FR13, UC07): immutable ConfigurationDrift records and the **History and drift** page.
- **Control expansion** to 32 and 21 library actions; firewall-policy actions excluded for channel safety.
- **Decision D5:** an absent firewall/RDP Group Policy value is Non-Compliant; effective protection lowers E to 1.
- **Reason codes** replaced free-text model reasons (trial evidence: "remove unused services" for an anonymous-access fix).

## Next tasks

1. **User (at home):** take a VirtualBox snapshot, then run one full agentic round **and** the remediation phase on the real VM. Check that the 5 audit controls read real values (confirms the `auditpol /backup` `Setting Value` assumption). Approve a few fixes, execute, and record the Remediation Agent's precheck/execute trace and the Orchestrator's next step here. Also time both phases against NFR06.
2. **Repeat the real-model probe** several times (it takes about 8 minutes) and report the completion rate per agent. The report's Chapter 5 should state a rate, not one good run.
3. **User review of risk attributes** in [RISK_DERIVATION.md](RISK_DERIVATION.md); update report Section 4.6.2 examples (62/70 → 69/77) and state the constant-L limitation.
4. **Report revisions** listed in the 26 October review: the edition (v5.1.0 → Stand-alone v2.0.0, 36 → 32 controls), the AI-role contradiction (§4.1.2, NFR07, Fig 4.5 now that all four roles are LLM agents), FR03 Unknown/Error, Figure 4.4 with the new `next_round` / `remediation_review` outcomes.
5. Firewall policy actions: design a channel-safety precheck before adding them to the library.
6. Independent manual comparison of the 16 new controls in the VM (gpedit/auditpol).
7. Retire the legacy orchestration code (`agent_team.py`, `investigation.py`'s preview prompt, `vm_investigation.py`, `framework.py`/`lifecycle.py` paths) once the agentic page covers their evaluation evidence.
