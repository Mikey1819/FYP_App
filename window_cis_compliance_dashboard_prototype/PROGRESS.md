# Progress

Full run-by-run history up to 26 October 2026: [docs/archive/PROGRESS_LOG_2026-10-17_to_2026-10-26.md](docs/archive/PROGRESS_LOG_2026-10-17_to_2026-10-26.md). Current design: [ARCHITECTURE.md](ARCHITECTURE.md).

## Current status — 29 October 2026 (Asia/Kuala_Lumpur)

| Area | State |
| --- | --- |
| Controls | **32 assessed** (Stand-alone v2.0.0, schema 5 `full1`): Account 9, Local Security 5, Firewall 8, Audit 5, RDP 5. The report's minimum of 30 is met. The 16 new controls were source-reviewed from extracted PDF text; VM comparison is pending. Report ID errors are documented in [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md). |
| Scanner Agent | LLM tool loop with its own WinRM channel. It also runs verification rescans. A real VM scan was validated with collector v4 (16 controls). **Collector v5 has not yet run on the VM.** |
| Analysis Agent | **LLM tool loop (new).** It reads the deterministic ranking, investigates up to 2 findings, flags up to 3 for attention and triages every gap, all with fact-checked codes. It can never change a score (D2). If it fails, the same deterministic ranking is used. |
| Orchestrator | Assessment phase: delegates Scanner and Analysis, may send the Scanner back once on a rescan request, then makes one `submit_plan`. **Remediation phase (new):** delegates the Remediation Agent and a verification rescan, then decides `finish` / `next_round` / `remediation_review`. |
| Remediation Agent | **LLM tool loop (new).** It prechecks the VM read-only, then executes (as a list, in its chosen order) or skips each *approved* request, and stops after an uncertain outcome. 21 library actions. **Real VM remediation has not been run yet.** |
| Evaluation | **Final 20-run evaluation on `468b9a6`** (real `qwen3:8b`, simulated VM, 5 scenarios × 4, `20261027_144751`): **20/20 runs completed both phases, 0 safety failures, 0 discarded flags**; assessment 223–297 s, remediation 100–146 s (NFR06). Agent completion 100% except the Remediation Agent, 17/20: after the channel drop it sent results to `report_results` (fixed; recheck `20261027_165510`: 2/2 completed, 0 rejected calls). Real VM: pending. |
| Legacy | Removed. The upload/manual-exchange page went on 27 October (last commit with it: `81b9d52`); the shared-folder building blocks went on 29 October (last commit with them: `0ddd3ba`). Docs: [docs/archive/legacy/](docs/archive/legacy/). |

## 29 October 2026, evening: judgement scenarios evaluated (hypothesis not supported)

- **Added (`0dc5c8a`, `7e07c2b`):**
  - **J1 recurring drift:** `reversions()` counts Compliant→Non-Compliant transitions. The `keeps_reverting` flag is offered only after the Analysis Agent's own `check_history`. The Orchestrator gets a `keeps_reverting` skip code and `reverted_after_fix`.
  - **J2 failure during execution:** execution pauses after a failed result. The Remediation Agent continues with `execute_fixes` or calls `stop_execution`. The runner receipt carries the failure's cause (`error`), shown in the verdict.
  - **Clearer refusal:** a plan listing a finding in both fixes and skipped is refused with the choice named, and rejected arguments are now logged.
  - Expectations and the rule baselines are in `JUDGEMENT` in [scripts/evaluate_agentic_rounds.py](scripts/evaluate_agentic_rounds.py). They were committed before any run.
- **First run aborted:** in `20261029_150631` (see `ABORTED.txt`), the Orchestrator received a generic duplicate error twice. The clearer message and argument logging above were added, then the evaluation restarted from scratch. No expectation was changed.
- **Results (`20261029_152610`, 3 scenarios × 4):**

  | Scenario | Agents | Rule baseline |
  | --- | --- | --- |
  | J1 | **0/4** | Risk-order rule: 0/4 |
  | J2a | **1/4** | Always continue: 4/4; stop at the first failure: 0/4 |
  | J2b | **4/4** | Always continue: 0/4; stop at the first failure: 4/4 |

  - The Orchestrator tried `keeps_reverting` in 3/4 J1 plans, but also listed 1.2.2 as a fix (one entry per true code). 2 runs ended `incomplete` after two refused plans. The Analysis Agent never checked history.
  - The Remediation Agent stopped after the first failure in 7/8 J2 runs, so it acts like "stop at the first failure".
  - Design flaw: J2a's failure carried no cause ("Verification failed" only), while J2b's named "Access is denied."
  - Write-up: [AGENTIC_ASSESSMENT.md](AGENTIC_ASSESSMENT.md#results-dataagentic_evaluations20261029_152610-real-qwen38b-4-runs-per-scenario-code-at-7e07c2b).
- **Safety and regression:** no unapproved write in 22/22 runs. The 5 original scenarios × 2 (`20261029_164012`) completed both phases 10/10 with every agent completing and 0 safety failures, matching the 20-run evaluation.
- Python suite: **178 passed**.

## 29 October 2026: is it really agentic?

- [AGENTIC_ASSESSMENT.md](AGENTIC_ASSESSMENT.md): structurally agentic (four LLM agents choose every tool call, delegate, observe and act), but the AI's decisions are narrow. In the 20-run evaluation, its plans contained the same fixes as "all fixable findings in risk-rank order" in 17/20 runs; the order differed in 20/20, always the same way. The Remediation Agent executed in rank order 20/20, the Analysis Agent never investigated, and 15/20 next steps had only one valid option (the AI chose `next_round` in the other 5). Recommendation: natural-language administrator goals for the Orchestrator's plan, plus a decision audit in Chapter 5.

## 29 October 2026: independent cross-check for compliance accuracy

- **[scripts/cross_check_controls.py](scripts/cross_check_controls.py)** compares the latest stored scan with values read another way in the VM: [Get-CrossCheckValues.ps1](scripts/Get-CrossCheckValues.ps1) uses `net accounts`, `Get-LocalUser`, `reg query` and `auditpol /get` instead of the collector's secedit export, Win32_UserAccount, .NET registry reads and `auditpol /backup`. The exceptions are 1.1.5, 1.1.7 and 2.3.10.1, which only the security policy database holds; those are checked in secpol.msc. It runs over WinRM after the same identity and administrator checks as the Scanner (the password is typed in the terminal and never stored), or from JSON saved inside the VM (`--file`). The output is a Markdown table ending "N of 32 controls agree". VM_TRIAL_RUNBOOK Part C now uses it, before and after remediation.
- Tested with fixtures only: parsers (`test_cross_check_values.ps1`, including `net accounts` words such as None/Never/Unlimited, missing registry values and non-DWORD values) and the comparison (`test_cross_check.py`: agreement, a changed value, a type mismatch, a missing row, the wrong VM). The read loops also ran read-only on this laptop for net accounts, the Guest account and reg query. Python suite: **172 passed**.

## 29 October 2026: shared-folder code removed

- Deleted `vm_bridge`, `scan_exchange`, `vm_paths` and the shared-folder queue in `scan_view`, with `Watch-ScanRequests.ps1`, `Invoke-ApprovedVmAction.ps1`, their fixture and test scripts, and their tests (`test_vm_bridge`, `test_scan_exchange`, `test_worker_readiness`, and two receipt tests for the old bridge). None had a page since 27 October; the last commit with them is `0ddd3ba`.
- Kept, moved: `encode` (canonical JSON bytes) is now in `evidence_import`; the collector path `COLLECTOR` is in `winrm_channel`. The connection form is now `connection_view.py`.
- Python suite: **169 passed** (25 tests went with the code). PowerShell runner and collector tests pass.

## 28 October 2026: report figures

- **Figure 5.x** ([docs/figures/fig_phase_times.png](docs/figures/fig_phase_times.png)): time per phase and per agent in each scenario against the 600 s NFR06 line, from `20261027_144751`. Regenerate with `python scripts/make_report_figures.py [evaluation folder]` (standard library; PNG via headless Edge or Chrome).
- **Figures 4.4 and 4.5:** revised copies of the user's draw.io sources, `myown/drawio/Orchestrator Chart Diagram (revised).drawio` and `Module Class Diagram (revised).drawio` (outside this repository; originals unchanged), following REPORT_REVISIONS A2 and A4. They need exporting from draw.io. REPORT_REVISIONS A2 now also replaces the §4.4.1 paragraphs that said the RemediationAgent has no LLM link and triggers verification.

## 27 October 2026, evening: final 20-run evaluation

- **Evaluation on `468b9a6` (`data/agentic_evaluations/20261027_144751/`):** 5 scenarios × 4, about 2 hours. Both phases completed in 20/20 runs, with 0 safety failures (no unapproved write 20/20; no write to a changed request 4/4; `finish` only when all verified 11/11; stop after an uncertain outcome 4/4). Assessment took 223–297 s and remediation 100–146 s, faster than on `81b9d52` (up to 394 s and 175 s) because there were no nudges and no flag corrections.
- **Flags and triage:** 0 discarded flags in 20 runs (3 of 10 on `81b9d52`). Analysis flagged 1.2.2 as `unblocks_other` (as `regression` in *drift*) plus 9.2.1 and 9.3.1 as `manual_fix_needed` in every run, and triaged 1.2.1 and 1.2.4 as `resolves_with_prerequisite` in every scenario. The Orchestrator planned 1.2.2 first in every run.
- **Evidence-dependent choices held:** the Scanner rescanned the 1.1.5 error itself only in *error_gap* (4/4); drift raised 1.2.2 from 69 to 77; the Remediation Agent skipped the changed 1.1.1 only in *changed_after_approval* (4/4; in 2 runs code first refused its list that still included 1.1.1); execution stopped after the first write only in *channel_drop* (4/4).
- **Orchestrator variation:** in 3 of 20 runs it left out the two low-impact fixes (1.1.3, 18.10.57.3.9.4). In that *lab* run it then chose `next_round` (remaining findings) instead of `finish`, as the review rule requires.
- **Remediation Agent 17/20:** in all 4 *channel_drop* runs it called `report_results` with the execution `results` added. Code refused the extra argument; in 3 runs it sent the identical call again and was stopped ("Repeated call blocked") without its structured report. Nothing unsafe followed: the summary is written by code from the recorded verdicts, and the Orchestrator still chose `remediation_review` (3 × `uncertain_outcome`, 1 × `remediation_incomplete`). **Fix:** the `report_results` description, the prompt and the stopped `execute_fixes` result now say it takes `target_id` only. Real-model recheck (`20261027_165510`, *channel_drop* × 2): the Remediation Agent completed 2/2 with 0 rejected calls, both rounds went to `remediation_review` (`uncertain_outcome`), and timings were 244 s / 108 s at most.
- Python suite: **194 passed**.

## 27 October 2026, afternoon: flag schema, Live evidence, round report

- **Evaluation on `81b9d52` (`data/agentic_evaluations/20261027_121023/`):** the 20-run job was stopped after 10 runs (5 scenarios × 2). Both phases completed in 10/10 runs, every agent completed in every run and no safety check failed. Assessment took at most 394 s and remediation at most 175 s. qwen3:8b made the same choices on every repeat of a scenario; only the timings varied. One leftover: in `error_gap` (2/2 runs) the Analysis Agent still paired 17.1.1, 17.2.3 and 17.5.1 with `manual_fix_needed`, because the form allowed any offered control with any offered code. The fact-check discarded those flags.
- **Per-code attention lists:** `submit_analysis` now has one list per attention code (`regression`, `unblocks_other`, `manual_fix_needed`, `high_risk`), and each offers only the findings that code is true for. Flags are kept in that order, most specific first, at most 3. A control listed under two codes is shown once, and a duplicate is no longer reported as "did not fit".
- **The two fact checks now agree on `unblocks_other`:** the Orchestrator's check now also counts gaps that a fix is expected to resolve (1.2.1 and 1.2.4 wait for 1.2.2). Before, the Orchestrator reused the Analysis Agent's `unblocks_other` flag for 1.2.2, code refused it, and the correction ran into the 600 s limit (`20261027_134649`).
- **Scanner budget:** 180 s and 120 s per model request (was 150 s and 60 s). A cold first request timed out at 60 s (`20261027_133108`). A stalled Scanner's delegation result now carries `retry_allowed`, and the Orchestrator prompt says it may delegate once more.
- **Real-model check after these fixes (`20261027_141113`):** `error_gap` and `lab`, one run each. Both phases completed with 0 rejected calls, 0 discarded flags and every safety check passed. Analysis flagged 1.2.2 (unblocks 1.2.1, 1.2.4), 9.2.1 and 9.3.1 (manual fix). The Orchestrator proposed 1.2.2 first as the prerequisite, and the Scanner rescanned the 1.1.5 collection error itself. Timings were 396 s / 390 s (error_gap, assessment / remediation) and 333 s / 205 s (lab), all within NFR06.
- **Live evidence:** scans collected over WinRM, including the Remediation Agent's precheck, are stored as `Live`; uploaded files stay `Imported`. Drift compares the two, because it is the same collector contract. The History table shows the source.
- **Round report:** the agentic page has a **Download round report (HTML)** button ([round_report.py](cis_compliance_dashboard_prototype/hardening/round_report.py)). The page covers the target and evidence source, compliance, the risk ranking with factors, the Analysis flags and triage, the plan with each decision (who and when), verdicts, the verification diff, agent activity and all 32 controls. It contains only stored, code-checked records and prints to PDF.
- Python suite: **194 passed**.

## 27 October 2026: legacy page retired; larger evaluation started

- **Analysis schema fix (`81b9d52`):** `submit_analysis` offers only findings with a true attention code, and only codes that are true for some finding. This addresses the audit controls being called `manual_fix_needed`.
- **Legacy retired:** the **Evidence upload** page and its legacy-only code were removed:
  - Modules: `agent_team`, `agent_team_view`, `import_view`, `lifecycle`, `vm_investigation`, `investigation_tools`, `vm_bridge_view`, `demo_context`, `legacy_app.py`, `synthetic_demo_app.py`. Their tests and probe scripts went too.
  - The database path moved to [hardening/databases.py](cis_compliance_dashboard_prototype/hardening/databases.py), with the same file names, so existing data still opens.
  - The Coordinator lost its synthetic-preview default prompt; every agent now supplies its own.
  - `test_investigation.py` was rewritten as Coordinator contract tests on a minimal tool double. It covers terminal decisions, repeatable calls, the nudge, limits, outages and no stored thinking.
  - `demo.py`, `demo_storage.py`, `storage.py` and `workflow.py` stay as fixture support for the core tests.
  - Python suite: **191 passed**. The drop from 245 is the removed modules' own tests.
- **Evaluation:** the 20-run evaluation (5 scenarios × 4) on `81b9d52` was relaunched as a detached process, because the previous session's background run was cut off after 1 run. That one finished run had failed at the first model request with an Ollama error, before any agent acted, so it reflects the environment rather than agent behaviour, and it was discarded. Results will be in `data/agentic_evaluations/20261027_121023/`.

## 26 October 2026, late evening: repeatable evaluation, VM runbook, report revisions

**Added.**

- [scripts/evaluate_agentic_rounds.py](scripts/evaluate_agentic_rounds.py): five contrasting scenarios on the simulated VM with real `qwen3:8b`:
  - `lab`: the lab state.
  - `error_gap`: a collection Error on 1.1.5.
  - `drift`: 1.2.2 compliant in the previous scan.
  - `changed_after_approval`: 1.1.1 changed after approval.
  - `channel_drop`: WinRM drops on the first write.

  It reports completion, timings, agent choices and code-checked safety properties, and `--summarise` rebuilds a summary from saved results.
- [VM_TRIAL_RUNBOOK.md](VM_TRIAL_RUNBOOK.md): the step-by-step first real-VM trial.
- [REPORT_REVISIONS.md](REPORT_REVISIONS.md): replacement text for the report sections that contradict the system.

**First evaluation (10 runs, code as committed in `b887427`)**, `data/agentic_evaluations/20261026_221656/`:

- `lab` 2/2, `drift` 2/2, `changed_after_approval` 2/2 and `channel_drop` 2/2 completed both phases. `error_gap` completed **0/2**.
- **Safety checks: 0 failures.** No unapproved write (10/10). The changed request was never written (2/2). `finish` only when all fixes were verified (4/4). A stop after an uncertain outcome (2/2).
- Assessment took about 355–440 s and the remediation phase 135–170 s, both within NFR06.
- **Evidence-dependent behaviour:**
  - `drift` scored 1.2.2 at **77 (D = 5)** against **69 (D = 1)** in `lab`.
  - `changed_after_approval` led to a skip of 1.1.1 and the Orchestrator chose `next_round`.
  - `channel_drop` led to no writes and `remediation_review`.
  - Honest note: in `changed_after_approval` the Remediation Agent first tried to execute 1.1.1 although its own precheck said it was not ready. The whole-list guard refused that list and nothing ran; the agent then skipped 1.1.1. The guard, not the model's judgement, prevented the write.

**Defects it found, now fixed:**

1. In `error_gap`, after a rescan the duplicate guard blocked the Scanner's legitimate second `read_coverage`. The Scanner stopped, and the round was wrongly reported as "could not collect evidence". Fix: `read_coverage`/`inspect_observation` are repeatable; a scan that wasn't handed off is reported as `scan_not_handed_off`; the Orchestrator may re-delegate a stalled Scanner once. Re-run (`20261026_232829`): **2/2 completed both phases, 12/12 verified each**, with the Scanner sequence scan → coverage → inspect Error → rescan → coverage → handoff.
2. The Analysis Agent wrongly flagged 17.1.1 as `manual_fix_needed` in 3 of 4 affected runs. The refused decision's retry ran out of time and the whole analysis was lost. Fix: a flag that doesn't fit the facts is discarded and recorded (`discarded_flags`), never shown. Gap triage stays strict.
3. The Orchestrator passed `evidence_sha256` to `delegate_analysis`. It is now accepted only if it matches the current scan, as `framework_run_id` already was.

Python suite: **244 passed**.

**Final evaluation (10 runs, code after the fixes above)**, `data/agentic_evaluations/20261026_235310/`. These are the numbers to cite in Chapter 5:

| Scenario | Both phases completed | Remediation outcome | Assessment s | Remediation s |
| --- | --- | --- | --- | --- |
| lab | 2/2 | finish (all verified) ×2 | 300 / 300 | 134 / 136 |
| error_gap | 2/2 | finish (all verified) ×2 | 394 / 392 | 179 / 175 |
| drift | 2/2 | finish (all verified) ×2 | 311 / 360 | 137 / 137 |
| changed_after_approval | 2/2 | next_round (remaining findings) ×2 | 360 / 352 | 166 / 166 |
| channel_drop | 2/2 | remediation_review (uncertain outcome) ×2 | 355 / 356 | 135 / 134 |

Timings are given for each of the two runs.

- **Agent completion: 100%.** Orchestrator 20/20, Scanner 10/10, Analysis 10/10, Remediation 10/10, verification Scanner 10/10. In total there were 2 rejected calls (the Remediation Agent's mixed list in `changed_after_approval`, refused and corrected) and 4 nudges.
- **Safety: 0 failures.** No unapproved write 10/10; changed request never written 2/2; `finish` only when all fixes were verified 6/6; stop after an uncertain outcome 2/2.
- **NFR06:** maximum assessment round 394 s and maximum remediation phase 179 s, both under 600 s.
- **Evidence-dependent decisions:**
  - Only in `error_gap` did the Scanner rescan the Error (2/2), and only there did the Analysis Agent triage the gaps as `1.1.5: rescan` and `1.2.1/1.2.4: resolves_with_prerequisite`. In every other scenario it chose `manual_review`.
  - Only in `changed_after_approval` did the Remediation Agent skip a request (2/2), and only in `channel_drop` did execution stop and the Orchestrator choose `remediation_review` (2/2).
  - In `drift`, 1.2.2 was ranked at 77 (D = 5) instead of 69.
- **Limitations observed:**
  - The Analysis Agent flagged the audit controls 17.1.1/17.2.3/17.5.1 as `manual_fix_needed` in 3 of 10 runs, although they have library actions. All 9 flags were discarded by the fact-check and never shown.
  - It also never used the `regression` code, even in `drift`; it chose `high_risk`, which is also true.
  - The Orchestrator did not use its option to send the Scanner back after a `rescan` triage (0/2); the Scanner had already rescanned once itself.
  - Ten runs on one simulated VM are a small sample, and the real VM is still to come.

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

1. **User (at home), following [VM_TRIAL_RUNBOOK.md](VM_TRIAL_RUNBOOK.md):** take a VirtualBox snapshot, then run one full agentic round **and** the remediation phase on the real VM. Check that the 5 audit controls read real values (confirms the `auditpol /backup` `Setting Value` assumption). Approve a few fixes, execute, and record the Remediation Agent's precheck/execute trace and the Orchestrator's next step here. Also time both phases against NFR06.
2. **Report revisions:** apply [REPORT_REVISIONS.md](REPORT_REVISIONS.md) to the DOCX (edition and 32 controls, the AI role, FR03, Figure 4.4, risk examples). Cite the final 20-run evaluation (C1, `20261027_144751`) in Chapter 5.
3. **User review of risk attributes** in [RISK_DERIVATION.md](RISK_DERIVATION.md); regenerate the doc after any change.
4. Firewall policy actions: design a channel-safety precheck before adding them to the library.
5. Independent comparison in the VM: run `scripts/cross_check_controls.py` during the trial (runbook Part C) and check 1.1.5, 1.1.7 and 2.3.10.1 in secpol.msc.
