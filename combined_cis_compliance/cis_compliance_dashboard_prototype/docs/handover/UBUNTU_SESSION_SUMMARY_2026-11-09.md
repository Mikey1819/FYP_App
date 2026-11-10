# Ubuntu framework: what was built and decided (sessions up to 10 November 2026)

Handover for a new conversation that will revise the FYP report to match the framework. Everything here is
committed on `main` (latest: `79b56000 Ubuntu: consistent UI`). Detailed, dated entries are in
[`../../../PROGRESS.md`](../../../PROGRESS.md); the architecture is in [`../UNIFIED_ARCHITECTURE.md`](../UNIFIED_ARCHITECTURE.md).

## 1. The project in one paragraph

A unified Streamlit dashboard (runs on the administrator's laptop) assesses and hardens **Windows Server 2022
(stand-alone, the teammate's part)** and **Ubuntu 22.04.5 LTS (this student's part, 30 CIS controls)** against CIS
benchmarks. A server is added only by a one-time **pairing code** (no address typed). A local LLM (`qwen3:8b` on Ollama)
**coordinates** agents; it never computes compliance or risk, never writes commands, never approves. Risk is
deterministic: `R = 6I + 5E + 4P + 3L + 2D`. Every change needs an administrator approval bound to the exact server,
round, evidence and parameters, runs once, and is checked by a fresh verification scan.

Repository: `C:\Users\teohk\OneDrive\Documents\GitHub\FYP_App`, app folder
`combined_cis_compliance\cis_compliance_dashboard_prototype`, venv `combined_cis_compliance\.venv-integration`.
Tests: `..\.venv-integration\Scripts\python.exe -B -m unittest discover -s tests` (last full run: **863 OK, 1 skipped**);
protected Windows files: `-B -m tools.baseline` (exit 0).

## 2. Ubuntu agents (level with the Windows engine's six agent features)

| Agent | What it does (tools are validated by code) |
|---|---|
| **AI Agent Orchestrator** (assessment) | Delegates Scanner and Analysis, submits the plan (fix or defer per Non-Compliant control, only registered actions, reasons from fixed vocabularies). May re-delegate the Scanner once (retry or `rescan` triage). |
| **Scanner Agent** | Collects evidence over SSH with the pinned helper; `inspect_observation` (sub-check states only, raw values never reach the model); verification mode for the rescan after execution. |
| **Analysis Agent** | Reads the deterministic ranking, `inspect_finding`, `check_history` (earlier statuses, D factor), flags (`highest_risk`, `affects_remote_access`, `persistent_failure`) and triage of gaps. |
| **Remediation Agent** (`backends/ubuntu/remediation_agents.py`) | `list_approved`, `precheck` (expiry + fresh read-only preview vs approved digests), `skip_fix`, `execute_fixes`, `stop_execution`, `report_results`. |
| **Orchestrator review** | After execution: `delegate_remediation`, `delegate_verification`, `submit_review` with `finish` / `next_round` / `remediation_review`, reason codes checked against recorded results. |
| **Finding explanation** | "Explain with local AI" (max 90 words from code-written facts, labelled unverified, does not affect the score). |

## 3. Where a fix comes from and how it is proven (for the report's method/validation chapters)

- **Basis:** CIS Ubuntu Linux 22.04 LTS Benchmark **v2.0.0**, pinned by SHA-256 in `catalogues/source-lock.json`, with
  ComplianceAsCode **v0.1.80** (CIS mapping + OpenSCAP datastream, also hash-pinned).
- **Catalogue:** `catalogues/ubuntu2204.json`, one entry per control: benchmark page, assessment contract, remediation
  contract, SCAP rule IDs, direct probe, registered action, `review_status: approved`, coverage.
- **Fix code:** one registered action per control (`backends/ubuntu/actions.py`) grouped in families
  (`vm/ubuntu/family_*.py`: sysctl, ssh, auth, aging, package, ufw, cron, grub, audit, service, …), Python stdlib only,
  applying exactly the benchmark value (e.g. `kernel.randomize_va_space=2`, benchmark p.151). Parameters come from a
  deterministic planner reading the evidence, never from the model.
- **Plan binding:** evidence hash, server identity, before-state hash, expected after-state hash, implementation hash,
  recovery plan. Changed state at run time → refused, nothing written.
- **Execution:** ledger claim → one SSH dispatch → systemd-supervised runner on the VM → receipt. Never retried.
- **Proof:** a fresh verification scan with two independent checks (the app's direct probe and the pinned OpenSCAP
  rule); Results shows the before → after changes. Restore returns the saved before-state.
- **No Ansible:** deliberately not used (`docs/handover/PROJECT_HANDOVER.md`): a playbook can run arbitrary tasks;
  here every change is a fixed, approved, recorded action.
- **Honest status:** the catalogue marks fixes `fixture_tested` (logic, refusals, verification and recovery tested
  against recorded states). Live VM evidence in PROGRESS: 3.3.2 applied, rescan Compliant, restore returned it. Not
  every one of the 30 fixes has been run live; the new UI work below has not been seen live on the VM.

## 4. Maintenance (auxiliary, never counted as CIS fixes)

- **Package-list refresh** (`apt-get update`, installs nothing): offered **only** when a package install
  (1.3.1.1 AppArmor, 6.3.1.1 auditd) could not be planned or run; after it runs, start a new round.
- **Reboot** (boot-ID verified): offered **only** after an applied fix that completes at the next boot (6.3.1.3 GRUB
  `audit=1`); names only those fixes. Cannot be undone (snapshot is the recovery).
- Neither changes scan results by itself; neither can turn a Deferred or Unknown control into a fix.

## 5. Ubuntu page, now matching the Windows page

- Same tabs: **Fixes, Risk ranking, Controls, Results, Agent log**.
- **Risk ranking:** "Finding details" selector with factors, rule per factor, rationale and **Explain with local AI**.
- **Fixes:** Windows-style rows with Approve/Reject, "Approve/Reject all undecided"; execute bar
  "Execute N approved fix(es)…" → confirmation → **Confirm and execute** (agents run the remediation phase; while the
  model is unavailable it runs in plan order). **Execute remaining without AI** appears only after the agents stop early;
  the outcome then reads "Executed without AI". Safety check shown only when needed.
- **Results:** Orchestrator review, execution results ("Nothing has been executed for this round yet." /
  "Nothing to execute in this round." before anything ran), and **Configuration changes found by the verification
  rescan** (status and sub-check changes, no raw values).
- **Agent log:** per phase a summary table (Agent, Status, Decision, Tool calls, Seconds, Engine) and one expandable
  card per agent with every step (Step, Event, Tool, Arguments, Result or error).
- **Step bar:** `1 Scan → 2 Analyse → 3 Plan → 4 Approve → 5 Execute → 6 Verify → <outcome>` with the Windows labels
  (Next round recommended, Finished, Needs your review, Executed without AI, Agents stopped early).
- **Round picker** (as on Windows, from the second round of a session; earlier rounds read-only) and a downloadable
  **Round report** (self-contained HTML, prints to PDF; six sections: outcome, risk ranking, fixes and decisions,
  remediation and verification, agent activity, all controls; model text excluded).
- "Refresh status" button removed.
- A new round is offered only when nothing in the current round awaits a decision or execution (both platforms) —
  this is why "Run next round" can be missing.

## 6. Teammate's recent Windows work (pulled, not written here)

Controls the program does not fix (manual steps, accept as exception), agents finish cleanly when only manual
findings remain, Complete hardening (final read-only scan, session becomes read-only with a completion report), phase
timer under the step bar, repeated-click protection on login/pairing, failure paths without dead ends.

## 7. Rules that still apply

- Never harden the development laptop. VM changes, package installs, firewall/SSH/PAM/sudo changes, reboots or
  snapshot restores need the user's explicit approval for that action.
- No credentials in chat, prompts, logs or databases; the VM password must never be used or repeated.
- Protected Windows files (checked by `tools.baseline`) are not edited.
- Commits only when asked, on `main`, **with no Claude co-author line**; the user pushes themselves.
- **The student's own report (Ubuntu part) is `C:\Users\teohk\Downloads\Teoh Kai Hong FYP Report .md`** (note the
  space before `.md`). It is outside the repository. `combined_cis_compliance/docs/report/` is the **teammate's**
  (Windows) report: reference only, not to be edited for this student. Do not claim live results from fixture tests.

## 8. Useful files for the report

- The report to revise: `C:\Users\teohk\Downloads\Teoh Kai Hong FYP Report .md`
- `combined_cis_compliance/AGENTS.md` (decisions D1–D7), `README.md`, `PROGRESS.md`
- `combined_cis_compliance/docs/report/` (the teammate's Windows report and its alignment notes; reference only)
- `cis_compliance_dashboard_prototype/docs/UNIFIED_ARCHITECTURE.md`, `docs/handover/PROJECT_HANDOVER.md`
- `combined_cis_compliance/docs/vm/VM_CONNECTION_SETUP.md` (pairing, WinRM/SSH, failure states)
