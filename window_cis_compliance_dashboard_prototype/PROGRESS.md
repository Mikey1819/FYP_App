# Development progress

## Current handoff

- **Status:** DEMO_READY (synthetic evidence and simulated execution; not PREVIEW_COMPLETE)
- **Acceptance progress:** 10/11 criteria supported = **90.9% (about 91%)** for the initial preview. This is an equally weighted checklist count, not an estimate of effort, live readiness or whole-FYP completion. A11 remains pending; visual QA and spoken practice remain outstanding.
- **Preview:** 22 October 2026, Malaysia time
- **Delivery target:** 21 October 2026, 23:59 Asia/Kuala_Lumpur
- **Current milestone:** P5 source review and collector/import preparation completed; latest suite 70 tests passed. P6 technical rehearsal previously passed for synthetic scope. A11 real evidence/manual agreement and imported-data dashboard integration remain pending, along with visual QA/spoken practice.
- **Next task:** Help the user set up Guest Additions and the dedicated FYP-Exchange shared folder using VM_EVIDENCE.md, then run the prepared collector inside the confirmed Server 2022 VM. Review the returned JSON against independently supplied hostname/UUID and manual observations before dashboard integration. Do not run the actual collector against the laptop. The shared folder and real collection have not yet been completed. Preserve DEMO_READY; A11 remains pending.
- **Do not wait for the VM to do P1-P4.** Label synthetic evidence and unverified catalogue entries.
- **Stop rule:** Honor PREVIEW_COMPLETE or DEADLINE_HANDOFF in DEVELOPMENT_PLAN.md.

## Confirmed environment

| Item | Evidence/status |
| --- | --- |
| Application | `cis_compliance_dashboard_prototype/app.py`; five synthetic controls, six views, SQLite assessments/workflow/investigation events; real local qwen3 investigation on request, simulated execution only |
| Python environment | Existing `cis_compliance_dashboard_prototype/.venv`; use its interpreter |
| Ollama service | `http://localhost:11434`; `/api/version` returned `0.40.5` on 17 October 2026 |
| Selected local model | `/api/tags` listed `qwen3:8b`, GGUF Q4_K_M, 8.2B, 5,225,388,164 bytes, with completion/tools/thinking capabilities |
| Loaded model state | `/api/ps` initially returned an empty list; service was running, no model loaded at that moment |
| CLI availability | `ollama` was not resolved on this shell's PATH; HTTP API works, so CLI presence is not a blocker |
| Windows Server target | User screenshot supplied 19 October: Server 2022 Standard Evaluation, version 10.0.20348/build 20348, 64-bit, PartOfDomain=False, DomainRole=2. VM shown as FYP-Server2022-Manual. Identity is not yet independently collected/imported |
| Recovery snapshot | User confirms step 1 completed: Clean_Server2022_Before_Hardening; existence/restore not independently tested |
| Benchmark source | Stand-alone v2.0.0 PDF reviewed for five controls; SHA-256 and exact pages/profile recorded in BENCHMARK_MAPPING.md. General v5.1.0 retained only as report reference |
| Evidence transfer | User needs help; VM_EVIDENCE.md specifies Guest Additions and FYP-Exchange share. Prepared ignored data/vm_exchange/Collect-Server2022Evidence.ps1; share not configured or tested |
| Schedule | User reports an automation card every five hours from 17 October 22:29 Malaysia time; activation and subsequent runs are not independently verified here |

## Completed preparation

- Reviewed report requirements, system diagrams, UI screenshots and current source in the earlier review.
- Agreed direction: one bounded local AI coordinator, validated fixed rules, deterministic security operations, explicit human approval, SQLite history.
- Created root instructions and development plan with phased work, measurable acceptance criteria and truthful completion states.
- Added an ownership-token run guard for cooperating development runs.
- Corrected README commands to enter the actual application subfolder and clarified the screenshot directory status.

## Validation record

Earlier read-only review on 17 October used Streamlit AppTest: all six views rendered without exceptions; simulated approval/verification and rejection paths passed. This did not validate a backend, live server or local model integration.

Preparation checks completed on **17 October 2026, approximately 21:36 Malaysia time (UTC+08:00)**:

- Local API GET `/api/version`, `/api/tags`, and `/api/ps` succeeded. CLI lookup alone was unavailable; no install is needed to use the API.
- POST `/api/chat` to local `qwen3:8b`, with `think=false`, `temperature=0`, `num_predict=128`, `keep_alive=1m`, and a 120-second timeout, returned a structured call to `get_control_reference` with `control_id=DEMO-NLA`. Only synthetic prompt content was supplied; no benchmark/report or server data was sent.
- That single request took **75.68 seconds**, with **39.99 seconds model load duration**, and generated 25 output tokens. This is one cold-start observation, not a throughput benchmark. Warm latency and full multi-step reliability remain untested.
- The probe offered one tool and explicitly requested it. It establishes basic local tool-call compatibility, **not A05** (adaptive selection among multiple tools).
- Used the existing virtual-environment Python for an inline preparation check: all four project documents exist and decode as UTF-8; the guard parses; README paths resolve.
- Run guard checks passed: second acquisition returns exit 2; wrong ownership token cannot release the active lock; status omits the token; matching ownership token releases successfully; a subsequent acquisition succeeds.
- `git diff --check` passed. Git warned about its configured LF-to-CRLF conversion for README, not whitespace errors.
- Application source and dependency requirements were not changed in preparation. Earlier Streamlit baseline checks remain the available UI evidence; they were not rerun solely for documentation changes.

P0 is complete. P1 should preserve the existing simulation while introducing testable domain logic. Keep agent prompts/tool responses compact and measure warm calls before setting the demo's performance expectations.

## Acceptance status

- A01: passes for the current synthetic stage; six views render and identify target, unvalidated profile, SQLite assessment backend and real local model investigation on request. Documented Streamlit startup and UI callbacks checked in the 18 October technical rehearsal.
- A02: passes for synthetic evidence; five typed results include expected rules, status, timestamp, coverage and explicit provenance. No live CIS validation is claimed.
- A03: comparison/risk boundary and invalid-input tests pass; risk is computed outside the UI. Connected coordinator tool-boundary tests also pass; the model cannot set numeric risk scores.
- A04: passes for synthetic scope. Assessments/risk and separate verification survive process restart; history compatibility and original snapshot preservation tested.
- A05: passes for two real qwen3:8b investigations on the same final code with different synthetic context: compatible clients produced a proposal; legacy clients added a history lookup and finished with operational review/no proposal. See LOCAL_MODEL_VALIDATION.md for exact traces, timings and the earlier blocked attempt.
- A06: boundary/fallback tests pass for exact schemas, forbidden tools, target scope, step/call/repeat/time limits, malformed responses and model outage. Latest full suite has 70 passing tests, including new offline import validation; model failures preserve the deterministic dashboard.
- A07/A08: pass for the supported synthetic NLA action. Exact proposal binding, zero rejected writes, concurrent/restarted duplicate prevention, separate read-back, failed verification and fresh-approval retries tested. Demo administrator identity is not production authentication; no live execution is supported.
- A09: real investigation events preserve tool names, arguments, returned evidence references and public summaries, with model/provenance labels. Raw thinking is excluded; model-client and coordinator tests cover this.
- A10: technical walkthrough passed on 18 October through Streamlit UI callbacks with two real model scenarios, rejection, approval, failed verification, separate-process restart and labelled outage fallback; 137.547 seconds. See REHEARSAL_RESULT.md. Visual browser QA and spoken presentation timing remain untested.
- A11: pending. Source/profile and five mappings reviewed, VM OS/role established from screenshot and snapshot user-confirmed. Real collector execution, machine-readable identity, transfer verification and independent manual comparisons remain required. Importer is tested with fixtures only and is not yet wired to the dashboard.

## External dependencies and questions

1. Preserve the installed standalone VM and user-confirmed snapshot; collect its exact identity/build/role in the future read-only export.
2. Use the reviewed Stand-alone v2.0.0 five-control subset from BENCHMARK_MAPPING.md; validate collector/manual agreement on the actual VM.
3. Help configure the dedicated VirtualBox shared folder described in VM_EVIDENCE.md, then inspect the imported file before app integration; no remote access service is required.
4. Select and authorize a lab remediation only when the target and recovery approach are clear. The host laptop is never a remediation target.

These dependencies block A11 and real execution, not domain/storage/model/UI development. No production credentials or network target discovery is needed for the scheduled preparation work.

## Update format for each run

While working, save a checkpoint at least every two minutes and before long checks (user instruction, 18 October). Record saved changes, actual test results or "not yet tested", unfinished work and the exact next action. Do not infer that a checkpoint means a development lock is free.

Append: Malaysia timestamp; run purpose; files/behavior changed; exact validation commands and outcomes; newly satisfied acceptance IDs; blockers; next concrete task. Update the current handoff at the top. Record skipped/failed runs honestly. Never replace real results with expected results.

## Run 17 October 2026 approximately 21:41 Malaysia time

Purpose: complete P1 while preserving the existing six-view demonstration. Acquired the cooperative development lock; no other development run was active.

Changes:

- Added UI-independent frozen control/evidence/result types and explicit Synthetic/Imported/Live provenance in `hardening/domain.py`.
- Implemented exact typed equality, numeric minimum and inclusive range rules. Missing evidence is Unknown; failed collection and type mismatch are Error. Booleans cannot masquerade as numeric counts.
- Added coverage/compliance summaries, compatible historical comparison, separate regression/improvement descriptions, the documented D=1/3/5 rule, and validated risk arithmetic/classification.
- Moved five synthetic controls and their history to `hardening/demo.py`; all IDs are DEMO IDs with unverified candidate references. Password uses an at-least-14 demo rule; lockout uses a 1-to-10 demo range. These are not asserted as validated benchmark requirements.
- Replaced duplicated UI scores with calculated values. Corrected lockout to 70; NLA remains 85 and password 56. Marked factor inputs and explanatory text as illustrative.
- Updated the UI to identify simulation/service roles, show evidence coverage/provenance/timestamps, retain original snapshots separately from simulated verification, and retain approval/rejection comments in session memory. Added state guards to prevent repeat or out-of-phase simulated decisions.
- Escaped text in table/metric/detail HTML helpers and used plain text for review comments. Added Error/Unknown filtering.
- Documented launch/test commands and honest current capabilities in README.

Validation:

- From `cis_compliance_dashboard_prototype`, ran `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v`: **17 tests passed in 7.266 seconds**.
- Tests cover minimum/range boundaries, invalid types, missing/error evidence, metadata validation, immutable snapshots, incomplete coverage, mismatched history, persistent non-compliance, risk bounds, repeatable scores, all six UI views/filters, approval/rejection, comment retention, original snapshot after verification, and disabled repeat approvals.
- Streamlit emitted its expected test-context warning; no app exceptions occurred.
- `git diff --check` passed before final documentation handoff; only Git line-ending conversion warnings were present.
- No PowerShell assessment or remediation, database, model request, benchmark validation or live target access was performed in this milestone.

Next: P2 persistence. External VM/benchmark dependencies remain unchanged; they do not block SQLite work. Do not mark the full preview complete.

## Run 18 October 2026, 02:43 Malaysia time (UTC+08:00) - working checkpoint

Acquired the development lock. Implementing the first bounded part of P2: SQLite immutable assessment snapshots, compatible history lookup, risk-input records and separate verification evidence. Added the two-minute checkpoint requirement to AGENTS.md. Application changes not yet made or tested. Next: implement a repository with versioned schema and transactional snapshot writes, then prove retrieval in a new process and refusal to overwrite snapshots. Later P2 proposal/decision/execution/agent-event storage remains pending; VM/benchmark dependencies unchanged.

### Checkpoint 18 October 2026, 02:44 Malaysia time (UTC+08:00)

Saved `hardening/storage.py` with a schema-versioned SQLite repository, transactional immutable snapshots, deterministic risk calculations with source/history references, typed round trips and compatible prior-result lookup. Saved `hardening/demo_storage.py` and connected dashboard projections to stored synthetic snapshots; ignored the local data directory. Not yet tested. Scope refined to P2 assessment/risk/history storage in this run; separate verification/workflow records will follow with the workflow contract, rather than inventing an execution record now. Next: add restart, duplicate/overwrite, rollback, history-isolation and UI storage-failure tests, then run the full suite. Lock remains owned by this run.

### Checkpoint 18 October 2026, 02:45 Malaysia time (UTC+08:00)

Saved storage and UI tests. Full suite command from application folder: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v`. First run: 30 tests with four cleanup errors from test-owned SQLite connections left open on Windows; assertions passed but the run failed. Fixed explicit connection closing in those tests. Rerun: **30 tests passed in 8.084 seconds**. Separate Python process recovered five typed results and scores 85/70/56 without fixture reseeding. Six views, repeated fixture loading, concurrent identical saves, invalid evidence, immutable writes, source-bound risk inputs, metadata-isolated history and unknown-schema UI handling passed. No live/model/host operations. Next: finish README/handoff, review the patch for persistence edge cases, run any checks needed for resulting changes and release this run's lock. P2 workflow storage and A04 verification persistence remain unfinished.

### Final handoff 18 October 2026, approximately 02:46 Malaysia time (UTC+08:00)

Completed the assessment/risk/history portion of P2 and documented the database location, fixture-seeding behavior, backup limits and session-only workflow in README. Review added explicit protection against SQLite `INSERT OR REPLACE` overwriting an existing snapshot (DELETE triggers alone are insufficient for this case). After that change, ran `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_storage.py -v`: **11 storage tests passed in 0.274 seconds**, including replacement refusal. The earlier full 30-test run passed as recorded above. `git diff --check` passed; only Git line-ending conversion warnings appeared. Tests used temporary databases; the normal demo database will be created on first launch. No dependencies installed, commits made, model calls sent or Windows settings changed.

Acceptance: A01/A02 rechecked for the synthetic stage; A03 core checks still pass. A04 now has real process-restart and compatible-history evidence but remains partial until independent verification records persist. A05-A11 remain unfinished; PREVIEW_COMPLETE is not set. External VM, benchmark and access-method dependencies are unchanged.

Next concrete task: add a workflow repository with immutable proposals bound to assessment/control/target/action/parameters, durable approve/reject decisions and unique execution attempts; verify rejection produces no simulated write and duplicate execution is prevented across restarts. Keep subsequent verification evidence separate from assessment snapshots. Then add persisted investigation events for the bounded Ollama coordinator. Preserve schema-version compatibility and use synthetic data only. This run's work is saved; release its ownership lock before ending.

## Run 18 October 2026, 03:41 Malaysia time (UTC+08:00) - working checkpoint

Acquired the development lock and reread the project handoff. Next bounded step: durable exact-action proposals, administrator decisions, at-most-once simulated execution and independent verification. Preserve existing assessment snapshots through an additive schema migration. No implementation checks yet in this run. Next: add the workflow schema/service and tests for rejection, approval binding, duplicate execution and failed verification; then connect the dashboard if the contracts pass. Real target/benchmark dependencies remain unresolved. Save checkpoints at least every two minutes while working.

### Checkpoint 18 October 2026, 03:43 Malaysia time (UTC+08:00)

Saved schema version 2 additive workflow tables and `hardening/workflow.py`. Proposals allow only the synthetic NLA action and exact boolean parameters. Decisions bind to a digest including the proposal identity; execution claims are committed before the simulator runs; verification reuses the original comparison rule and is stored separately. Saved tests for approval bypass, rejection, concurrent/restarted repeats, failed execution/read-back, interrupted attempts, schema migration and immutable audit records. Not yet tested. Next: run workflow tests, fix any failures, then replace the session-only UI workflow with saved records. Development lock remains held.

### Checkpoint 18 October 2026, 03:44 Malaysia time (UTC+08:00)

Workflow contract suite passed: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_workflow.py -v` from the application directory, **11 tests passed in 0.565 seconds**. Saved dashboard integration: restores the latest proposal in a new session, records real simulation-event timestamps, shows saved parameters/decisions/verification and exposes failure scenarios for rehearsal. New demonstration clears the current view but preserves audit records; history can reopen a saved proposal. UI changes are not yet tested. Next: run the full suite, add new-session/rejected/failed-verification UI coverage, then finish docs and handoff. Lock remains held; live execution and model integration remain absent.

### Checkpoint 18 October 2026, 03:44 Malaysia time (UTC+08:00) - validation complete

Full suite after initial UI integration: **41 tests passed in 2.518 seconds**. Added UI checks for failed verification/rejection across new sessions, opening old proposals, and continuing an approved-but-unstarted attempt exactly once. Saved simulator scenario metadata on execution attempts; corrected unavailable-verification messaging so successful execution is not misreported as failed. Full suite rerun: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v`, **43 tests passed in 3.752 seconds**. Streamlit emitted its expected bare test-context warnings; no app exceptions. README now describes persisted workflow, schema upgrade, unknown outcomes, demonstration choices and backup behavior. Next: final diff review and handoff, then release this run's lock. No model calls, host changes, dependencies or live target access occurred.

### Continued work 18 October 2026, 12:07 Malaysia time (UTC+08:00)

User explicitly requested continuing toward the same preview while the prior handoff was being finalized. `git diff --check` passed for the workflow milestone. The existing run retains its ownership lock and continues into P3: strict investigative tools, bounded local model client/coordinator, durable real investigation events and synthetic-scenario tests. First validate mocked-model boundaries; then attempt small local Ollama investigations with time limits and record actual failures honestly. No live target or remediation is authorized. Next: implement the tool registry and bounded loop; save another checkpoint within two minutes.

### Checkpoint 18 October 2026, 12:09 Malaysia time (UTC+08:00)

Saved `investigation_tools.py`, `ollama_client.py` and `investigation.py`, plus schema version 3 investigation audit tables. Six exact-schema tools operate on the fixed synthetic assessment; approval/execution are excluded. Proposal submission requires prior reference/evidence/context/action lookups and is withheld for legacy-client fixtures. Coordinator has step/call/time/repeat limits and labels model provenance. Local client uses fixed 127.0.0.1:11434/qwen3:8b with no redirects, cloud fallback or model download. Consulted official Ollama tool-calling/chat API documentation. These new changes are not yet tested. Next: mocked-model boundary tests and UI integration, then a bounded real local probe if tests pass. Same development lock remains held.

### Checkpoint 18 October 2026, 12:11 Malaysia time (UTC+08:00)

Mock investigation suite: **8 tests passed in 0.332 seconds**. Added the dashboard's local investigation panel, persisted trace viewer and review link for AI-prepared proposals. Full suite: **51 tests passed in 10.455 seconds**. Started the real local probe with `.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\probe_investigation.py --scenario compatible_clients`; process still running. Saved SQLite events already show actual qwen3 tool selection including related-configuration and supported-remediation lookups; do not yet claim full A05. Probe records are in ignored `data/investigation_probe.sqlite3`. Next: collect the bounded probe result, test the contrasting legacy-client fixture if the first succeeds, add UI outage/client protocol tests and document exact traces/timings. Lock remains held.

### Checkpoint 18 October 2026, 12:12 Malaysia time (UTC+08:00)

Compatible-client real model probe completed in **75.047 seconds**: run `a06be452c0294690b13e5697f6180a48`, five actual calls in order: reference, finding evidence, related configuration, supported remediation, submit proposal. Saved proposal `eaf9d49dd80a494799c6083764be7ff9` remains Awaiting Approval, with no decision/execution. Started the contrasting `legacy_clients` probe; it is still running. Added mocked HTTP protocol/size/error checks and a UI model-outage test. Full suite: **55 tests passed in 11.076 seconds**. README now documents real invocation, saved traces, strict limits and schema 3. Next: inspect second probe outcome and record actual differences; finish validation handoff and release the lock. A05 remains pending the second result; no live server evidence exists.

### Checkpoint 18 October 2026, 12:13 Malaysia time (UTC+08:00)

First legacy-client probe `780e40d043d942feb3d5099818b65349` stopped safely after **80.000 seconds**, status Invalid calls blocked. It chose reference/evidence/context/history/action lookups, then attempted two rejected submissions (wrong schema, then legacy-client guard). No proposal or execution was created. This demonstrates the boundary, not a successful second A05 scenario. Found that supported-action lookup still advertised the action while compatibility forbade its proposal. Changed lookup to return explicit `proposal_allowed=false` and no eligible action for legacy context, added the eligibility field to context and clarified the coordinator's final-summary instruction. Added a regression assertion. Probe exports now use unique run IDs to preserve every attempt. Next: rerun targeted tests, then one legacy probe with these changed semantics; record failures without repeated unchanged retries. Lock remains held.

### Checkpoint 18 October 2026, 12:14 Malaysia time (UTC+08:00)

Targeted investigation tests after eligibility clarification: **8 passed in 0.322 seconds**. Revised legacy run `a3033c5345ca4c4d82856ddecc67fb4f` completed in **40.281 seconds** with reference/evidence/context/history/action lookups, no proposal, and a final operational-review summary. Started one compatible-client run on the same final code/prompt for a controlled two-scenario comparison. The earlier failed legacy trace remains saved. Added TEACHER_PREVIEW.md with truthful architecture/demo steps, failure case, backup guidance and remaining rehearsal limits. Fixed the UI to select the newly completed investigation rather than leaving an older trace selected. Next: collect final compatible result, verify UI change, save acceptance evidence and release the lock. No host changes or model-generated execution occurred.

### Final handoff 18 October 2026, 12:15 Malaysia time (UTC+08:00)

Final compatible run `aefc85ad0aef4c7db64f6c4b6ffb4b8c` completed in **62.625 seconds**, selecting reference/evidence/context/action/proposal tools and saving undecided proposal `002aa9b11756472ab2e6e81d38f199e4`. Together with the final legacy run (40.281 seconds), this satisfies A05's two evidence-dependent real tool paths on the same code. Saved details, exact IDs, earlier failure and limitations in LOCAL_MODEL_VALIDATION.md. Read-only probe DB audit found two assessment snapshots, two undecided proposals, four model runs and **zero decisions/attempts/executions**.

Validation: final UI selection fix checked with `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_app.py -v`: **6 tests passed in 8.623 seconds**. Final investigation change checked with its 8-test suite; full 55-test suite passed before those targeted changes as recorded above. `git diff --check` passed with only line-ending conversion warnings. No extra dependencies/models, cloud calls, live target access, host configuration changes, commits or deployments.

P2/P3/P4 now provide the synthetic preview's persistent workflow and real bounded investigator. A01-A09 are supported for the documented synthetic scope; A10 full timed rehearsal and A11 validated server/benchmark evidence remain incomplete. Status stays IN_PROGRESS, not DEMO_READY/PREVIEW_COMPLETE. Next concrete task is the separate-database end-to-end rehearsal in TEACHER_PREVIEW.md, including fallback demonstration and measured total time. Release this run's ownership lock before ending.

## Run 18 October 2026, 18:38 Malaysia time (UTC+08:00) - working checkpoint

Reviewed instructions, plan, progress, README and teacher walkthrough; acquired the development lock. Next milestone is an automated, timed end-to-end rehearsal through Streamlit AppTest on a new, isolated rehearsal database, including real local model calls and simulated-only execution. This will distinguish software execution time from human presentation time and will not claim browser visual QA or live server validation. No changes tested yet. Next: add a reproducible rehearsal command that saves each step/timing and partial failures, then run it and fix any demonstrated UI issues. Asked the user for VM/benchmark readiness for the later A11 stage; independent rehearsal work continues. Lock remains held.

### Checkpoint 18 October 2026, 18:40 Malaysia time (UTC+08:00)

Saved `scripts/rehearse_preview.py`: opt-in real local model calls through Streamlit AppTest, fresh rehearsal database per invocation, incremental JSON step/timing/failure records, separate-process restart check and explicitly mocked outage fallback. Started `.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\rehearse_preview.py --live-model`. Evidence directory: `data/rehearsals/20261018_183916_19d507f8/`. Opening six-view/risk checks passed in 1.813 seconds; the compatible-client model step is running. Script is being validated by this execution; do not claim completion yet. Next: inspect live-model UI results and remaining workflow steps, then browser layout check if available. Original probe databases remain untouched; lock remains held.

### Checkpoint 18 October 2026, 18:41 Malaysia time (UTC+08:00)

Real compatible-client investigation through the dashboard passed: model run `17ecd9966ceb487fbe7f146292814d09`, 84.094 seconds model time / 84.281 seconds UI step, five expected reference/evidence/context/action/proposal calls. Legacy-client scenario is now running; no retries were performed. Independent documented Streamlit startup check returned local HTTP health `ok` in 3.860 seconds; its temporary loopback-only server process was stopped afterward. Browser-control inventory returned no available browsers/apps, so visual screenshot/layout QA cannot be claimed in this session. Next: finish the second model scenario and persisted workflow/restart/fallback steps, inspect the saved rehearsal report, and document exact tested boundaries. Lock remains held.

### Checkpoint 18 October 2026, 18:42 Malaysia time (UTC+08:00) - rehearsal passed

All eight technical rehearsal steps passed in **137.547 seconds**. Legacy UI model run `8edde04716b94a0d8cdf86eea0b86562` completed in 47.688 seconds model time and requested review without a proposal. The model-prepared compatible proposal was rejected with no attempt; two fresh simulated proposals demonstrated passed and failed verification. A separate Python process reopened all six views and preserved the failed state/comment and original snapshot. Injected model timeout was explicitly labelled Mock outage (rehearsal only); earlier real traces remained accessible. No real model failure occurred in this run.

Final full suite: `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` from the application folder, **55 tests passed in 6.414 seconds**. Saved REHEARSAL_RESULT.md and updated README/TEACHER_PREVIEW.md with exact reproduction/backup commands and untested boundaries. Status is DEMO_READY per the plan's synthetic completion level; PREVIEW_COMPLETE remains unset. Next: final documentation consistency check, release the lock, and wait for confirmed VM/benchmark facts for P5. Browser visual check and spoken practice remain outstanding; no browser surface was exposed. User's VM readiness question has not yet been answered.

Final handoff, approximately 18:43 Malaysia time: documentation consistency check and `git diff --check` passed (Git line-ending warning only). Existing application code was preserved; this run added the reproducible rehearsal script and evidence/documentation. No host security changes, dependencies, model downloads, cloud calls, deployment or commits. The temporary Streamlit health-check process and rehearsal subprocesses have exited. Release this run's ownership lock before ending; next run should follow the current handoff at the top rather than repeat completed rehearsals without a change or new concern.

## Run 18 October 2026, 23:57 Malaysia time (UTC+08:00) - working checkpoint

User reconfirmed the report's CIS Microsoft Windows Server 2022 Benchmark v5.1.0 and requested a progress percentage. Re-read project instructions, plan, progress and README; acquired this run's lock. Checked the report's scope: it targets Server 2022 and explicitly excludes Active Directory/domain-specific policies. CIS's official listing includes Server 2022 v5.1.0 and a separate Server 2022 Stand-alone v2.0.0. The actual VM role and exact source PDF/profile remain unconfirmed; an asynchronous VM-readiness question is pending.

Saved a transparent 10/11 = 90.9% acceptance count and corrected stale A01/A03 wording. This does not represent remaining engineering effort or full-FYP completion. Next: save the conditional baseline decision and five-control live-validation checklist, link them from the plan/walkthrough/README, and check documentation consistency. Documentation edits not yet validated. No application code or host configuration changes; lock remains held.

## Run 18 October 2026, 23:58 Malaysia time (UTC+08:00) - baseline and progress handoff

Completed a documentation milestone: added LIVE_VALIDATION_PLAN.md with the conditional baseline choice, device eligibility design, five candidate-control review checklist and read-only imported evidence path for A11. User clarified that the VM is not set up yet and wants eventual support for different physical/virtual Windows devices. Recorded standalone Server 2022 as the proposed first lab, while keeping actual target identity/build/role, source PDF/profile and transfer method unverified. Updated AGENTS.md, DEVELOPMENT_PLAN.md, README.md, TEACHER_PREVIEW.md and this handoff so subsequent runs retain that distinction. No application code, database or host security settings changed.

Progress is **10 of 11 initial-preview acceptance criteria supported: 90.9%, rounded to 91%**. This is an equally weighted criterion count, not remaining effort or whole-FYP completion. No additional acceptance criterion completed in this run. A11, browser visual QA and spoken practice remain pending; DEMO_READY remains the state and PREVIEW_COMPLETE is unset.

Checks actually completed: report scope paragraphs reviewed (Server 2022 v5.1.0 named; AD/domain-specific policies excluded); official CIS listing checked for Server 2022 v5.1.0 and Stand-alone v2.0.0; inline existing-venv Python check passed for six edited documents' UTF-8 decoding, balanced fenced blocks, local Markdown links, and the eleven acceptance IDs/percentage arithmetic. git diff --check passed with only the existing README line-ending warning. Application tests were not rerun for these documentation-only changes; the latest application result remains 55 tests passed in 6.414 seconds and the prior technical rehearsal passed in 137.547 seconds.

Next concrete task: obtain the actual Stand-alone benchmark PDF and review five mappings; once the user sets up the proposed lab, confirm OS/build/role and implement/test its read-only collector/import path. Do not label candidate DEMO mappings as validated, broaden to arbitrary Windows platforms, or retry unchanged model probes while waiting. Release this run's ownership lock before ending.

## Run 19 October 2026, 00:54 Malaysia time (UTC+08:00) - working checkpoint

User supplied a screenshot confirming Server 2022 Standard Evaluation, 64-bit, version 10.0.20348/build 20348, PartOfDomain=False and DomainRole=2. User now confirms the clean snapshot is created. Located the supplied v5.1.0 PDF (6,059,578 bytes) after resolving the omitted .pdf extension. Edition applicability review is in progress, not completed. Existing venv has no PDF extraction packages/Poppler. Initial local pypdf installation attempt found no available versions; no package installed. Next: obtain a working read-only extractor, check the document scope, then update current target/dependency handoffs. No app or host-security changes; lock held.

## Run 19 October 2026, 00:56 Malaysia time (UTC+08:00) - scope review complete

Updated AGENTS, development plan, live-validation plan, README, teacher walkthrough and current progress to retain user-supplied VM OS/role facts and snapshot completion. Reviewed the supplied v5.1.0 PDF cover and scope/profile text: printed page 26 explicitly excludes standalone/workgroup targets, and printed page 31 defines L1 Domain Controller/Member Server. Recorded file size and SHA-256 in LIVE_VALIDATION_PLAN.md. This is a targeted text review, not a full or visual PDF review; no candidate control was activated or validated.

PDF extraction packages and Poppler were unavailable. Three bounded venv-only pypdf installation attempts (default configuration, explicit index/isolated configuration, and disabled pip configuration) all returned no matching distribution; no package was installed. Used standard-library zlib/literal text decoding as a read-only fallback; an initial output encoding failure was corrected with UTF-8. Source PDF unchanged. No application code, databases, Windows settings or domain membership changed.

Checks: inline venv Python verified UTF-8 decoding, balanced fenced blocks and resolving local Markdown links for six edited documents; passed. git diff --check passed with only README line-ending warning. Application tests not rerun for documentation-only changes; prior 55-test pass remains latest application evidence. Acceptance remains 10/11 (90.9%, rounded 91%), DEMO_READY; A11 and visual/spoken preparation remain pending.

Next concrete task: obtain CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0 PDF, review approximately five control mappings and then implement the read-only export/import path for this VM. Exact target identity and transfer method still need machine-readable evidence. Release this run's ownership lock before ending.

## Run 19 October 2026, 09:05 Malaysia time (UTC+08:00) - working checkpoint

Acquired guard; located Stand-alone v2.0.0 PDF (5,098,178 bytes, SHA256 474f467dd90b5cd50598589e427c2360502b8d25e633f729efd89f44662c5d1d, 918 pages). Installed pypdf 6.21.1 and pymupdf 1.28.2 into the existing project venv through approved network access; no global install. Read relevant scope/profile and five control sections, rendered 11 relevant pages into ignored data/benchmark_review, visually inspected scope/profile, lockout, firewall and NLA pages. Printed p23 confirms standalone scope; exact profile is Level 1 - Member Server. Lockout is 1-5 (not demo 1-10), password at least 14, Guest disabled, selected Public firewall policy DWORD=1, NLA policy DWORD=1. No full-document review or real VM checks claimed.

Next: finish visual review of remaining audit pages, save reviewed catalogue/mapping notes, implement guarded read-only VM collector and strict offline import/evaluation CLI with fixture tests. Existing demo remains unchanged. Changes not yet implemented/tested; lock held.

### Checkpoint 19 October 2026, 09:07 Malaysia time (UTC+08:00)

Completed text/visual inspection of all 11 rendered scope/profile/control/audit pages. Saved separate reviewed server2022_catalogue.py, strict evidence_import.py and offline inspect_server_evidence.py CLI. Import requires explicit expected hostname/UUID, fixed catalogue/hash/profile, standalone Server 2022 identity, all five records, registered sources, exact scalar types and timestamp intervals; no risk scoring or DB integration. Missing policy values remain Unknown and errors distinct. These additions are untested. Next: finish single-file read-only PowerShell collector, add boundary/malformed evidence tests and pure collector tests; run checks before handing off. No VM collection or host setting changes; lock held.

### Checkpoint 19 October 2026, 09:08 Malaysia time (UTC+08:00)

Saved single-file Collect-Server2022Evidence.ps1 with hostname/OS/role guard before configuration collection, local admin requirement, 30-second secedit export timeout, SID-based Guest lookup, read-only 64-bit registry reads, bounded-error records and no-overwrite JSON output. Temporary export/log files only; no configuration-changing commands. Added 15 importer tests and pure PowerShell helper tests. First importer run: 14 pass, 1 malformed error-array case raised TypeError; corrected to reject non-string errors before membership check. First PowerShell test launch was blocked by default script execution policy; next run will use a process-only policy override for fixture tests, without changing saved Windows policy. Changes awaiting rerun; collector has not been executed against any real machine. Next: validate helper behavior and full suite, then write VM handoff/manual comparison instructions. Lock held.

### Checkpoint 19 October 2026, 09:11 Malaysia time (UTC+08:00) - verification passed

Full suite: .\.venv\Scripts\python.exe -B -m unittest discover -s tests -v from application folder: 70 tests passed in 5.291 seconds (expected Streamlit test-context warnings only). Targeted importer rerun: 15 passed in 0.295 seconds. PowerShell fixture helper/syntax tests passed using process-only execution policy override; no actual CIM/registry/secedit collection ran. Fixed malformed error-array validation before the final suite. Saved BENCHMARK_MAPPING.md and VM_EVIDENCE.md; prepared data/vm_exchange collector copy (SHA256 9925cb7e0371296b0e5c63fcbc9877327b9bb7f68736ac114a519bcbb7ad97a9). User says file transfer is not yet available; setup guidance now prepared. Updated planning/current handoffs to reflect reviewed source and pending real execution. Next: documentation/file consistency checks and final shared-folder handoff; lock remains held.

### Final handoff 19 October 2026, 09:11 Malaysia time (UTC+08:00)

Completed one P5 preparation milestone: source-reviewed standalone subset, guarded VM collector, strict offline importer/evaluator and transfer/manual-check guide. No additional full acceptance ID completed: A11 still requires actual VM collection and independent comparisons; importer-to-dashboard persistence/display integration is not implemented. DEMO_READY remains; PREVIEW_COMPLETE unset. Eight updated/new documents passed UTF-8/fence/local-link checks, four new Python sources parsed, transfer copy bytes matched source, and git diff --check passed (README line-ending warning only). Existing user edits and synthetic application/history preserved; no commit/deploy or live model rerun. The new PDF packages are venv-only authoring dependencies.

Exact next action: user installs Guest Additions inside the lab VM and adds the prepared data/vm_exchange directory as writable VirtualBox share FYP-Exchange, per VM_EVIDENCE.md. Then run Collect-Server2022Evidence.ps1 inside that VM and return server-evidence.json plus displayed hostname/UUID. Next coding run validates it with inspect_server_evidence.py, checks manual observations, and plans separate imported snapshot/UI integration without synthetic risk assumptions. Never use the laptop as collector/hardening target. Release this run's ownership lock before ending.
