# Integration progress — plan: docs/inputs/2026-11-05-unified-vm-hardening-system-plan.md

Actual location: Desktop/FYP_App-main/window_cis_compliance_dashboard_prototype.
Branch: integrate/unified-vm-hardening. Pre-change reference: af43fbccaea5a5818396a376468afb44bd439c40.

## 2026-11-05 checkpoint
- Task 0 in progress: verified 86-file source archive outside runtime; baseline manifest; protected/import-origin tests pass.
- Original Python suite: 178 passed; with 2 integration preservation tests: 180 passed in 18.775s.
- Four original PowerShell fixture suites: PASS. No live VM tests or changes.
- Python 3.13.0; new .venv-integration; pip check passes; full freeze recorded.
- Desktop/GitHub comparison: all 86 source files match after CRLF/LF normalization; no copy overwritten.
- Benchmark SHA256 verified: 37b8d91eadb5621656ff38d24c39ac34b9589087a3f3a9fbba2c8a2dd665b6da; 1064 pages extracted outside runtime.
- Visual baseline pending; original AppTest covers goal, approval/rejection, confirmation, page switching and resume.
- Task 1 next: contracts, explicit isolated paths and shared UI injection.
- Tasks 2–17 pending. No milestone declared complete.

## Rulings / preflight
- Work in place on requested branch; user explicitly prefers existing entry point and optional worktree.
- Existing fixture patch point LiveScanner and behavior expectations must remain compatible during adapter injection.
- Early mutation capability remains disabled until coordination gate; runner/recovery remains required for Ubuntu.
- Local Python sandbox temp paths are unwritable: process TEMP/TMP set to project .integration-tmp.
- Streamlit AppTest stalls inside sandbox; identical fixture suite passes outside sandbox with a 75s stack-dump deadline.
- PDF Poppler fails with DLL relocation: pypdf used for textual reference extraction; no PDF alteration.
- The attached plan is authorized for local development. Site policy/risk reviews remain unapproved.

## Verification commands
From application directory with TEMP/TMP pointing at project .integration-tmp:
`..\.venv-integration\Scripts\python.exe -B -m unittest discover -s tests -v`
From project root: four `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/.../test_*.ps1` named in README.
Logs: .integration-tmp/baseline-tests-unrestricted.log (passed); sandbox attempts separately retained, not counted as passes.

## 2026-11-06 implementation checkpoint (supersedes the task status above)

No milestone is declared complete. Tasks 0–4 are partially implemented; tasks 5–17 remain incomplete.

| Task | Implementation and evidence | Remaining gate |
| --- | --- | --- |
| 0 | Recovery archive, 86-file manifest, import-origin check, isolated environment, original 178 Python tests and four PowerShell suites passed | Complete visual/behavior evidence and final authorized edit report |
| 1 | `system/contracts.py`, explicit isolated paths, common snapshot panels in the existing app | Finish replacing Windows presentation reads with shared snapshots |
| 2 | Existing six-field form, Advanced transport/key/trust, bounded credential-free endpoint discovery | Form-change invalidation and remaining adversarial UI tests |
| 3 | SSH trust before authentication; fixed Ubuntu identity reads; original WinRM identity plus Server 2022 check; target/epoch ledger | Authenticated live Ubuntu inspection; no credentials supplied to this chat |
| 4 | Original Windows services through adapter; deterministic assessment; durable workflow resumption; same-page Windows/Ubuntu/Windows fixture | Full snapshot UI coverage and connection/operation edge cases |
| 5 | PDF hash verified; full recommendation extraction; groups 1–2 reviewed | Review remaining recommendations, pin actual content and mappings, record policy/source reviews |
| 6–17 | Not complete. Ubuntu capability boundary refuses assessment and writes; no fabricated results | Real 30-control assessment, persistence/risk/agents, all 30 action families, recovery, live evaluation and handover |

Latest broad verification: 201 Python tests passed in 18.100 seconds (`.integration-tmp/integration-ui-regression.log`). A subsequently added same-page transport-switch/resume acceptance test passed after restoring the durable workflow binding on resume. A broad run after that change is still pending. Protected Windows engine/script hashes remain unchanged; authorized edits currently include `app.py`, `connection_view.py`, and `agentic_view.py`.

Additional modules include `system/{connection,discovery,identity,session,ledger,bootstrap,config}.py`, `backends/base.py`, `backends/windows/adapter.py`, `backends/ubuntu/{adapter,ssh_channel}.py`, and integration tests. Ubuntu adapter is an explicitly incomplete capability boundary, not a completed collector or remediation implementation. Live Windows dispatch remains disabled pending coordination acceptance; live Ubuntu dispatch remains disabled pending runner/recovery acceptance.

Read-only observations: the supplied SSH endpoint returned the matching host-key fingerprint during a handshake, with **no authentication** (`.integration-tmp/ssh-handshake.json`). Local Ollama `qwen3:8b` returned `READY` to a bounded inference in 10.84 seconds (`.integration-tmp/ollama-inference.json`). Neither proves Ubuntu collection or execution. Original Overview visual styling was observed in the browser; full visual regression evidence remains incomplete.

## Supplied target facts and remaining live prerequisites
User supplied Ubuntu host `192.168.56.10:22`, hostname `FYP-Ubuntu2204`, username `vboxuser`, machine ID `f1d16ae7e6bc4d2488f9410fcd858e36`, and fingerprint `SHA256:0qRovBYoeBMmpWGuLeFoEH3ZVngOgajNPorDT7CUUms`. The fingerprint was supplied again after console verification instructions. Credentials belong only in the application. No authenticated OS/privilege/helper inspection has occurred. No snapshot or recovery-console availability is assumed.

Live changes require an exact target-bound preview and separate approval. Source/site-policy/risk reviews are not human-approved by this implementation. Continue local development while these live gates remain closed.

## 2026-11-06 subsequent checkpoint — source and predicate foundation

- Overview/History now use a target-scoped facade for managed connections. Ubuntu pages do not open the Windows store. Windows history references are filtered by the active registration epoch; typed comparisons reject unrelated epochs and reversed chronology.
- Matching initial assessment retries return the existing workflow/round without scanning again. Operation-ID conflicts are checked before dispatch-key matches. Two independent processes with different operation IDs dispatch the same claimed set at most once; an exited owner does not authorize takeover. Full cancellation/reconciliation/backup gates remain incomplete.
- Connection exceptions cannot echo library ValueError text, selected-key paths or sudo secrets. Present changed public form fields invalidate the backend and workflow authority. Disconnect clears platform-specific history selectors as well as approval/confirmation state.
- `catalogues/source-lock.json` pins real ComplianceAsCode v0.1.80, exact source commit, verified official release SHA512, local Ubuntu datastream SHA256, actual rule IDs and variable selectors. `tools/check_sources.py` verifies the offline inventory. All 30 source recommendations have been read; source/policy human review and OpenSCAP engine validation remain pending. Activation remains false.
- `backends/ubuntu/predicates.py` now contains all 30 deterministic compound predicate definitions. Synthetic cases exercise 29 compliant outcomes plus the Manual control's unresolved human review, all 30 failing states, all 30 missing states and all 30 error states. These are subcases within four test methods, not 120 separate unittest methods. Extra tests cover existing accounts, disabled IPv6 evidence, SSH contexts, conflicts, malformed values and secret/forged-status fields.
- `evidence.py`, `envelope.py`, and `scap.py` validate allowlisted facts, exact target/epoch/request/source ownership, timestamps, sizes, JSON duplicates, XML entities and sanitized result extraction. Raw shadow hashes and arbitrary SCAP messages are not exported by tested parsers.
- `vm/ubuntu/probes.py` contains pure normalization for sysctl precedence, local account aging, password quality, SSH output and semantic audit rules. `collector.py` contains bounded fixed read-only I/O with Linux/Ubuntu/identity preflight. **Complete collection orchestration, privileged installation, engine invocation, capabilities and live end-to-end assessment are not yet implemented.** No helper was installed or run on the VM.
- Added baseline/source/setup/report-change documentation. The unchanged preexisting theme was saved in a verified supplemental archive because the original archive excluded `.streamlit`. Original archive bytes were preserved.

Verification: full original + integration suite **227 tests passed in 51.467s**, log `.integration-tmp/integration-ubuntu-foundation-regression.log`. Earlier checkpoint: 205 passed in 18.138s. `python -B -m tools.baseline` reports no protected/missing files, and five authorized UI edits (`app.py`, connection, agentic, overview, history). `pip check` passes. `python -B -m tools.check_sources` reports 30 controls, verified pins and activation false. Browser visual recheck could not resume because browser control returned an unavailable-session error; the visual gate is still open.

Task status: 0–4 partial; 5 source pin/inventory implemented but activation review incomplete; 6 predicates/evidence/parser/I/O foundation implemented and fixture-tested but collector and live/UI assessment incomplete; 7–17 incomplete. All 30 remediation implementations and live transitions remain outstanding. Source manifests reserve action IDs but must not be counted as executable action coverage. Predicate fixtures are not live evidence or a completed assessment pipeline.

Ruling: continue pure predicate/evidence/parser development with activation disabled while source human review and target engine facts are pending. This permits local fixture development without representing draft policy or helper code as accepted live capability. If source review changes a predicate, revise its manifest/version and rerun affected tests before activation.

Next: finish bounded target collection orchestration and provenance, real selected-rule evaluation, then persist/serve validated Ubuntu assessments through the existing backend/UI. Preserve remaining gates in the task table; do not mark milestones complete based on this checkpoint.

## 2026-11-06 transfer checkpoint — supersedes earlier current-status summaries

The user requested a development handover to a new conversation/agent. Deliverables are `docs/handover/PROJECT_HANDOVER.md` and `docs/handover/NEW_AGENT_PROMPT.md`. This is an interim transfer, not completion of task 17. Implementation work was left intact rather than continued during handover preparation.

Latest implementation commit is `74065a8`; significant subsequent code remains uncommitted. It adds collection orchestration and pre-export schema sanitization, bounded privileged-file inventory, selected SCAP scan planning, stricter source-rule association checks, and audit/PAM false-pass fixes. Portable evidence validation now lives in `vm/ubuntu/evidence_schema.py`. Complete provenance assembly, deployed helper/SCAP execution and backend/UI assessment remain unfinished.

The exact restart task is `tests/integration/test_ubuntu_storage.py`: three tests have been written, but `backends/ubuntu/storage.py` does not exist. Implement the planned isolated Ubuntu storage with idempotence, append-only evidence, ownership and integrity checks; do not remove the red tests.

Fresh full Python regression for this handover: **242 tests in 23.599 seconds; 239 passed, three errors**, all `ModuleNotFoundError` for the missing Ubuntu storage module. Log: project `.integration-tmp/handover-current-regression.log`. The current tree is not green. The earlier 227-pass result describes an earlier checkpoint. Baseline check rerun: no protected changes/missing files, five authorized UI edits. Source check rerun: 30 controls with verified pins/mappings, activation false. `pip check` rerun: no broken requirements. Original PowerShell suites and visual checks were not rerun for this documentation transfer.

No VM was authenticated or changed during handover preparation. Source/policy/risk reviews and live execution gates remain pending. See the handover for the uncommitted file inventory, known collector limitations and acceptance criteria for continuation.

## 2026-11-06 Ubuntu storage checkpoint — task 7 partial (supersedes the transfer checkpoint's test status)

Added `backends/ubuntu/storage.py` (`UbuntuStore`) against the three existing red tests, which were not changed. Design:

- Three files per Ubuntu base path: the given evidence file plus `<stem>_framework.sqlite3` and `<stem>_agentic.sqlite3`, holding the plan's 11 table purposes (`imported_assessments`; `framework_runs`, legacy `framework_tasks`; `agentic_rounds`, `investigation_runs`, `investigation_events`, `rem_proposals`, `rem_decisions`, `rem_comments`, `rem_receipts`, `drift_records`). Each file has its own `PRAGMA application_id` and `user_version=1`.
- All three files are inspected **read-only** before any write. A database with other tables, another application ID/version, or an altered table/trigger set (for example a dropped append-only guard) is refused; it is never adopted, migrated or repaired. A foreign derived file blocks creation of the other two.
- Every table has UPDATE/DELETE triggers and a pre-insert trigger covering every unique key, so `INSERT OR REPLACE` cannot delete rows silently.
- Evidence stores exact sanitized bytes, SHA-256 digest, the `ExpectedEvidence` ownership, receipt time and a snapshot of the 30 evaluated assessments. One request ID per target/epoch; different bytes for the same request are rejected.
- Reads check the digest, ownership columns and payload version, re-run `parse_bundle` against the **recorded receipt time**, and compare the re-evaluated assessments with the stored snapshot. A predicate change that alters an outcome makes the record unreadable until reassessment, as in the Windows store. `StoredEvidence` is historical; it does not count as fresh evidence and authorizes no new work.
- Cross-file order: evidence first, then one idempotent run per evidence digest (bound to one workflow), then an explicit idempotent round only for an existing linked run. If a write fails partway, the result is reported orphan evidence; no run or round is invented. Retrying `start_run` reuses the stored bytes without declaring them fresh. `consistency_errors()` reports SQLite integrity failures, schema/guard changes, unreadable evidence, orphan evidence and broken run/round links. It never repairs anything.

Four regression tests were added afterwards for partial-write recovery, round/workflow link refusal, snapshot/guard tampering and foreign derived files. They were written after the implementation, not test-first. As a check, removing the recovery shortcut made the recovery test fail, and restoring it made the test pass again.

Verification (synthetic fixture evidence only, labelled `Synthetic fixture`; no live data):
- Focused storage tests: 7 passed. Storage + evidence + contracts: 19 passed.
- Full suite: **246 tests in 23.741s, all passed**. Log: project `.integration-tmp/storage-checkpoint-full-regression.log`.
- `tools.baseline`: no protected/missing files, five authorized UI edits; log `storage-checkpoint-baseline.log`. `tools.check_sources`: 30 controls, pins verified, activation false; log `storage-checkpoint-sources.log`. `pip check`: no broken requirements (exit 0 under PowerShell; under Git Bash the same command printed the success line and then exited 139, a segfault, which is recorded here as an environment anomaly).

Still open in task 7: Ubuntu history/drift read models through `system/history.py`, manual patch-review events, proposal/decision/receipt APIs, cancellation/reconciliation records, quiesced backup/restore, and wiring `UbuntuStore` into `IntegrationPaths`/`UbuntuBackend`. M2 is **not** complete. No VM was contacted or changed.

Next: collector provenance-envelope assembly and the real selected-rule SCAP path, then serve validated assessments and history from `UbuntuStore` through `UbuntuBackend` and the existing pages.

## 2026-11-06 provenance and read-only Ubuntu history checkpoint — tasks 6/7 partial

Test-first. The new tests failed (missing module, or stub behaviour) before the implementation.

- **`vm/ubuntu/provenance.py`** (target side, standard library, written for Python 3.10):
  - `collector_digest()` hashes the exact eight-file helper bundle. The host computes the expected `collector_sha256` from its copy, so a deployed helper must be byte-identical.
  - `.gitattributes` now marks `vm/ubuntu/*.py` `-text` so checkouts cannot convert line endings and change the digest.
  - `validate_request()` accepts only the eight fixed request fields with strict formats: 32-hex request ID; mode `Live (SSH)` or `Synthetic fixture`.
  - `build_envelope()` refuses a missing or empty control, schema-invalid or forged fields, naive or impossible times, and invalid artifact metadata. It derives each probe's `exit_state` (`ok`/`missing`/`error`/`partial`) from the observation states and emits canonical ASCII JSON.
  - `run_collection()` requires a preflighted IO whose recorded identity matches the request.
- **`vm/ubuntu/collector.py`:** `preflight()` now records the verified machine ID and hostname on the IO object.
- **`vm/ubuntu/collection.py`:** the Manual updates control 1.2.2.1 now emits explicit `missing` facts instead of an empty set. An empty set would have made the envelope invalid and hidden the gap. It evaluates as Unknown, never Compliant.
- **`backends/ubuntu/adapter.py`:** stored assessments are now served read-only from `UbuntuStore`.
  - `history()` lists runs for the verified target and epoch whose workflow is registered in the ledger. Each run's evidence is re-validated, and its machine ID and hostname must match the verified session.
  - `compare()` lists per-control status changes for two runs in chronological order within that scope.
  - `snapshot()` fills the summary and 30 control rows with subchecks for a stored round. Findings stay empty because risk (task 8) is not implemented. Step states show only Scan done.
  - The store file is never created by a read. `can_assess`/`can_remediate` remain false and `start_round` still refuses; there is no live Ubuntu assessment path.
- **`system/ui/components.py`:** the shared Controls caption now ends with `Evidence: <mode>`, so synthetic Ubuntu data is visibly labelled. This also adds `Evidence: Live (WinRM)` (or the stored Windows mode) to the Windows Controls caption. It is a presentation-only change in the shared helper, recorded here for UI review and report alignment.

Verification (synthetic fixture evidence only): provenance tests 5 passed; backend/UI tests 6 passed; collection, probe I/O, shared UI and Windows adapter tests pass. Full suite **257 tests in 26.523s, all passed**, log `.integration-tmp/provenance-history-full-regression.log`. Baseline: no protected changes. Sources: 30 controls, activation false. `pip check` (PowerShell): no broken requirements.

**Selected-rule SCAP execution was not implemented this step.** Four items block it:
1. How SCAP rule results enter the 30 compound predicates as subchecks next to the direct probes. This changes predicates and the evidence schema, and needs a reviewed reconciliation rule.
2. How sanitized SCAP summaries travel and are stored. Today the envelope carries only artifact metadata (kind, sha256, bytes).
3. Whether a hardened XML parser is available in the target helper without installing packages during a scan.
4. The target's OpenSCAP version, which is still unverified (`openscap_version` is null).

Also still open: deployment and installation of the helper (needs approval), the live invocation over SSH, opening `start_round`, Ubuntu risk derivation (task 8), and the remaining task 7 items listed in the storage checkpoint above. M2 is not complete. No VM was contacted or changed.

## 2026-11-06 selected-rule SCAP path checkpoint — task 6 partial

Test-first: 16 new tests in `tests/integration/test_scap_reconciliation.py` failed before the implementation (missing names and modules, and schema refusal).

- **`vm/ubuntu/spec.py`:** pinned profile, datastream SHA-256 and the per-control rule map (29 mapped controls; 1.2.2.1 has none). These ship inside the digest-pinned helper, and a test keeps them equal to the catalogue and source lock.
- **`vm/ubuntu/scap_results.py`** (target side, standard library):
  - `scan_argv()` builds `oscap xccdf eval --profile … --results <request dir> --rule … <datastream>` from pinned constants and a 32-hex request ID only. No remediation, remote fetch or report flags. It is identical to the host `prepare_scan` argv (tested).
  - `sanitize_results()` refuses non-UTF-8 input, DTD/entity declarations, multiple results, target/profile mismatch, duplicate rows, unknown result tokens and evaluated out-of-scope rules. It keeps only one result token per selected rule; a missing result becomes `notchecked`.
- **`vm/ubuntu/collector.py`:** the bounded process runner is now `_run(argv, seconds)`. File reads take an explicit size limit. New `FixedProbeIO.scap_results()`:
  - checks the `oscap --version` output against the accepted version, and the installed datastream hash against the pin;
  - requires a root-owned 0700-or-stricter result root, and creates a fresh per-request directory, so a request directory is never reused;
  - accepts exit codes 0 or 2 only, sanitizes the result file, then removes its own result directory.
  - **This method has not run on the VM.** The `oscap` version-output format, timing, exit-code behaviour and result-directory provisioning on the target are unvalidated.
- **`vm/ubuntu/collection.py`:** `scap_request=(request_id, engine_version)` runs one scan for all mapped controls. Any engine failure becomes an explicit `error` observation for each mapped control.
- **`vm/ubuntu/provenance.py`:** the helper bundle now includes `scap_results.py`. Live collection refuses to run without an accepted engine version.
- **`vm/ubuntu/evidence_schema.py`:** new `scap_rules` field, exactly the control's pinned rules with raw result tokens only.
- **`backends/ubuntu/predicates.py`:** SCAP subchecks are reconciled with the direct checks using the conflict rule recorded in `docs/SOURCES.md`. A SCAP pass never cancels a direct failure; a SCAP-only failure is a conflict (Unknown); unresolved results never pass. A mutation check (making a SCAP-only failure a confirmed failure) failed two tests and was reverted.
- **`backends/ubuntu/envelope.py`:** Live (SSH) envelopes must include `scap_rules` for every mapped control.

Verification (synthetic fixtures only): full suite **273 tests in 28.815s, all passed**, log `.integration-tmp/scap-reconciliation-full-regression.log`. Baseline: no protected changes. Sources: 30 controls, activation false. `pip check` passes. Stored fixture evidence without `scap_rules` evaluates exactly as before, so existing stored snapshots stay valid.

**Still pending before any live scan:**
- Human review of the reconciliation rule and of the upstream variable differences.
- Provisioning the helper, datastream and result directory on the VM (needs approval).
- Recording the target's `oscap` version in the source lock.
- Running live end to end and validating it.
- Opening `UbuntuBackend.start_round` through a host-side SSH invocation of the helper; this host→helper invocation is not yet implemented.

Also still pending: risk derivation (task 8). M2 is not complete. No VM was contacted or changed.

## 2026-11-06 Ubuntu risk derivation checkpoint — task 8 partial (implemented, review pending)

Test-first. `tests/integration/test_ubuntu_risk.py` failed before `backends/ubuntu/risk.py` existed: 9 errors from the missing module, plus the failing adapter test. Two bugs in my own new tests were fixed before the first green run: an invalid unresolved-observation fixture, and a consequence lookup that ignored extensions.

- **`backends/ubuntu/risk.py`:**
  - **Reuse, unchanged:** imports the Windows `CONSEQUENCE`, `PRIVILEGE_SCOPE`, `LIKELIHOOD`, `SURFACE_EXPOSURE`, `RiskFactors` and `risk_level`. Shared categories give identical factors; the formula and bands are the Windows code itself.
  - **Draft gate:** `rank(current, previous, policy)` refuses an unreviewed policy unless `allow_draft=True`, which tests and the reviewer report use.
  - **Scoring:** only Non-Compliant findings are scored, ordered by score descending with control ID as the tie-break.
  - **Exposure (E):** base surface only. No Linux effective-context adjustment has been reviewed, and no Windows firewall or RDP context is used.
  - **Drift (D):** compares the newest compatible earlier determinate result: same target/epoch/reference target, different record and round (superseded same-round scans are excluded), same evidence mode (synthetic and live never compare), same benchmark and source-lock hashes, strictly earlier completion. D=1 with no such prior, 3 for a persistent failure even if the value changed, 5 for a regression.
  - **Explanations:** each finding carries I/P/E/L/D reasons, the L heuristic caveat, the paraphrased rationale and the policy label (`DRAFT, pending human review` until approved).
- **`catalogues/ubuntu2204-risk.json`** (`ubuntu-risk-2026-11-06-draft1`, `pending_human_review`, no reviewer):
  - Categorical consequence, privilege and surface for all 30 controls, plus paraphrased rationales. Level and Automated/Manual must match the catalogue.
  - Named Linux extensions requiring review: consequence `session_hygiene`=2 (5.1.7 only); surfaces `remote_shell`=4, `local_exploit_mitigation`=2, `system_software`=3; privileges `privilege_escalation_path`=4, `host_network_path`=2.
  - Validation refuses unknown categories, mismatched classification, missing or extra controls, extensions that collide with Windows names, out-of-scale scores, empty rationales, and approval without a named reviewer and UTC time.
- **`backends/ubuntu/adapter.py`:** while the policy is pending, snapshot findings are empty and capabilities list "Ubuntu risk ranking is withheld: the risk-attribute manifest is pending human review." Under an approved policy, findings are ranked using earlier stored rounds of the same target/epoch, and the Analyse step shows done. That approved path was tested with an **in-memory fixture approval only**; the manifest file is still pending.
- **`tools/ubuntu_risk_report.py`** writes `docs/UBUNTU_RISK_DERIVATION.md`: a generated draft table of every category, factor and D=1/3/5 score, plus the extensions, for the human reviewer.

Verification (synthetic fixtures only): risk tests 13 passed, covering:
- all four likelihood mappings and the 23×L4 / 7×L3 split;
- Windows factor parity;
- band edges (37 Low, 40 Moderate, 62 High, 80 Critical) and the `risk_level` 39/40/59/60/79/80 edges;
- D=1/3/5, including a persistent failure with a changed value giving 3;
- Unknown priors skipped; incompatible mode/lock/round/time/record/target history giving D=1;
- Unknown/Error never scored.

A drift mutation (always D=5) failed two tests and was reverted. Full suite **286 tests in 28.362s, all passed**, log `.integration-tmp/ubuntu-risk-full-regression.log`. Baseline: no protected changes (Windows `risk.py`/`domain.py` are only imported). Sources: activation false. `pip check` passes.

Open:
- Human review and approval of every category assignment and Linux extension. The project team must record the reviewer and time in the manifest; do not mark it approved to make the tab work.
- A reviewed Linux effective-context rule for E, if one is wanted.
- The Risk ranking tab with real Ubuntu scores is reachable only after review and a real assessment.

The task 8 gate ("shows deterministic, explainable Ubuntu scores") therefore stays open until review. Windows fixtures and tests are unchanged. No VM was contacted.

## 2026-11-06 host-side helper invocation checkpoint — tasks 6/16 partial (gated, not live)

Test-first: `tests/integration/test_ubuntu_live_path.py` failed before the implementation (16 errors: missing CLI module, launcher, `invoke_helper`, `HELPER_COMMAND` and gate). One adjustment to that new test before green: the open-gate fixture also injects an accepted engine version, because the source lock's `openscap_version` is still null.

- **`vm/ubuntu/cli.py` + `vm/ubuntu/collect`** (launcher `#!/usr/bin/python3 -IB`, fixed path): read one ≤64 KiB strict JSON request (`request`, `scap_engine_version`, `registered_firewall_manager`), preflight, collect, and write only the envelope to stdout. Any failure writes one fixed stderr line and exits 2, with no echo of values or paths. Both files are in the digest-pinned helper bundle, and `.gitattributes` pins the launcher's line endings.
- **`SshChannel.invoke_helper()`:** the only privileged command is `sudo -n /usr/local/libexec/fyp-hardening/collect`. The request goes on stdin; stdout is bounded to the envelope limit and stderr is counted and discarded; a nonzero exit gives a generic error.
  - **No sudo password over stdin.** If sudo has cached credentials it does not read the password, which would then reach the helper. A narrow passwordless rule for that one exact command is part of the provisioning preview in `docs/VM_SETUP.md`.
  - The `helper` stat probe now points at the launcher.
- **`UbuntuBackend`:**
  - **Gate:** `assessment_gate()` is open only when catalogue activation is true (reviewed sources, recorded OpenSCAP version, accepted coverage), and is **closed today**. `capabilities.can_assess` follows the gate, and blocked reasons explain each closed gate.
  - **`start_round`:** refuses while the gate is closed and refuses agentic mode. It then:
    1. reserves the workflow binding and claims the operation in the ledger (a replay with the same operation ID returns the recorded round without scanning again);
    2. builds the request only from verified session facts plus source-lock and helper digests;
    3. invokes the helper once, validates the envelope, stores evidence and the run, and records a deterministic round.
  - **Failure:** marks the claim `refused` (read-only, nothing changed on the VM) so a new attempt is not blocked; partial evidence would be reported as orphan evidence.
  - **Firewall registration:** UFW ownership is a constructor registration that defaults to none, so 4.1.4/4.1.7 stay Unknown until a reviewed registration exists.
- **`hardening/agentic_view.py`** (authorized scoped edit): the Ubuntu **Assess without AI** button now calls `start_round` through the existing `_run_round`, and stays disabled while the gate is closed. `docs/authorized-ui-changes.patch` has been regenerated against baseline `af43fbc`.
- **`docs/VM_SETUP.md`:** concrete provisioning preview (files, owners, modes, sudo rule, datastream, scratch directory, impact, recovery). **Not executed.**

Verification (fakes only; no VM, network or sudo):
- **Target CLI:** valid and malformed requests.
- **Channel invocation:** exact command, stdin, bounds, generic failure.
- **Backend:** gate closed today with no channel call and no store created; with a test-only gate, one collection, stored, replayed without a second scan; agentic refused; identity mismatch refused and a retry allowed.
- **Page:** the existing page connects without scanning, then the button runs exactly one assessment.

A mutation that removed the button handler failed the page test and was reverted. Full suite **296 tests in 25.248s, all passed**, log `.integration-tmp/helper-invocation-full-regression.log`. Baseline: no protected changes, five authorized UI files. Sources: activation false. `pip check` passes.

Not done, and needing approvals or reviews:
- provisioning on the VM (approval of the preview);
- the authenticated read-only prerequisite inspection;
- recording the OpenSCAP version and activating the catalogue after source/site-policy review;
- the reviewed UFW registration;
- a first live end-to-end assessment.

No VM was contacted or changed.

## 2026-11-06 Ubuntu agents checkpoint — task 9 partial (simulated round complete; gated, not live)

Test-first. `tests/integration/test_ubuntu_agents.py` failed before the implementation (missing `AgentLogStore`/agents, the backend constructor parameters, and the agentic button handler). Before green, I corrected two things in my own new tests: a fixture-dependent guess of which controls are unresolved, now read from `read_ranking` by a ranking-aware fake; and a misleading test name.

- **`backends/ubuntu/agents.py`:** Orchestrator, Scanner and Analysis role tools run by the **unchanged** Windows `Coordinator` (`hardening/investigation.py`) and Ollama client.
  - **Budgets:** phase 600 s; Scanner 180 s and Analysis 220 s within the remaining phase budget; orchestrator 12 steps/16 calls/3 invalid; child roles 8/10/2; per-request ≤90 s; one no-tool reminder.
  - **Validated in code:** every tool call names the verified `target_id`, uses exact argument keys and enumerated codes, and follows the role state machine (scan → coverage → optional single rescan only when Error results exist → handoff; ranking → at most 2 inspections → submit with ≤3 flags on confirmed failures and exactly one triage code per unresolved control; delegate scanner → delegate analysis → plan).
  - **Never shown to models:** raw evidence values. The model sees only status counts, control IDs, catalogue titles, and code-generated subcheck names, states and reasons. The goal (≤300 chars) is passed as quoted untrusted data and can only justify an `outside_goal` deferral.
  - **No fix can be proposed:** no Ubuntu remediation family exists yet. The plan accepts only `defer` with fixed reason codes; any `fix`, action ID, extra field or altered factor is refused; omitted findings are deferred by code (`not_decided`). There is **no Remediation Agent yet**; it arrives with tasks 10–15.
- **`backends/ubuntu/storage.py`:** `AgentLogStore` exposes the agentic file's investigation tables to the unchanged `InvestigationLog`. `record_round(..., mode='agentic', details=...)` stores the bounded round references and validated outcomes; deterministic rounds take none.
- **`backends/ubuntu/adapter.py`:**
  - **Agentic `start_round`:** runs through the same gate and ledger claim as deterministic. `can_use_model` = gate open and the local model probe passes. Each scan is the same read-only helper invocation, validated and stored before any role sees it.
  - **No evidence collected:** the round is refused with its agent log kept, and the message offers **Assess without AI**.
  - **Evidence collected but analysis or plan incomplete:** the round is still recorded, and its step shows `failed` rather than hidden.
  - **Snapshot:** the agentic Agent log comes from the durable Coordinator events of all three roles. A deterministic round shows one `system` event labelled `Deterministic (no AI)`. Approve/Execute/Verify show `skipped` (no proposal exists), not `pending`.
  - **History:** now lists only runs of recorded rounds, as Windows does. Superseded rescans and interrupted-round evidence are not history.
- **`hardening/agentic_view.py`** (authorized scoped edit): the Ubuntu **Start agentic round** button now runs `start_round` with the goal input. Both Ubuntu buttons stay disabled while the gate is closed. `docs/authorized-ui-changes.patch` has been refreshed.

**Hermeticity bug found and fixed.** With the test-only gate open, one existing live-path test used the default model probe. During one local test run it made real loopback requests to the developer's local Ollama `qwen3:8b`, on synthetic fixture data only; no VM was involved. That test asserted the now-superseded rule "agentic refused until Ubuntu agents exist". It was replaced by the current equivalent ("agentic refused while the local model is unavailable; nothing claimed or scanned"). All open-gate test backends now use a stopped-model probe and a client that fails if called. The suite time dropped from 36.7 s to 4.6 s for those modules.

Verification (scripted fake models and fake helper; synthetic evidence; no VM):
- **Agent tests (14):** in-order delegation; deferral of every finding; refused fabricated tool, `fix`, action ID and score fields; out-of-order and repeated calls blocked; model offline gives no scan; phase deadline; injected evidence text never reaches any model; investigation, flag and rescan limits; scan failure; goal-dependent `outside_goal`.
- **Backend:** agentic round recorded with all three roles in the Agent log and no proposals; deterministic mode with the model stopped calls no model and labels system activity; offline agentic refused with its log kept, then deterministic works; incomplete analysis recorded as `failed`.
- **Page:** the same page's **Start agentic round** runs exactly one simulated round and shows the five tabs and an Agent log with all three roles.

A mutation allowing `fix` decisions failed a test and was reverted. Full suite **310 tests in 27.507s, all passed**, log `.integration-tmp/ubuntu-agents-full-regression.log`. Baseline: no protected changes (Coordinator and Ollama client are imported unchanged). Sources: activation false. `pip check` passes.

Not done:
- No real-model Ubuntu round has been evaluated. Only scripted fakes, plus the accidental fixture-only loopback calls noted above, which were not evaluated as results.
- The gate is closed.
- No Remediation Agent or action family exists.
- No measured performance against the 600 s budget.
- No live VM assessment.

M3 is not complete.

## 2026-11-06 target runner foundation checkpoint — task 10 partial (no live family, no supervision yet)

Test-first. `tests/integration/test_ubuntu_runner.py` failed before the implementation (15 errors: missing modules). Before green I corrected my own new fixtures: non-hex workflow/round IDs, which the schema rightly refuses, and fixed-clock subprocesses so fixture approvals are not judged by wall time. The test-only family lives in `tests/integration/runner_fixture.py` (writes one value in a temporary directory) and is never registered in production.

- **`vm/ubuntu/remediation_schema.py`** (shared, stdlib):
  - `ubuntu-remediation` schema 1, accepted only in exact canonical bytes. Binds target/epoch/identity, workflow/round, evidence digest, catalogue/control/predicate, action ID/version/implementation hash, typed parameters, before-state and expected after-state digests, approver, approval/expiry (≤1 h), before-state age at approval (≤5 min), job deadline (≤1,800 s) and recovery scope.
  - Strict receipt schema with outcomes `applied`, `refused`, `unresolved`, `reconciled_applied`, `reconciled_not_applied`.
- **`backends/ubuntu/actions.py`, `approvals.py`:** `plan_action` accepts only a registered family, a supported control, valid parameters and an in-limit deadline. `approve(plan, operator, now)` emits the exact bytes and SHA-256; `verify` re-checks bytes, hash and expiry. **`FAMILIES` is empty** (host and target): reserved catalogue action IDs cannot plan or run.
- **`vm/ubuntu/runner.py`** (target, stdlib):
  1. Takes an atomically created persistent fence.
  2. Validates identity, expiry/clock skew, the registered family, version/implementation hash, parameters and deadline.
  3. Rejects request-ID conflicts.
  4. Requires a fresh read-set equal to the approved before-state.
  5. Requires the family's own deterministic result to equal the approved after-state. This catches parameters altered in transit, which stay canonical and well-formed, so `inconsistent_request` is refused with zero writes.
  6. Stores the request, claims it atomically, re-reads immediately before the write, writes, checks the after-state, and writes the receipt atomically.

  The fence is released only on a clean terminal outcome. Apply exceptions, unexpected after-states and process death keep it. `reconcile(request_id)` decides from current state (before → not applied; expected → applied; anything else stays unresolved and fenced) and never re-executes; a claimed request is never run again.
- **`backends/ubuntu/executor.py` + `system/ledger.py`:**
  - `execute` verifies the approval and workflow/target/epoch, claims the ledger operation as a mutation (target ownership; the dispatch key is the request hash, so another operation ID cannot dispatch again), dispatches once, and trusts only a receipt for exactly this request ID and hash.
  - A lost or untrusted receipt becomes `unresolved` and blocks further mutations.
  - `reconcile` settles from the target's record through the new `CoordinationLedger.reconcile` (audited, unsettled operations only, no time-based takeover).
  - `completed` means applied as approved; compliance still needs a fresh verification scan.

Verification (TEST-ONLY family, temporary files; no VM, no system configuration):
- canonical-bytes and strict reparse;
- stale before-state, operator, control and deadline refusals;
- applied once with the fence released, and a duplicate refused;
- change before dispatch, and change after claim, both with zero writes;
- identity, expiry, implementation hash, inconsistent and non-canonical requests and an unknown family refused with zero writes;
- apply exception unresolved, keeps the fence against other requests, and reconciliation leaves an unknown state fenced;
- **real process death** (`os._exit`) after a write reconciles to applied; a simulated crash after claim reconciles to not applied; neither replays;
- **two real processes** racing on one request: exactly one applies;
- host: applied once, and a second operation cannot redispatch; a lost receipt is unresolved, blocks the target, then reconciles without replay; expired, tampered or wrong-workflow approvals are refused before dispatch; a receipt for another request is not trusted.

Mutations that released the fence after uncertainty, or treated a lost receipt as refused, failed tests and were reverted. Full suite **325 tests in 28.445s, all passed**, log `.integration-tmp/ubuntu-runner-full-regression.log`. Baseline: no protected changes. Sources: activation false. `pip check` passes.

**Still open in task 10 (live families stay disabled):**
- root-owned runner deployment and its fixed sudo entry;
- persisting proposals, decisions and receipts in `UbuntuStore` and opening `UbuntuBackend.decide`/`execute_approved`;
- systemd-supervised long jobs (1,800 s package cap);
- the SSH/UFW recovery watchdog with acknowledgement over a fresh connection (120 s);
- auxiliary maintenance (refresh, reboot, recovery) schemas and the `request_auxiliary → decide → dispatch_auxiliary` path;
- cancellation semantics;
- the fault-injection gate across SSH, dashboard and supervisor loss.

The runner's ownership check (`require_root_owned`) and the POSIX atomicity assumptions have not run on the Ubuntu target; tests ran on the Windows host.

## 2026-11-06 proposal, approval and gated execution path checkpoint — task 10 partial

Test-first (`tests/integration/test_ubuntu_proposals.py`, `test_ubuntu_fix_ui.py`). The new tests failed before the implementation on missing APIs. Before green I corrected three of my own test mistakes:
- a preview clock later than the approval time, which the approval correctly refused;
- choosing a control the fake target does not fail (it fails none; the test now injects runtime ASLR = 0 to make 1.5.1 Non-Compliant);
- a string literal broken by my patch script.

- **`UbuntuStore`**:
  - `add_proposal` stores a deterministic plan only for a recorded round of the same workflow, target and epoch.
  - `record_decision` keeps one append-only decision per proposal: the **exact approved request bytes**, which must equal the stored plan field for field and match its action, or a rejection that writes nothing.
  - `add_comment` stores comments apart from the approval bytes.
  - `record_receipt` accepts only receipts for that proposal's approved request ID and hash; reconciliation receipts are appended.
  - `proposals(binding, round)` reads them back.
  - `consistency_errors` now also reports proposals without rounds, decisions without proposals, and receipts without an approved request.
- **Target runner:**
  - `Runner.preview(action_id, params)` is read-only and takes no fence. It returns the before and expected-after digests the runner will later check, the collection time, and the family's sanitized summary.
  - `vm/ubuntu/runner_cli.py` and the fixed launcher `vm/ubuntu/runner` accept exactly `preview`, `execute` (header line, then exact approved bytes) or `reconcile`, with one fixed failure line.
  - `SshChannel.invoke_runner` uses the only privileged write command, `sudo -n /usr/local/libexec/fyp-hardening/runner`; collector and runner share one bounded fixed-command path.
  - The runner files are part of the digest-pinned helper bundle, and `.gitattributes` pins the launcher's line endings.
- **Agents:** the Orchestrator may choose `fix` only for a confirmed failure that a registered family can plan deterministically, with exactly that family's action ID and a fix reason code. Nothing is eligible before a scan. Parameters always come from the family planner, never the model.
- **`UbuntuBackend`:**
  - **Proposals:** after an agentic round, each accepted fix gets a target preview and a stored plan. A failed preview creates no proposal.
  - **`decide`:** latest round only, ledger-claimed; approval rebuilds the plan only if the family is still registered at the same version and hash, then binds the exact bytes (≤1 h expiry, before-state ≤5 min old).
  - **`execute_approved`:** behind `execution_gate()`, which is **closed**. It requires the expected set to equal the current approved request IDs, dispatches each not-yet-executed request once through the host executor, stores its receipt, and stops at the first non-completed outcome.
  - **Snapshot:** proposals and results show in the common rows, with `approved_request_id` (a new optional, defaulted `ProposalRow` field) for exact-set confirmation. Execution is reported as applied, never as verified compliant.
  - **Capabilities:** `can_remediate` follows the execution gate and requires a registered family.
- **`hardening/agentic_view.py`** (authorized scoped edit) and **`system/ui/components.py`:** the Ubuntu Fixes tab shows each proposal with its preview, decision and recovery scope.
  - **Approve/Reject:** each proposal has buttons that need an operator name.
  - **Execute:** the approved set is listed with IDs, and execution needs an explicit confirmation checkbox. The click runs in the button callback, which also clears the confirmation, so it can never carry over to another set. Failures are shown on the next render.
  - **Why execution runs in the callback:** clearing the confirmation before the click is handled had made Streamlit render the button disabled and drop the click; this was found and fixed by the page test.

**Encoding issue found and fixed.** One of my patch scripts wrote `system/ui/components.py` using the Windows default cp1252, which saved a new `·` character as an invalid UTF-8 byte. It was repaired, and a scan confirmed every `.py`, catalogue JSON and docs Markdown file under the app decodes as UTF-8. Earlier patch scripts in this session used the same pattern, but they added only ASCII, and existing bytes round-trip unchanged.

Verification (TEST-ONLY file family and fakes; no VM):
- **Store:** lifecycle; append-only guards; approval that must match the stored plan and binding; rejection writing nothing; foreign receipts.
- **Runner:** preview read-only and consistent with execution; runner CLI operations and refusals; fixed channel command.
- **Agents:** fixes accepted only for eligible controls with their exact action.
- **Backend:** previewed proposal → approve → closed gate refuses → wrong set refused → execute once → second call does not redispatch → result row says verification required; rejection writes nothing; no registered family gives no proposal and no runner call.
- **Page:** approve needs an operator name; execute is disabled while the gate is closed and until confirmed; one confirmed click writes exactly once.

Full suite **337 tests in 33.771s, all passed**, log `.integration-tmp/ubuntu-proposals-full-regression.log`. Baseline: no protected changes; `docs/authorized-ui-changes.patch` refreshed. Sources: activation false. `pip check` passes.

**Still open in task 10:**
- the fresh verification scan after execution (Verify step);
- systemd supervision of long jobs;
- the SSH/UFW recovery watchdog;
- maintenance/auxiliary operations and cancellation;
- runner deployment (needs approval);
- the fault-injection gate.

The execution gate stays closed, no real family is registered, and nothing can change the VM.

## 2026-11-06 first real family checkpoint — task 11 partial: sysctl family (1.5.1, 3.3.1, 3.3.2, 3.3.8)

I read CIS 1.5.1 (printed pp.151–153, text extracted with pypdf because PDF rendering is unavailable on this host). Remediation sets the parameter in `/etc/sysctl.conf` or an `/etc/sysctl.d/*.conf` file and runs `sysctl -w`. A canonically later file, or a later line in the same file, overrides; the audit also considers UFW's sysctl file.

Test-first (`tests/integration/test_ubuntu_sysctl_family.py`, 8 tests). Before green I corrected one fixture that used a non-matching managed-file header, which the family correctly refused.

- **`vm/ubuntu/family_sysctl.py`** (target, stdlib):
  - **Parameters:** exactly the `spec.SYSCTL` keys and values for the control; only IPv6 keys may be omitted.
  - **Write:** one managed drop-in, `/etc/sysctl.d/60-fyp-hardening-cis.conf`, with an exact header and merged `key = value` lines; foreign content in it is refused. Runtime is set by fixed `/usr/sbin/sysctl -w key=value` argument lists for listed keys only. No other file is edited.
  - **Eligibility (preview and before claim):** refused when a canonically later source (by file name) or UFW's sysctl file sets a key to another value. Earlier sources and later sources with the same value are allowed.
  - **Read-set:** an order-independent path→hash map of every listed source, the managed content, the UFW file hash and the runtime values, so the expected after-state is exact.
  - The implementation hash is the module's own bytes; the module is in the digest-pinned helper bundle.
  - `LinuxSysctlSystem` gives the family fixed, bounded target I/O:
    - the source list from `systemd-sysctl --cat-config` headers;
    - allowlisted directories only, with the single Ubuntu `99-sysctl.conf → ../sysctl.conf` symlink allowed;
    - an atomic 0644 write that refuses symlinks;
    - runtime reads and writes through fixed commands.

    **It has not run on the VM.**
- **Runner:** an optional family eligibility hook runs before the claim (`not_eligible`, zero writes) and in preview. The exact before-state bytes are stored in the request directory for approved recovery. `runner_cli` builds the real families over a preflighted `FixedProbeIO` (root, Ubuntu 22.04, identity).
- **Host:** `backends/ubuntu/actions.FAMILIES` now holds the four sysctl specs.
  - **Planner:** proposes only when the control is Non-Compliant, the sysctl resolution is complete, and IPv6 state is known; IPv6 keys are dropped only when IPv6 is affirmatively disabled.
  - **Recovery scope:** the managed file plus the runtime keys.
  - **Agreement:** host and target registries agree on IDs, versions and implementation hashes (tested).
  - **Superseded test:** the old "registry is empty" test now asserts exactly these four actions and 26 absent reserved IDs.
- **Catalogue coverage** (`catalogues/ubuntu2204.json`): assessment `fixture_tested` for all 30; remediation and refusal `fixture_tested` for 1.5.1, 3.3.1, 3.3.2 and 3.3.8; verification and recovery remain `not_implemented`; live validation remains `not_run`. `tools.check_sources` still passes, with activation false.

Verification (in-memory fake system; no VM, no real sysctl):
- parameter schema;
- the apply path, which writes only the managed file and listed runtime keys;
- other controls' managed keys preserved;
- later, UFW and foreign-content conflicts refused, with earlier and same-value sources allowed;
- the runner applies once, keeps the before-state, and refuses a conflict that appears after approval with zero writes;
- the host planner's eligibility;
- host/target registry agreement;
- the conf parser (slashes, dashes, comments, last value wins).

A mutation disabling the later-file check failed a test and was reverted. Full suite **345 tests in 32.964s, all passed**, log `.integration-tmp/ubuntu-sysctl-full-regression.log`. Baseline: no protected changes. `pip check` passes.

Open:
- the fresh verification scan after execution;
- recovery (`recovery.restore.v1`);
- live validation;
- supervision and watchdog;
- runner deployment;
- the remaining 26 families.

The execution gate stays closed.

## 2026-11-06 post-execution verification checkpoint — task 10/11 partial

After `execute_approved` applies at least one change, the backend runs a fresh read-only collection through the same helper, validator and predicates, and records it as a `verification` round (deterministic, linked by `verifies_round` and the applied request IDs). Store rounds now carry a kind; verification rounds never become the displayed or decidable round, but appear in history.

Result rows now show the control's fresh status: for example the TEST-ONLY family "applied" yet verification still Non-Compliant, with "No automatic retry". If no fresh evidence can be collected, the execution returns `verification_pending`, the Verify step stays pending, and nothing is retried. Verification needs the same accepted OpenSCAP engine as any Live collection, so it cannot run while the assessment gate is closed.

Tests: the existing end-to-end remediation test now asserts applied + verified Non-Compliant + both steps done + history including the verification round. A new test covers a refused verification collection giving `verification_pending`, one write, and no retry. Catalogue coverage: verification is now `fixture_tested` for 1.5.1, 3.3.1, 3.3.2 and 3.3.8; recovery and live validation are still pending. Full suite **346 tests in 29.930s, all passed** (`.integration-tmp/ubuntu-verification-full-regression.log`); baseline, sources and `pip check` pass. No VM was contacted.

## 2026-11-06 user approvals recorded

The user (Teoh Kai Hong) wrote in chat: "continue the development, i approve the stuff that need my decision". Recorded as a **blanket approval, not an item-by-item review**:

- `catalogues/ubuntu2204-risk.json`: `review_status` approved, with the reviewer string stating the blanket basis and a UTC time. Ubuntu risk scores are now shown, labelled with that basis. Draft-state behaviour is still tested with an explicit pending copy.
- `catalogues/source-lock.json`: `review_status` approved, plus a new `review_record` (reviewer, time, scope = interpretations, site policies and the SCAP reconciliation rule in `docs/SOURCES.md`, and the exact chat basis). All 30 catalogue controls are `review_status` approved.
- **Not changed by the approval:** `openscap_version` stays null and `activation_ready` false. The assessment gate stays closed until the real VM version is observed and recorded. The execution gate stays closed.
- **Not executed by the approval:** VM provisioning needs the user's snapshot and console run. No credentials are held by the assistant.
- Commits on `integrate/unified-vm-hardening` are now authorized (local only; no push, merge or deploy).

Six risk tests that encoded the pending state were updated to the recorded approval, or now use an explicit pending copy; none were deleted. Full suite **346 tests in 32.440s, all passed**; baseline, sources and `pip check` pass.

## 2026-11-06 VM facts reported by the user; provisioning bundle built

- **Reported by the user:** VM `FYP-Ubuntu2204`, console login works, `whoami` vboxuser, hostname FYP-Ubuntu2204, `/usr/bin/oscap` version 1.2.17. Existing snapshot `03-pre-demo-acceptance-20261021` (created 21/10/2026 by Codex; its description mentions an earlier deployed framework). A fresh snapshot before provisioning was requested.
- **Compatibility finding:** the pinned datastream is SCAP 1.3 / OVAL 5.11.2, and OpenSCAP 1.2.17 likely cannot evaluate it. This is recorded in `source-lock.json` `openscap_validation`; `openscap_version` stays null and activation false. A read-only `oscap info` / `oscap ds sds-validate` check on the VM was requested before any engine or content decision.
- **Bundle:** `tools/build_ubuntu_bundle.py` builds `dist/ubuntu-helper` (git-ignored) with the exact helper bytes, launchers, pinned datastream, `SHA256SUMS`, `install.sh` and `uninstall.sh`. The sudo rule covers the read-only collector only. Two new tests check exact bytes, hashes, scope and script syntax.
- **Bug found and fixed:** the installed package directory must also contain the launcher copies, or the target-side collector digest could never be computed.
- Full suite **348 tests, all passed**; baseline: no protected changes. Nothing was run on the VM by the assistant.

## 2026-11-06 OpenSCAP 1.2.17 selection finding; tailoring and UFW registration

- **User-run read-only checks on FYP-Ubuntu2204:**
  - `oscap info` parses the pinned SCAP 1.3 datastream and lists `cis_level2_server`; `oscap ds sds-validate` exits 0.
  - A selected-rule evaluation with 53 `--rule` options exited 0 with **1 notapplicable and 622 notselected** results: OpenSCAP 1.2.17 evaluated only the last `--rule`.
- **Fix:** `backends/ubuntu/scap_tailoring.py` generates a deterministic XCCDF tailoring file from the pinned datastream. It defines profile `xccdf_org.fyphardening_profile_cis_level2_server_selected30`, which extends `cis_level2_server` and keeps its refinements, selects exactly the 53 rules and deselects the other 570. Its SHA-256 is pinned in `spec.SCAP_TAILORING_SHA256`. Target and host scans use `--tailoring-file ... --profile <tailored>` with no `--rule`; the collector refuses a tailoring file that does not match the hash; the bundle ships and installs it.
- **Other user-reported facts:** Python 3.10.12; `vboxuser` may run `(ALL : ALL) ALL` with `use_pty`; UFW active and enabled (deny incoming, **allow outgoing**, disabled routed, SSH allowed from 192.168.56.1 only); nftables disabled; netfilter-persistent absent; machine ID matches.
- **UFW registration:** `system/config.UBUNTU_FIREWALL_REGISTRATIONS` registers UFW for machine `f1d16ae7…`, approved by the user. The collector still checks competing managers per scan.
- **Still unaccepted:** the OpenSCAP version stays null until a tailored evaluation on the VM returns real pass/fail results.
- Full suite **352 tests, all passed**; baseline: no protected changes; sources: activation false.

## 2026-11-06 OpenSCAP accepted; sources activated; first install reported

- **Tailored evaluation (user-run, read-only):** exit 2; 53 evaluated (10 pass, 28 fail, 15 notapplicable), 570 notselected. `source-lock.json`: `openscap_version` 1.2.17 with the validation evidence, `activation_ready` true. The **read-only assessment gate is open**; the **execution gate stays closed**.
- **Fresh recovery snapshot (user-reported):** `Before_Unified_Hardening_Provisioning_2026-11-06`.
- **First install:** the user ran `install.sh` and reported Python 3.10.12 and oscap 1.2.17. That install used the bundle copied **before** the tailoring change, so reinstalling from the rebuilt bundle (uninstall first) was requested; otherwise the tailoring file is missing and the helper digest differs.
- **Tests:** eight tests that assumed inactive sources or no accepted engine were updated. Closed-gate behaviour is now tested with an explicitly closed gate or an inactive lock copy, and the real gate is asserted open from recorded evidence. None were deleted. Full suite **352 tests, all passed**; baseline: no protected changes.

## 2026-11-06 first live run: /proc/sys read fix

- The user connected through the app (fingerprint entered). **Assess without AI** returned "Ubuntu fixed helper command refused or is not installed (exit status 2)", the helper's own refusal code.
- A user-run read-only diagnostic traceback showed `OSError [Errno 12] Cannot allocate memory` from one `read(4 MiB + 1)` of `/proc/sys/kernel/hostname` in `preflight`: sysctl proc files allocate a buffer of the requested size.
- **Fix:** `collector.read_bounded` reads in 64 KiB chunks and enforces the same limit across chunks. All collector file reads and the runner identity read use it. New `tests/integration/test_bounded_read.py` (a sysctl-like stream that fails on large reads) failed before the fix.
- Bundle rebuilt; a reinstall is required. Full suite **354 tests, all passed**; baseline: no protected changes.

## 2026-11-06 second live diagnostic: sysctl, GRUB and inventory fixes

- **User-run read-only diagnostic:** `systemd-sysctl --cat-config` exit 0 (290 lines). Eight keys are set in no file; the IPv4 `accept_source_route` keys hit Ubuntu `50-default.conf` globs and exclusions. `grub.cfg` is uid 0, mode 0664 (refused by the old trust rule). The privileged inventory exceeded 20 s / 100,000 entries.
- **Fixes (test-first, `tests/integration/test_live_findings.py`):**
  - CIS-aligned exact-name resolver returning `unset`; schema accepts `unset`; the predicate fails it.
  - The sysctl family parses exclusions and refuses conflicting later globs.
  - `trusted_owner` allows root-group write only.
  - Inventory budget 120 s / 2,000,000 entries, still metadata-only.
- Earlier in the same pass: the sshd `without-password` alias maps to `prohibit-password`; units that are not installed report `not-found`.
- Full suite **363 tests, all passed**; baseline: no protected changes; helper Python 3.10 syntax checked; bundle rebuilt. Reinstall required.

## 2026-11-06 FIRST LIVE UBUNTU ASSESSMENT (read-only) — Assess without AI

Run by the user through the existing app: SSH connect with the independently verified fingerprint, then **Assess without AI**. The installed root-owned helper ran through the single `sudo -n` collector rule. Selected-rule OpenSCAP 1.2.17 evaluation used the pinned tailoring. The evidence was validated, stored and shown in the shared Controls tab. Evidence `37889bd4287f…`, mode **Live (SSH)**, collected 2026-11-06T10:22:06Z.

| Status | n | Controls |
| --- | --- | --- |
| Compliant | 5 | 1.3.1.1, 1.5.4, 4.1.3, 5.2.2, 5.4.1.3 |
| Non-Compliant | 20 | 1.5.1, 1.5.3, 2.1.2, 3.3.1, 3.3.2, 3.3.8, 4.1.7, 5.1.7, 5.1.16, 5.1.20, 5.2.3, 5.3.3.2.2, 5.4.1.1, 5.4.1.5, 6.3.1.1, 6.3.1.2, 6.3.1.3, 6.3.3.4, 6.3.3.6, 6.3.3.8 |
| Unknown | 5 | 1.2.2.1 (fresh-update check not implemented), 4.1.4 (UFW loopback resolver unsupported), 5.1.10, 5.1.19, 5.1.21 |

- **Coverage** 25/30 (83%); **compliance** 5/25 (20%); 0 Error.
- **SCAP/direct conflict:** 5.1.10, 5.1.19 and 5.1.21 have effective `sshd -T` values of `no` (the CIS audit method), but the ComplianceAsCode rules require an explicit configuration line, so the SCAP rules fail. Under the approved conflict rule this is Unknown, not a guess. Whether CIS-effective direct evidence should prevail for these three is a recorded interpretation question.
- **Gates:** no write was possible; the execution gate is closed. Live remediation, recovery and watchdog acceptance remain outstanding.

## 2026-11-06 approved restore (recovery.restore.v1) — task 10 partial

Test-first: `tests/integration/test_ubuntu_restore.py`, two backend tests in `test_ubuntu_proposals.py`, and an extended page test. All failed before the implementation.

- **Target, `vm/ubuntu/family_restore.py`:** an auxiliary family the runner always registers.
  - **What it restores:** one applied request (exact request bytes and hash), back to its stored before-state.
  - **When it refuses:** if the original was not applied, the original family or version is unavailable, the stored before-state fails its hash, or the current state no longer equals the state the fix produced. A restore therefore never overwrites a newer change.
  - **Protocol:** the same runner fence, claim, receipt and at-most-once rules. Restores are not restorable.
  - `SysctlFamily.restore` rewrites the recorded managed file, or removes it if it did not exist, and resets the recorded runtime values; `LinuxSysctlSystem.remove_managed` refuses symlinks.
- **Host:**
  - `actions.AUXILIARY` holds the restore spec, which is never a CIS family.
  - `UbuntuBackend.request_auxiliary(RECOVERY, applied fix, RecoveryInput(request ID, before-state digest, restore_before_state))` previews on the target and stores a **recovery** proposal.
  - `decide` approves it; `dispatch_auxiliary` runs it once behind the closed execution gate, followed by a fresh verification scan.
  - Recovery proposals never join the `execute_approved` CIS fix set. Other auxiliary kinds are refused explicitly.
  - `ProposalRow` gains an optional `before_state_sha256`.
- **UI (authorized scoped edit):** **Prepare restore** for an applied fix; the restore is approved like any proposal; a confirmation checkbox and **Run approved restore** dispatch it once.
  - Fixed in passing: the page's fix set now excludes approved restores, which would otherwise have made the backend reject the set.
  - Re-entering the operator name for a new decision is expected, because Streamlit clears the hidden field.
- **Coverage:** recovery is now `fixture_tested` for 1.5.1, 3.3.1, 3.3.2 and 3.3.8; live validation is still pending.
- **Mutation:** disabling the newer-change guard failed the overwrite test; reverted.
- Full suite **369 tests, all passed**; baseline: no protected changes; UI patch refreshed; bundle rebuilt.
- **Note:** the helper bundle changed, so the VM needs a reinstall before the next live scan. Otherwise the collector digest no longer matches and the evidence is rejected.

## 2026-11-06 core-dump family (CIS 1.5.3) — task 11 partial

I read CIS 1.5.3 (printed pp.159–161) in full first, along with 1.5.4 and 2.1.2.

- **`vm/ubuntu/family_core.py`** (`ubuntu.1.5.3.v1`) has three managed parts and edits no other file:
  - `* hard core 0` in `/etc/security/limits.d/60-fyp-hardening-cis.conf`;
  - `fs.suid_dumpable = 0`, persisted in the shared managed sysctl drop-in (the sysctl machinery gained an internal `SUBPART`, not a separate action) and at runtime;
  - only when `systemd-coredump` is installed, `Storage=none` and `ProcessSizeMax=0` in the drop-in `/etc/systemd/coredump.conf.d/60-fyp-hardening-cis.conf`, which overrides `coredump.conf` without editing it.
- **Not eligible** when a non-zero hard core limit exists for another domain, a later `*` limit exists, a later coredump drop-in overrides, or a later sysctl source conflicts. Foreign content in a managed file is refused.
- **Restore:** returns each managed file, or its absence, and the runtime value exactly.
- **Implementation hash** covers the family and the sysctl module it uses. Host spec (`backends/ubuntu/actions.FAMILIES`) and target registry agree. `LinuxTargetSystem` composes the bounded sysctl and limits/coredump I/O for the runner.
- **Deliberately omitted:** `systemctl daemon-reload` from the CIS remediation text. `systemd-coredump` reads its configuration on each invocation, so the family avoids a service-manager action. Recorded for review.
- **Coverage:** 1.5.3 remediation, refusal, verification and recovery are `fixture_tested`; live validation is pending.
- **Tests:** 7 new tests in `tests/integration/test_ubuntu_core_family.py`, written first. A mutation that disabled the limits guard failed two subtests. Two registry tests were updated to the exact five implemented families (25 reserved IDs remain absent).
- **2.1.2 Avahi:** not implemented yet. The CIS remediation is package purge, which needs the package family and supervision. The mask-and-retain branch needs a dependency fact and a site-policy exception; without them the predicate correctly stays Unknown.
- Full suite **376 tests, all passed**; baseline: no protected changes; bundle rebuilt (reinstall before the next live scan).

## 2026-11-06 sudo log file (CIS 5.2.3) and password length (CIS 5.3.3.2.2) — task 12 partial

I read CIS 5.2.3 (printed p.562) and 5.3.3.2.2 (printed pp.605–607) in full first.

- **`vm/ubuntu/family_auth.py`, `ubuntu.5.2.3.v1`:** adds only `Defaults logfile="/var/log/sudo.log"` (the approved site path) in `/etc/sudoers.d/60-fyp-hardening-cis`. `/etc/sudoers` is never edited.
  - The file is first written as `/etc/sudoers.d/.60-fyp-hardening-cis.tmp`. The name contains a `.`, so sudo never reads it. It is checked with `visudo -cf`, moved into place, and then the whole configuration is checked with `visudo -c`. If either check fails, the file is removed straight away, so a rejected file is never left active.
  - **Not eligible** when any `Defaults` line negates `logfile`, when an include other than `/etc/sudoers.d` exists, or when the managed file holds content this family did not write. Restore removes the file or returns the earlier content, then validates again.
- **`ubuntu.5.3.3.2.2.v1`:** adds only `minlen = 14` in `/etc/security/pwquality.conf.d/60-fyp-hardening-cis.conf`, the location CIS recommends. `pwquality.conf` and PAM files are never edited.
  - Eligibility runs the collector's own resolver (`probes.password_minlen`) on the simulated after-state, using the CIS precedence order: module arguments, then `pwquality.conf`, then the last `.conf.d` file. It refuses if a PAM `minlen` argument, a `pwquality.conf` value or a later drop-in would still win, or if `pam_pwquality` is not in use. An earlier drop-in that the managed file supersedes is allowed.
  - Existing passwords are unchanged; only new passwords must meet the rule.
- **Host specs (`backends/ubuntu/actions.FAMILIES`):** 5.2.3 is proposed only when the sudoers were fully resolved and `visudo -c` passed in the evidence. 5.3.3.2.2 is proposed only when PAM resolution is `complete`. The implementation hash covers `family_auth.py` and `probes.py`, and the host and target registries agree.
- **Target I/O (`LinuxAuthIO`):** bounded, ownership-checked reads; writes use `O_NOFOLLOW` to the managed files only. `visudo` runs through the collector's fixed-environment, deadline-bounded runner.
- **Coverage:** 5.2.3 and 5.3.3.2.2 remediation, refusal, verification and recovery are `fixture_tested`; live validation is pending. A new test ties catalogue remediation coverage to the registered families exactly.
- **Tests:** 9 new tests in `tests/integration/test_ubuntu_auth_families.py`, written first (RED: 14 errors from the missing module and registry). Mutations that disabled the minlen precedence guard (3 failures) and the `!logfile` guard (1 failure) were caught and reverted. Registry tests now list exactly 7 implemented families; 23 reserved IDs remain absent.
- Full suite **385 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt (reinstall before the next live scan). Execution gate still closed.

## 2026-11-06 account aging (CIS 5.4.1.1, 5.4.1.3, 5.4.1.5) — task 12 complete

I read CIS 5.4.1.1 (printed pp.653–655), 5.4.1.3 (pp.660–661) and 5.4.1.5 (pp.665–666) in full first.

- **`vm/ubuntu/family_aging.py`** contains one parameterised `AgingFamily` with three registered actions. Each uses one fixed site value: `ubuntu.5.4.1.1.v1` (maxdays 365), `ubuntu.5.4.1.3.v1` (warndays 7) and `ubuntu.5.4.1.5.v1` (inactive 45).
  - **Default:** the family changes only the single `PASS_MAX_DAYS` / `PASS_WARN_AGE` line in `/etc/login.defs`, or the `INACTIVE=` line in `/etc/default/useradd`, and only when that default fails. Other bytes, the file mode and the group are preserved. A missing or duplicated line is refused, as the collector refuses it. A missing `/etc/default/useradd` is created and is removed again on restore.
  - **Accounts:** it runs a fixed `chage <flag> <value> -- <name>` argv, with no shell, only for password-bearing accounts whose own value fails. Compliant accounts and locked accounts are untouched.
  - **No password hash** enters state, a summary or a receipt. `parse_accounts` reuses the collector's account parser and adds only each account's last-change day.
- **Lockout guard (5.4.1.1 and 5.4.1.5):** an account that would be changed is refused when:
  - its last-change date is missing or `0` (forced change);
  - or its password would be expired, or would expire within **30 days**, under the new values.
  This protects the SSH management account (`vboxuser`) and every other password-bearing account. If a password is old, change it first and rescan, then the fix becomes eligible. 5.4.1.1 also refuses when `PASS_MIN_DAYS`, or an account's minimum age, is at least 365, because users could then never change their password. 5.4.1.3 (warning days) cannot lock anyone out, so it has no guard.
- **Approval summary:** shows the default change and each account's `[old, new]` value by name.
- **Restore:** writes the original default file content back. For each account it runs `chage` with the recorded value (`-1` blanks the field), and only where the value differs.
- **Host specs:** propose only for a Non-Compliant control with a complete account inventory. The target preview runs the lockout guard before anything is shown for approval.
- **Coverage:** 5.4.1.1, 5.4.1.3 and 5.4.1.5 remediation, refusal, verification and recovery are `fixture_tested`; live validation is pending.
- **Tests:** 11 new tests in `tests/integration/test_ubuntu_aging_families.py`, written first (RED: 22 errors). The fakes are checked with the real compliance predicate before and after.
  - **Mutation checks:** disabling the expiry margin (4 failures), the last-change check (1 failure plus 2 errors) or the minimum-age check (1 failure) was caught. A fourth mutation, which checked already-compliant accounts as well, first survived. A test with an already-compliant account was added and now catches it.
  - Registry tests list exactly 10 implemented families; 20 reserved IDs remain.
- Full suite **396 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt (reinstall before the next live scan). Execution gate still closed.

## 2026-11-06 systemd supervision and the commit-confirm rollback watchdog — target side

These are the mechanisms the package, SSH, UFW and audit families need. No family uses them yet; they are tested with test-only families and a fake launcher.

- **Supervision modes:** a family may declare `supervision = 'job'` or `'confirm'`. Families without it keep the existing in-session write unchanged.
  - **`job`:** after the usual fence, validation, read-set, self-consistency, eligibility, claim and re-read checks, the write runs in a transient unit, `fyp-hardening-job-<request>`. The unit is bounded by `RuntimeMaxSec` (the family's `max_seconds`), so an SSH disconnect can no longer interrupt it. `execute` returns a `running` receipt, and the unit writes the final receipt itself.
  - **`confirm`:** commit-confirm. A rollback timer, `fyp-hardening-rollback-<request>`, is armed **before** the job starts, set to `max_seconds + confirm_seconds` (the window must be 60–1800 s). If the timer cannot be armed, nothing is started (`refused / watchdog_unavailable`). After a successful write the job waits in `awaiting_confirmation`. `confirm` then settles it as `applied / confirmed` and disarms the timer. If no confirmation arrives, the timer restores the recorded before-state (`rolled_back / restored`). A failed write, or an unexpected after-state, rolls back immediately.
- **One decision per request:** confirm and rollback each try to exclusively create the same `decision` file, so exactly one of them wins. A late confirm returns the rollback receipt, and a late timer returns the confirmed receipt. A job never writes after a decision exists, after a terminal receipt, or when another request holds the fence. Rollback stops a still-active job before restoring.
- **Status (`reconcile`):** reports `job_running`, `awaiting_confirmation` or `rollback_in_progress` without touching state.
  - A `job` unit that ended without a receipt is decided from state as before; nothing is ever replayed.
  - A `confirm` job that ended with nothing to confirm is rolled back.
  - A confirmation that was interrupted before its receipt is finished from state.
- **Reboot:** transient timers do not survive a reboot. `boot-rollback` restores every unconfirmed commit-confirm change. The bundle now ships `systemd/fyp-hardening-boot-rollback.service` (oneshot, `Before=ssh.service`), hash-checked but **not** installed by `install.sh`. Enabling it is part of the separately approved runner deployment.
- **Entry points:** systemd calls `runner job <id>`, `runner rollback <id>` and `runner boot-rollback` through argv. These are refused unless `INVOCATION_ID` is set. systemd sets it for every unit, and `sudo` resets the environment, so the sudo route cannot use them. `confirm` arrives over stdin like the other host operations. `vm/ubuntu/supervision.py` builds fixed `systemd-run`/`systemctl` argv from a validated 32-hex request ID only. The job starts without `--no-block`, so the unit is already active when `execute` returns.
- **Host:** receipts gain the `running` and `rolled_back` outcomes. In the executor, `running` keeps the ledger claim running, and `rolled_back` settles as refused (not applied). A new `confirm()` settles a commit-confirm change. It must be sent over a fresh SSH login made after the change; that login is the proof the management channel survived. Backend and UI wiring follows.
- **Line endings:** my patch scripts used `write_text`, which on Windows turned three LF files into CRLF, including the `runner` shebang script. A CR in a shebang breaks it on Linux. I restored the original line endings before committing and added a test that both entry scripts stay LF. Patch scripts now write bytes.
- **Tests:** 15 new tests in `tests/integration/test_ubuntu_supervision.py` (RED first: 13 errors) and 1 new bundle test.
  - **Mutation checks:** caught — removing the decision guard, the fence guard, the awaiting check, rollback's job stop, the confirm-mode status rollback, the watchdog refusal and the `INVOCATION_ID` check. Removing the final-receipt-first check in `run_job` survives, because the fence check covers the same case.
- Full suite **413 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt. **Live acceptance is still pending**, and the execution gate stays closed.

## 2026-11-06 fix: "Ubuntu workflow binding required" after a Streamlit module reload

- **Symptom (user, live):** after reinstalling the bundle, **Assess without AI** failed twice (ledger 13:14 and 13:15 UTC). The helper ran its full collection, about 27 s each time. The Ubuntu store then refused to save: "Ubuntu workflow binding required". The VM was not changed, and the store files were not written.
- **Root cause:** Streamlit 1.66's file watcher evicts **every** watched app module from `sys.modules` when a watched source file event passes its change check, then re-imports them on the next rerun. On Windows, OneDrive and indexers can raise such events. The ledger, kept in `st.session_state` inside `ConnectionService`, kept the old `WorkflowBinding` class. `backends.ubuntu.storage` is imported lazily, so the re-imported store got the new class, and its `type(binding) is WorkflowBinding` check rejected a valid binding. I reproduced this outside Streamlit by evicting the modules between creating the ledger and importing the store. No source file changed after the app started, so the exact event is not known.
- **Fix:** `.streamlit/config.toml` sets `[server] fileWatcherType = "none"` and `runOnSave = false`. The app never hot-reloads code under a live SSH session; restart it to load code changes. The type check stays strict.
- **Test:** `tests/integration/test_streamlit_reload.py` reproduces the class split, then asserts the watcher stays off (RED before the config change). Full suite **414 tests, all passed**; baseline: no protected changes.

## 2026-11-06 supervised fixes in the backend and page: status checks and reconnect-to-confirm

- **One ledger operation per approved request:** `ubuntu-execute:<request_id>`, whichever page action dispatched it. A second dispatch of the same request is impossible, and a later status check or confirmation finds the operation without extra storage.
- **`refresh_execution`:** asks the target for the status of `running` or `unresolved` requests in the latest round. It never dispatches a write. A status receipt is stored only when its outcome or code changes. When a request is settled `completed`, the usual fresh verification scan runs. A rollback settles the operation as refused.
- **`confirm_change`:** accepted only when the request is in `awaiting_confirmation` **and** the current connection's login started after the host first saw that state.
  - The time the host first saw the state is a new ledger audit event (`note` / `first_event`), on the host clock.
  - The login time is a new `VerifiedSession.connected_at` field, taken **before** the SSH login begins. Both times come from the host clock, so the VM clock does not matter.
  - The connection that dispatched the change, or any older login, is refused with a fixed message and nothing is sent to the VM. A fresh login confirms it and runs the verification scan. Without a confirmation, the target's timer restores the before-state.
- **`pending_supervised`:** lists running, waiting or unresolved changes on this VM across all of its workflows. Disconnecting deliberately clears the page's workflow key, so this is how a fresh login finds what is waiting for it.
- **Disconnect and connect rule:** disconnecting used to be refused while the target held a change. That blocked the reconnect a commit-confirm needs. Now disconnecting is always allowed: it closes the channel and changes nothing on the VM. **Connecting to a different VM** is refused (`pending_change_elsewhere`, fixed message, credentials cleared) while another VM holds a running or unresolved change. Reconnecting to the same VM is allowed. The rule comes from the durable ledger, so it holds across app restarts.
- **Page (`hardening/agentic_view.py`, authorized scoped edit):** a panel above the Ubuntu tabs lists each pending change. Each entry has **Check status**, plus **Confirm change** when the change is waiting, with the reconnect instructions. Result rows explain `running`, `awaiting_confirmation` and `rolled_back`. `docs/authorized-ui-changes.patch` has been regenerated against baseline `af43fbc`.
- **Tests:** written first and seen to fail.
  - `tests/integration/test_ubuntu_supervised_backend.py` (6): confirm through a fresh login, rollback, status de-duplication, a plain job, ledger events, and finding a change after reconnecting.
  - `tests/integration/test_ubuntu_confirm_ui.py` (1, through the real page): execute, check status, refused on the same login, disconnect, reconnect, confirm. Exactly one execute and one confirm reach the target.
  - `tests/integration/test_routing.py` (+1): disconnect is allowed, another VM is refused, the same VM is allowed.
  - **Mutation checks, all caught:** removing the fresh-login check, loosening its time comparison, removing status de-duplication, removing the awaiting check, removing the other-VM refusal, and not restoring the workflow key.
- Full suite **422 tests, all passed**; baseline: no protected changes. Fixture-only: no family uses supervision yet, and the execution gate stays closed.

## 2026-11-06 supervised package families (CIS 1.3.1.1, 1.5.4, 2.1.2, 6.3.1.1)

I read the CIS remediation text for each control first: 1.3.1.1 p.136 `apt install apparmor apparmor-utils`; 1.5.4 p.160 `prelink -ua` then `apt purge prelink`; 2.1.2 pp.221–222 stop the socket and service, then `apt purge avahi-daemon`, or mask them when a dependent package is required; 6.3.1.1 p.752 `apt install auditd audispd-plugins`.

- **`vm/ubuntu/family_package.py`:** one `PackageFamily` with four registered actions. Each is a **systemd-supervised job** (`supervision = 'job'`, 900 s) that runs outside the SSH session. Parameters are exactly the CIS package set.
- **Eligibility is apt's own read-only simulation** (`apt-get -s`, with `--no-install-recommends` for installs):
  - an install may only add new packages; any removal, or an upgrade of an installed package, is refused;
  - a purge may only remove the installed CIS targets. If apt would take a dependent package with it, which is the CIS impact warning, the purge is refused, and the mask-and-retain branch stays a human decision;
  - half-installed targets, nothing to do, or an unavailable package are refused.
- **Exact state:** the recorded state is each target's dpkg status and version plus the simulated plan. After the change, the expected state is every target present (at its planned version) or absent, with an empty plan. The runner's after-state check therefore stays exact.
- **Steps:** 1.5.4 runs `prelink -ua` before the purge, and 2.1.2 runs `systemctl stop -- avahi-daemon.socket avahi-daemon.service` before it. Both are fixed allowlisted argv.
  - apt runs with `DEBIAN_FRONTEND=noninteractive`, `NEEDRESTART_MODE=l` (list only: needrestart never restarts services such as sshd), `--force-confdef/--force-confold` and a 120 s dpkg lock wait.
  - Package lists are not refreshed, so an unavailable download fails the job before dpkg changes anything.
- **Restore:** after an install, it purges exactly the packages the install added and nothing else. After a purge, it reinstalls the recorded versions. Purged configuration returns to package defaults, and prelinking is not redone. Both are stated in the approval summary.
- **Host specs:** a fix is proposed only for a Non-Compliant control whose package facts were collected. Coverage for 1.3.1.1, 1.5.4, 2.1.2 and 6.3.1.1 is now `fixture_tested`; live validation is pending.
- **On your VM:** 6.3.1.1 and 2.1.2 are the Non-Compliant ones, and 1.3.1.1 and 1.5.4 already comply. Whether the avahi purge is eligible depends on the VM's real dependents: if a desktop meta-package needs it, the purge is refused.
- **Tests:** 10 new tests in `tests/integration/test_ubuntu_package_families.py` (RED: 10 errors) with an in-memory apt fake, plus a simulation parser test.
  - **Mutation checks, all caught:** allowing upgrades, allowing dependent removals, allowing half-installed packages, an over-broad restore, and skipping the preparation steps.
  - Registry tests list exactly 14 implemented families; 16 reserved IDs remain.
- Full suite **432 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt (reinstall before the next live scan). Execution gate still closed.

## 2026-11-06 commit-confirm SSH families (CIS 5.1.7, 5.1.10, 5.1.16, 5.1.19, 5.1.20, 5.1.21)

I read the CIS 5.1.x text first (pp.502–553). The values are ClientAliveInterval 15 with ClientAliveCountMax 3, MaxAuthTries 4, and `no` for HostbasedAuthentication, PermitEmptyPasswords, PermitRootLogin and PermitUserEnvironment. CIS says "first occurrence of an option takes precedence", and allows the entry "in a file in Include location" when the order of precedence is understood.

- **`vm/ubuntu/family_ssh.py`:** one `SshFamily`, six registered actions. It writes only `/etc/ssh/sshd_config.d/00-fyp-hardening-cis.conf`, and `sshd_config` is never edited. Each control owns only its own keys in that shared file, written in one fixed key order. Its recorded state is just those keys' managed entries plus their effective `sshd -T` values, so SSH fixes for different controls neither invalidate nor undo each other.
- **Precedence is checked, not assumed.** The fix is refused for:
  - a `Match` block anywhere;
  - any `Include` other than the standard one, or the standard Include missing (or present more than once), since without it the drop-in is never read;
  - a main-file line before the Include that sets the same key;
  - an earlier drop-in, by lexical order, that sets the same key;
  - foreign content in the managed file.
  The runner's after-state check also compares the effective `sshd -T` values with the CIS values.
- **Write:** the file is written, checked with `sshd -t`, and sshd is reloaded with `systemctl reload ssh.service`; existing sessions survive a reload. If validation or the reload fails, the previous file is put back. The temp name does not end in `.conf`, so sshd never reads it.
- **Commit-confirm:** `supervision = 'confirm'`, `confirm_seconds = 600`. After applying, the operator disconnects and reconnects within 10 minutes and presses **Confirm change**. If the fresh login fails, for example because MaxAuthTries 4 is reached by offered keys, or nobody confirms, the rollback timer restores the before-state. The approval summary says so.
- **Host specs:** a fix is proposed only for a Non-Compliant control whose SSH context resolution is `complete`. 5.1.10, 5.1.19 and 5.1.21 are Unknown on the live VM because of the SCAP conflict, so they are not proposed; that interpretation question remains open. On the live VM, 5.1.7, 5.1.16 and 5.1.20 are the candidates.
- **Coverage:** all six are `fixture_tested`; live validation is pending.
- **Tests:** 8 new tests in `tests/integration/test_ubuntu_ssh_family.py` with an in-memory model of sshd's first-value-wins rule (RED: 13 errors).
  - **Mutation checks, all caught:** a main-file line before the Include, an earlier drop-in, a Match block, a missing Include, restoring other controls' keys, and not being commit-confirm. The missing-Include mutation first survived; a dedicated test was added.
  - Registry tests list exactly 20 implemented families; 10 reserved IDs remain.
- Full suite **440 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt (reinstall before the next live scan). Execution gate still closed.

## 2026-11-07 commit-confirm UFW default deny (CIS 4.1.7)

I read CIS 4.1.4–4.1.7 (pp.433–441) first. For 4.1.7 the remediation is `ufw default deny incoming|outgoing|routed`. Its impact note says to consider `allow out` http, https, ntp, port 53 and port 853 before applying.

- **Site-policy decision:** the allowed outbound traffic is exactly the CIS 4.1.7 list: DNS 53, http 80/tcp, ntp 123/udp, https 443/tcp and DNS over TLS 853. This was chosen under the user's blanket approval ("i approve the stuff that need my decision"). It appears in every approval summary and is easy to change later. `ufw logging on`, also in that list, does not affect connectivity and is not part of this change.
- **`vm/ubuntu/family_ufw.py`, `ubuntu.4.1.7.v1`:**
  - **Order:** the missing outbound allowances are added first, then only directions whose default is `allow` become `deny`; deny, reject and disabled already comply. Outbound traffic is never fully blocked mid-change.
  - **SSH replies:** UFW's before-rules keep accepting established traffic, so SSH replies continue.
  - **Refused when:** UFW is inactive, or incoming would become deny with no SSH (port 22) allow rule.
  - **Exact state:** ufw's reported defaults plus its own `### tuple ###` records from `user.rules`/`user6.rules`, with v6 twins only when `IPV6=yes`.
  - **Restore:** puts the default policies back first, then deletes only the allowances this change added. A rule that already existed is never deleted.
  - **Commands:** ufw runs only through an allowlist of fixed argv.
  - **Commit-confirm:** `supervision = 'confirm'`, 600 s.
- **Host spec:** proposed only for a Non-Compliant 4.1.7 with a registered UFW firewall manager (`firewall_manager = ufw`) and UFW active. On the live VM the expected change is outgoing allow → deny plus the five allowances. Incoming is already deny, and routed is disabled.
- **4.1.4 (loopback):** not implemented. It needs the pending collector rule resolver; until then the control stays Unknown.
- **Coverage:** 4.1.7 is `fixture_tested`; live validation is pending.
- **Tests:** 8 new tests in `tests/integration/test_ubuntu_ufw_family.py` with an in-memory model of ufw's records (RED: 10 errors).
  - **Mutation checks, all caught:** changing the defaults before adding the allowances, no lockout check, no active check, restore deleting pre-existing rules, and changing directions that already comply.
  - Registry tests list exactly 21 implemented families; 9 reserved IDs remain.
- Full suite **448 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt (reinstall before the next live scan). Execution gate still closed.

## 2026-11-07 sudo use_pty (CIS 5.2.2) and auditd service (CIS 6.3.1.2)

- **Shared sudo file:** `vm/ubuntu/family_auth.py` now has `SudoDefaultsFamily`, with one `Defaults` line per control in `/etc/sudoers.d/60-fyp-hardening-cis`: 5.2.2 `Defaults use_pty` and 5.2.3 `Defaults logfile="/var/log/sudo.log"`.
  - Each control's state is the other sudo sources plus whether its own line is present, so the two never invalidate each other. Restore removes or adds only its own line, and an empty file is removed.
  - Validation compares canonical JSON, so `{"use_pty": 1}` is not accepted as `true`.
  - A `!use_pty` (5.2.2) or `!logfile` (5.2.3) anywhere is refused.
  - `SudoLogfileFamily` keeps its name. Its implementation hash changed; it has not been deployed.
- **`vm/ubuntu/family_service.py`, `ubuntu.6.3.1.2.v1`:** CIS `systemctl unmask`/`enable`/`start auditd`, running only the missing steps.
  - **Refused when:** the unit is not installed (6.3.1.1 comes first, so the host does not propose it while `auditd.enabled` is `not-found`), or its enablement state is not modelled (static, indirect, ...).
  - **Restore:** returns the exact recorded enablement and activity. auditd's unit refuses manual stops, so stopping uses `systemctl kill --signal=SIGTERM` and waits for the unit to become inactive.
  - On the live VM, installing auditd (6.3.1.1) normally enables and starts it as well; 6.3.1.2 covers a disabled or masked unit.
- **Coverage:** 5.2.2 and 6.3.1.2 are `fixture_tested`.
- **Tests:** 2 new 5.2.2 tests and 4 new 6.3.1.2 tests, written first (RED: 10 errors).
  - **Mutation checks, all caught:** ignoring the negation, restore dropping the other control's line, accepting `1` for `true`, running every service step, and skipping the installed check.
  - 23 implemented families; 7 reserved IDs remain.
- Full suite **454 tests, all passed**.

## 2026-11-07 audit-rule families (CIS 6.3.3.4, 6.3.3.6, 6.3.3.8)

I read the CIS text first (pp.784–802). Each control's rules are the exact CIS remediation lines, loaded with `augenrules --load`.

- **`vm/ubuntu/family_audit.py`:** one `AuditRulesFamily`, with one file per control in `/etc/audit/rules.d/`: `60-fyp-cis-time-change.rules`, `60-fyp-cis-privileged.rules` and `60-fyp-cis-identity.rules`.
  - 6.3.3.4: b64 and b32 `adjtimex,settimeofday,clock_settime` rules plus a `/etc/localtime` watch, key `time-change`.
  - 6.3.3.8: `-w <path> -p wa -k identity` for all eight identity paths.
  - 6.3.3.6: `-a always,exit -F path=P -F perm=x -F auid>=UID_MIN -F auid!=unset -k privileged` for each binary in the scan's privileged inventory, using UID_MIN from `login.defs`. Parameters are bounded: sorted unique absolute paths, at most 512, no `.`/`..` parts; UID_MIN between 500 and 60000. The target re-checks that each path is still a setuid/setgid regular file.
- **Refused when:**
  - auditd is not installed (6.3.1.1 comes first);
  - the configuration is locked (`enabled 2`), because augenrules would silently not load;
  - another file sets `-e 2`, because a restore could then only take effect after a reboot;
  - a later file contains `-D`;
  - any rule is unparseable by the collector, such as suppressions or unknown filters.
- **State:** the managed file plus whether every rule of this change is loaded, compared semantically with the collector's parser. `auditctl -l` prints `-F key=`, `auid!=-1`, `-S all` and its own syscall order, so a byte comparison would fail. A failed load puts the previous file back.
- **Live VM:** these become possible only after auditd is installed (6.3.1.1).
- **Coverage:** 6.3.3.4, 6.3.3.6 and 6.3.3.8 are `fixture_tested`.
- **Tests:** 7 new tests in `tests/integration/test_ubuntu_audit_rules_family.py` with an in-memory auditd that prints rules the way `auditctl -l` does. One test checks that the real 6.3.3.4 predicate turns Compliant (RED: 11 errors).
  - **Mutation checks, all caught:** allowing a locked configuration, an `-e 2` file, a later `-D`, skipping the parse, skipping the inventory re-check, a syntactic loaded comparison, and unsorted paths.
  - 26 implemented families; 4 reserved IDs remain.
- Full suite **461 tests, all passed**.

## 2026-11-07 GRUB audit=1 (CIS 6.3.1.3)

I read CIS 6.3.1.3 (p.757) first: add `audit=1` to `GRUB_CMDLINE_LINUX` in `/etc/default/grub`, then `update-grub`.

- **`vm/ubuntu/family_grub.py`, `ubuntu.6.3.1.3.v1`:** the same variable is extended through Ubuntu's sourced `/etc/default/grub.d/60-fyp-hardening-cis.cfg`, with `GRUB_CMDLINE_LINUX="$GRUB_CMDLINE_LINUX audit=1"`. `/etc/default/grub` is never edited.
  - Runs as a supervised job (`update-grub` can be slow). A failed `update-grub` puts the previous drop-in back and regenerates the configuration.
- **Refused when:**
  - any GRUB source contains `audit=0`;
  - a later drop-in replaces `GRUB_CMDLINE_LINUX` without keeping `$GRUB_CMDLINE_LINUX`;
  - GRUB is not the generator, or there are no boot entries;
  - every entry already has `audit=1`;
  - the managed drop-in holds foreign content.
- **State:** the drop-in plus the `audit=` arguments of every generated boot entry, parsed exactly as the collector does. The predicate judges the generated entries, so the control complies after `update-grub`.
- **No reboot:** the running kernel audits early processes only after the next boot, which stays the administrator's decision. The approval summary says so.
- **Coverage:** 6.3.1.3 is `fixture_tested`.
- **Tests:** 4 new tests in `tests/integration/test_ubuntu_grub_family.py`, with an in-memory model of how `update-grub` sources the files; the real predicate turns Compliant (RED: 11 errors).
  - **Mutation checks, all caught:** allowing `audit=0`, a later replacing drop-in, already-compliant entries, and a missing GRUB.
  - 27 implemented families; 3 reserved IDs remain.
- Full suite **465 tests, all passed**.

## 2026-11-07 UFW loopback resolver, loopback rules (CIS 4.1.4) and UFW enable (CIS 4.1.3)

I read CIS 4.1.3 (p.429) and 4.1.4 (p.433) first. The 4.1.4 audit checks that `ufw status verbose` lists the loopback rules in order; its remediation is `ufw allow in on lo`, `allow out on lo`, `deny in from 127.0.0.0/8` and `deny in from ::1`.

- **Collector resolver (closes the pending "4.1.4 loopback resolver" item):**
  - `probes.ufw_loopback` reads ufw's ordered user-rule records from `/etc/ufw/user.rules` and `/etc/ufw/user6.rules`, which are now on the collector's read allowlist.
  - For each traffic class (loopback in, loopback out, spoofed 127.0.0.0/8 or ::1 inbound on other interfaces) it reports the action of the first rule covering the whole class. It reports `mixed` when an earlier rule covering only part of the class acts differently, and `none` when no explicit user rule covers it, which CIS's audit treats as failing.
  - Addresses are compared with `ipaddress`; routed rules are ignored; any unparseable record makes the resolution `unsupported`, never a guess.
  - The evidence schema gained the values `none` and `mixed`. 4.1.4 is now decidable instead of always Unknown.
  - **The helper bundle changed**, so the VM needs a reinstall before the next scan.
- **`UfwLoopbackFamily` (`ubuntu.4.1.4.v1`):** appends the missing CIS rules in CIS order; ufw appends, so earlier rules keep precedence.
  - Eligibility runs the same resolver on the predicted rule list and refuses when appending cannot comply. That covers an earlier deny, an earlier partial rule with another action, ufw IPv6 off while the kernel has IPv6, or nothing to do.
  - **Bug found by the tests:** a rule present for only one address family is refused. Adding the missing twin is possible, but `ufw delete` on restore would also remove the existing rule.
  - Restore deletes only the rules this change added.
- **`UfwEnableFamily` (`ubuntu.4.1.3.v1`):** `systemctl unmask`/`enable`/`start ufw.service`, then `ufw --force enable`, running only the missing steps.
  - **Never runs without an SSH (port 22) allow rule**, and is refused when ufw is not installed or nothing needs doing.
  - Restore disables the firewall again if it was inactive and returns the unit's state. `LinuxServiceIO` now also allows `ufw.service`; only auditd uses the SIGTERM stop path.
- Both are commit-confirm, 600 s.
- **Coverage:** 4.1.3 and 4.1.4 are `fixture_tested`.
- **Tests:** 6 resolver/collector tests (`test_ubuntu_ufw_loopback.py`) and 7 family tests (`test_ubuntu_ufw_enable_loopback.py`), written first (RED: 8 and 14 errors).
  - **Mutation checks, all caught:** allowing a half-present rule, skipping the resolver check, ignoring the IPv6 mismatch, enabling without an SSH rule, restore deleting pre-existing rules, and a resolver that ignores partial rules.
  - 29 implemented families; only 1.2.2.1 remains.
- Full suite **478 tests, all passed**.

## 2026-11-07 update facts and patch job (CIS 1.2.2.1, Manual); all 30 controls now have a fix family

CIS 1.2.2.1 is Manual. Its remediation is `apt update && apt upgrade`, and "site policy" decides what counts as current.

- **Collector facts (closes the pending "1.2.2.1 fresh-update check" item), all read-only:**
  - `pending_updates` counts `Inst` lines of `apt-get -s -q -o Debug::NoLocking=1 upgrade`, which never takes apt's lock;
  - `held_packages` comes from `apt-mark showhold`;
  - `reboot_required` is whether `/run/reboot-required` exists (absent means false);
  - `metadata_fresh` means the newest apt `*Release` list was fetched within **7 days**. CIS sets no threshold, so this is a site value, recorded here. It is read with `stat` only.
  - Pending updates are a confirmed failure. Nothing can make the control pass, because the human-review subcheck always remains.
  - **The helper bundle changed**, so the VM needs a reinstall before the next scan.
- **`vm/ubuntu/family_patch.py`, `ubuntu.1.2.2.1.v1`:** `apt-get update`, then `apt-get -y upgrade`, as a supervised job (1800 s).
  - A plain upgrade never removes or newly installs packages, and holds are kept. apt runs non-interactively, keeps existing configuration files (`confdef/confold`), and needrestart only lists services.
  - Refused while `dpkg --audit` reports broken packages.
  - **State:** the pending-upgrade list and the holds; after the job, nothing is pending.
  - **No automatic restore:** downgrades are not reliable. The recovery kind is `snapshot_restore`, the VirtualBox snapshot, and restore raises with that instruction. The approval summary says so, says the control stays a Manual review, and notes a possible reboot, which is never performed.
- **Host spec:** proposed only when the control is Non-Compliant (pending updates), metadata freshness was collected, and at least one update is pending.
- **Changed test:** `test_provenance` asserted that 1.2.2.1's probe was all `missing` because it had no collector. The expectation is now `partial`/`missing`/`error`; the safety assertion that it is never Compliant is unchanged.
- **Coverage:** 1.2.2.1 is `fixture_tested`. **All 30 controls now have registered fix families**; 0 reserved IDs remain.
- **Tests:** 6 new tests in `tests/integration/test_ubuntu_patch_family.py` (RED: 5 errors, 1 failure).
  - **Mutation checks, all caught:** a no-op restore, allowing broken dpkg, skipping `apt-get update`, treating a missing reboot flag as true, and a locking simulation.
- Full suite **484 tests, all passed**; baseline: no protected changes; source check passes.

## 2026-11-07 decision: SSH SCAP conflicts follow the CIS effective-value audit (closes the open SSH interpretation question)

- **Live finding (scan 2026-11-06 17:06 UTC):** 5.1.10, 5.1.19 and 5.1.21 were Unknown.
  - `sshd -T` reported `no` for HostbasedAuthentication, PermitEmptyPasswords and PermitUserEnvironment, with context resolution `complete` (no Match blocks).
  - The selected SCAP rules (`disable_host_auth`, `sshd_disable_empty_passwords`, `sshd_do_not_permit_user_env`) failed; they require an explicit configuration line.
- **CIS basis:** for all three, CIS's audit is `sshd -T | grep <option>`, with `sshd -T -C …` only when Match blocks are used (pp.529, 549, 553). CIS does not require an explicit line.
- **Decision:** user-proposed on 2026-11-07 ("Resolve the disagreement between effective SSH settings and SCAP checks, verify applicable contexts, then reassess").
  - **Rule:** for SSH controls only, when context resolution is complete and every audited `sshd -T` context complies, a failing SCAP rule becomes an `advisory` subcheck instead of a `conflict`. The new `advisory` state is neutral in `combine`; its reason names the explicit-line requirement.
  - **Unchanged:** a direct failure still wins, and non-SSH conflicts stay Unknown. Without complete, audited contexts the SCAP result stays a conflict.
- **Stored evidence:** the store verifies each envelope against its import-time snapshot.
  - A difference is accepted only when the snapshot matches the earlier rule (`ssh_effective_authority=False`) exactly. The evidence is then shown under the current rule; any other difference is still rejected.
  - All five stored live scans verify this way. The newest now reads **22 Non-Compliant, 8 Compliant, 0 Unknown, 0 Error**, so all 30 controls are decided. The earlier scans keep 2 Unknown (1.2.2.1 and 4.1.4, from before their collectors existed).
- **Note on 1.2.2.1:** it is decided only because updates are pending (Non-Compliant). It is a CIS Manual control: with no pending updates it returns to Unknown (manual review) and is never machine-Compliant.
- **Tests:** 4 new tests in `tests/integration/test_ubuntu_ssh_interpretation.py`, mirroring the live facts (RED: 3 failures, 1 error).
  - **Mutation checks:** removing the resolution guard, the audited-context guard, the earlier-rule fallback, or accepting any snapshot is caught. The guard that every direct check passed is redundant defence in depth: a direct failure is handled first, and SSH direct checks only pass or fail.
- Full suite **488 tests, all passed**; baseline: no protected changes. Restart the app to load the new rule; no helper reinstall is needed (host-side change only).

## 2026-11-07 execution acceptance: runner probe, marker scenarios and an evidence-based execution gate

The execution gate was a hard-coded "closed". It now opens only on evidence.

- **Target:**
  - `runner {"op":"probe"}` is read-only. It reports the installed helper's collector digest, every registered family's version and implementation hash, whether `systemd-run` exists, and whether `fyp-hardening-boot-rollback.service` is enabled.
  - `vm/ubuntu/family_acceptance.py` (`acceptance.marker.v1`) is a commit-confirm family (30 s job, 60 s window). Its only write is `/var/lib/fyp-hardening/acceptance/marker` in the runner's root-only state directory, and it never touches system configuration.
  - The request schema accepts the control binding `acceptance` (predicate `ubuntu.acceptance.predicate.v1`) and action IDs `acceptance.*`.
  - On the host the marker is an auxiliary action (with `recovery.restore.v1`), never a CIS family.
- **Ledger:** append-only `acceptance_runs` (scenario, runner digest, exact approved request bytes) and `acceptance_outcomes`. The first settled outcome is the only one recorded.
- **Backend:**
  - `deployment_status` is the cached probe check. It needs the helper digest equal to this application's, identical family versions and hashes for the host registry plus auxiliaries, the launcher present, and boot rollback enabled. A runner that refuses the probe counts as "not deployed".
  - `start_acceptance` previews, plans, approves with the named operator and dispatches through the normal executor and ledger. Only one run can be open at a time.
  - `acceptance_status` only checks status and settles a run as `confirmed`, `rolled_back` or `failed:<code>`.
  - `confirm_acceptance` uses the same fresh-login rule as fixes, and refuses the rollback scenario, which must be left to its timer.
- **Gate (`execution_gate(backend)`):** open only when the deployment checks pass **and** this target has a `confirm` run settled `confirmed` **and** a `rollback` run settled `rolled_back`, both recorded against the currently deployed runner digest. A reinstalled or updated helper needs new acceptance runs.
- **Tests:**
  - `test_ubuntu_acceptance_target.py` (6) and `test_ubuntu_acceptance_host.py` (7), written first (RED: 5 and 7 errors). The two registry tests now expect the marker in the target registry as an auxiliary.
  - **Mutation checks, all caught after strengthening:** ignoring the runner digest, one scenario being enough, confirming the rollback scenario, skipping the boot-rollback check, skipping the helper check, and parallel runs. Two tests first missed the digest binding and the parallel-run guard and were strengthened.
- Full suite **501 tests, all passed**. Nothing is deployed; the gate stays closed until `install-runner.sh` is approved and both scenarios pass on the VM.

## 2026-11-07 acceptance page and runner deployment stage

- **Page (`hardening/agentic_view.py`, authorized scoped edit):** a collapsible **Execution acceptance** section.
  - It shows the deployment-probe findings, or **Run confirm scenario** / **Run rollback scenario** (named operator required; one open run at a time).
  - Each run has **Check status**, which settles it in the click handler so the gate reasons above are current, plus **Confirm** for the confirm scenario only.
  - `docs/authorized-ui-changes.patch` has been regenerated against `af43fbc`.
- **Bug found by the page test:** `pending_supervised` assumed the Ubuntu store exists whenever the VM has a workflow. An acceptance run creates a workflow before any scan, so the page crashed. It now returns nothing until a store exists (backend regression test, RED then GREEN).
- **Bundle:**
  - `install-runner.sh` is a separate approved stage. It checks identity, bundle hashes, a byte-identical installed helper and `systemd-run`. It installs and enables, without starting, `fyp-hardening-boot-rollback.service`, then installs `/etc/sudoers.d/fyp-hardening-runner` (`vboxuser ALL=(root) NOPASSWD: /usr/local/libexec/fyp-hardening/runner ""`) with `visudo` validation.
  - `uninstall-runner.sh` reverses it, rule first.
  - `uninstall.sh` now also removes the runner stage, so new runner code needs a new approval. Both uninstallers refuse while `/var/lib/fyp-hardening/runner/active` exists, so a change in progress keeps the state its rollback needs.
- **Preview for approval:** `docs/RUNNER_DEPLOYMENT.md` (target facts, exact changes, what stays guarded, recovery and steps).
- **Tests:**
  - `tests/integration/test_ubuntu_acceptance_ui.py` drives both scenarios through the real page until the gate's reasons disappear. A wrong expectation about the final marker was corrected: the rollback correctly restores the marker the confirmed run left.
  - One bundle test covers the runner stage.
- Full suite **504 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt. **Nothing is deployed.** The runner stage waits for the administrator's approval.

## 2026-11-07 fix: VM clock skew broke the first live acceptance attempts

- **Live symptoms:**
  - The first **Run confirm scenario** at 17:39 UTC reached the VM and was refused `not_yet_valid`, which happens only when the VM clock is more than 5 s behind the host.
  - A later attempt failed on the host with "Before-state evidence is older than five minutes". The age check also rejects a negative age, which happens when the VM is ahead. The stored scans show the VM about 1 s ahead at those moments.
  - So the VirtualBox guest clock drifts and is corrected in jumps. No change was applied on the VM.
- **Fix:**
  - **Freshness on the host clock:** plans now record `before_state_collected_at` as the host time the preview was received (CIS fixes, restores and acceptance). The runner's re-read of the exact before-state at execution still guards against stale state.
  - **Runner tolerance:** `CLOCK_SKEW_SECONDS` is now 60, up from 5.
  - **Offset reported by the probe:** the runner probe now reports the VM's `now`. The deployment check estimates the offset at the probe's midpoint and, above **30 s**, reports "The VM clock differs from this computer by N s…" as a deployment problem that keeps the gate closed.
- **Tests:** two new acceptance tests (VM 10 s ahead and 20 s behind still run; 7 minutes is reported and blocks). The harness now always uses the simulated VM clock.
  - **Mutation checks, all caught:** going back to the 5 s skew, VM-time freshness, and no offset check.
- Full suite **506 tests, all passed**. **The runner changed:** reinstall the helper (`uninstall.sh` removes the runner stage too), then run `install-runner.sh` again.

## 2026-11-07 maintenance operations: package-list refresh and approved reboot (plan Section 9 / Task 15)

- **Target (`vm/ubuntu/family_maintenance.py`, auxiliary and never CIS families, both supervised jobs):**
  - **`maintenance.apt_refresh.v1`:** `apt-get update`.
    - **State:** a digest of the apt sources configuration plus a stamp written only after a successful update. The approval binds the exact repository configuration (changed sources make the request stale) and success is exact.
    - **Restore:** refused honestly; a refresh changes no configuration.
  - **`maintenance.reboot.v1`:** stamps the current boot ID in the runner state directory, then schedules `systemctl reboot` 60 s later through a fixed transient timer (`fyp-hardening-reboot`).
    - **After-state:** reached only when the boot ID differs from the stamp. The runner's new `awaiting_reboot` status keeps the request's lock until the VM is back on a new boot, then settles `applied / rebooted`.
    - **Restore:** refused; a reboot cannot be undone, so recovery is the snapshot or the console.
  - The request schema accepts the binding `maintenance` (predicate `ubuntu.maintenance.predicate.v1`).
- **Host:**
  - `request_auxiliary` now handles `METADATA_REFRESH` (`MetadataRefreshInput('')` binds the previewed digest; a different digest is refused) and `REBOOT`.
  - **Reboot:** `RebootInput(staged, 'now')` must name already-applied changes of the latest round; nothing else is accepted.
  - **Dispatch:** `dispatch_auxiliary` runs approved maintenance. Status and confirmation reuse the supervised-job paths, and a completed refresh or reboot is followed by a fresh verification scan.
  - **Fix set:** "Execute approved fixes" now takes CIS fixes only (`AUXILIARY_PREFIXES` excluded).
  - **Rows:** proposals show the kinds `metadata_refresh` and `reboot`; an `awaiting_reboot` result says to reconnect and check status.
- **Page:** the Fixes tab gains **Prepare package-list refresh** and **Prepare reboot to complete applied changes** (enabled only after applied fixes). Once approved, each has a confirmation checkbox and **Run approved …**, offered once.
- **Superseded test:** "reboot is unsupported" is now "a reboot naming no applied change is refused".
- **Tests:** 6 target, 4 host and 1 page test, written first.
  - **Mutation checks, all caught:** a same-boot reboot counting as done, settling without a new boot, stamping before a successful update, a reboot naming unapplied IDs, an unchecked digest, and maintenance joining the CIS execution set.
  - The acceptance harnesses now register the maintenance operations, as a real runner does.
- Full suite **517 tests, all passed**; baseline: no protected changes; UI patch regenerated; bundle rebuilt. **The runner changed:** reinstall, re-run `install-runner.sh` and repeat both acceptance scenarios before live use.

## 7 November 2026 — live execution acceptance passed (current runner)
- The administrator reinstalled the helper and runner stage built from 4b404c8 (collector digest `3df47649b229`, matching this checkout).
- Ledger acceptance records for that digest: confirm → `confirmed` (settled 03:05:56 UTC); rollback → `rolled_back` (settled 03:07:38 UTC).
- The evidence-based execution gate is therefore open for this runner version. No CIS fix has run live yet; the next step is one low-risk fix (3.3.2) with a snapshot taken first.

## 7 November 2026 — agent output budgets (live finding)
- **Live symptom:** the first agentic round on the accepted runner (03:16 UTC) stored no fix proposals; the Fixes tab showed only "Prepare package-list refresh".
- **Cause, from the stored run logs:** scanner and analysis completed (30/30 decided, 22 Non-Compliant). At the plan step, qwen3:8b returned an empty reply twice (once after the nudge); the round ended "Unavailable" with `plan: null`.
  - The Ubuntu backend shared one client with the default 384-token output limit across all roles.
  - A plan deciding the 22 failures with registered actions is about 2,450 characters, roughly 800–1,000 tokens, so the tool call was truncated.
- **Fix (host only):** per-role clients, with orchestrator 2048, analysis 768 and scanner 512 tokens; the Windows engine uses 1024/768/512. 2048 output plus a prompt of about 1,600 tokens fits the client's fixed 4,096-token context. The protected `ollama_client.py` is unchanged.
- **Tests:** 2 new tests, written first: the orchestrator budget covers a plan fixing all 30 controls, and role budgets match or exceed the Windows engine. Mutations caught: orchestrator 1024, and one shared client.
- Full suite **523 tests, all passed**; baseline: no protected changes. The collector digest is unchanged (`3df47649b229`): no reinstall, and the acceptance results still apply.

## 7 November 2026 — honest plan reasons, AI plan table and readable previews (live finding)
- **Live symptom (round 03:28 UTC):** with the output budget fixed, the plan arrived and proposed 4.1.4 and 5.1.20 (both flagged highest risk). The other 20 Non-Compliant controls were deferred as `no_registered_action`, although each had a registered, offered action. The Fixes tab showed only the two proposals, as raw JSON.
- **Changes:**
  - `submit_plan` now refuses `no_registered_action` for a control that has a registered action. The refusal names the action, so the model can correct its plan within the invalid-call limit.
  - The `delegate_analysis` result gives the orchestrator `registered_actions` (failing control → action ID) in plain form, and the tool description says when that reason applies.
  - New `PlanRow` contract field (default empty, so Windows is unaffected). The Fixes tab shows an **AI plan** table for every Non-Compliant control: decision, reason in words, analysis flag.
  - Proposal previews are readable lines with every key and value kept (`preview_text`), not raw JSON.
  - Stale wording ("no Ubuntu remediation family is implemented yet") updated.
- Operator-created fixes were deliberately not added: project decision D4 has the orchestrator choose proposals. The round goal steers it.
- **Tests:** 9 new tests, written first. One old assertion now expects readable preview text. Mutations caught: removing the honesty check, hiding `registered_actions`, listing only decided controls, and raw JSON previews.
- Full suite **532 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged (`3df47649b229`).

## 7 November 2026 — separate fix and defer lists; Ubuntu round goal disabled (live finding)
- **Live symptom (round 03:57 UTC):** the orchestrator offered fixes for all 22 failures with the right action IDs, but gave each the defer reason `no_registered_action`. The plan was refused with a generic message; the model resent the identical call; the protected Coordinator blocked the repeat, so no plan was stored.
- **Cause:** fix and defer reasons shared one `reason_code` enum in a single `decisions` list.
- **Changes:**
  - `submit_plan(fixes=[{control_id, action_id, reason_code}], defers=[{control_id, reason_code}])`. Each list carries only its own reason codes, `fixes` lists only controls that have a registered action, and both lists are optional (a failure in neither is recorded as not decided).
  - Refusals name the valid codes or the registered action. The stored plan format is unchanged, so the adapter, UI and history read old and new rounds alike.
  - **Round goal disabled for Ubuntu** at the administrator's request (due for removal): the page no longer shows the input and the backend refuses a goal. The Windows page keeps its goal for now (protected engine and original tests).
- **Tests:** 6 new tests (5 plan format, 1 backend goal refusal) plus a page assertion, written first. Existing Ubuntu tests now send plans through a `plan_call` helper in the new format; one test no longer passes a goal. Mutations caught: fix reasons accepting defer codes, a mixed enum, a control in both lists, the goal check removed, and the goal input restored.
- Full suite **538 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged.

## 7 November 2026 — complete plans and an honest fix reason; first live SSH attempt (live finding)
- **Live rounds 04:11 and 04:21 UTC:** the plan was valid but listed only 5.1.20 and 4.1.4, both flagged `highest_risk`, and left the other 20 failures out (recorded as not decided).
  - **Cause:** the only fix reasons were `high_risk` and `unblocks_other`; an ordinary confirmed failure had no true fix reason.
  - **Changes:** a new fix reason, `confirmed_failure` ("Confirmed CIS failure with a registered fix"). `submit_plan` must place every confirmed failure in `fixes` or `defers`; a refusal names the missing controls. The orchestrator prompt and tool description say so.
- **First live CIS execution, 5.1.20 (administrator-approved):** the commit-confirm job started at 04:22:32.07 (VM clock). The job then rolled itself back 0.33 s later as `rolled_back` / `nothing_to_restore`, with identical before- and after-state digests. No status call came from the host until 04:23:41, so the rollback came from the job, after `apply` failed.
  - `SshFamily.apply` puts the previous drop-in back when `sshd -t` or `systemctl reload ssh.service` fails, so nothing changed. The runner discards the exception, so the failing step needs read-only VM evidence (journal of `fyp-hardening-job-<request>`, `ssh.service` around 04:22, `sshd -t`).
  - SSH configuration is unchanged.
- **Tests:** 2 new tests, written first; older tests now send complete plans. Mutations caught: completeness check removed; the plan table listing only decided controls.
- Full suite **539 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged (`3df47649b229`).

## 7 November 2026 — target IO name collisions (root cause of the 5.1.20 rollback)
- **VM evidence (administrator, read-only):**
  - The request directory holds `job_started`, `decision` and `receipt.json`, so the job reached `apply`.
  - The job unit started and "Deactivated successfully" at 12:22:32 local (04:22:32 UTC).
  - `/etc/ssh/sshd_config.d/` is empty, with its mtime still Oct 9, so no file (not even the temporary file) was ever created there.
  - The suggested `ssh` journal window used UTC on a MYT clock, so its "No entries" carries no information.
- **Cause:** `LinuxTargetSystem` mixes every family's IO class. `LinuxAuditIO._put(name, content)` came earlier in the MRO than `LinuxSshIO._put(content)`, so `write_managed` raised TypeError before any write. The job then rolled back with `nothing_to_restore`. `LinuxSshIO.write_managed` also shadowed `LinuxSysctlSystem.write_managed`: sysctl fixes would have entered the SSH write path and failed the same way, before writing.
  - Family tests use fakes, so the real composed class was never exercised.
- **Fix:** the SSH IO methods are now `write_sshd_dropin`, `_put_sshd_dropin` and `_sshd_ok`.
- **New guards (3 tests, written first):**
  - every attribute of every IO class (methods, static methods, constants) is the one `LinuxTargetSystem` resolves;
  - the sysctl write resolves to its own IO;
  - every `self.system.<name>` a family calls exists on the real class.
  - Mutations caught: the collision reintroduced, and a misspelled system call.
- Full suite **542 tests, all passed**; baseline: no protected changes; source check passes; bundle rebuilt.
- **Helper changed (collector digest `b1b17b633dfd`):** reinstall, rerun `install-runner.sh` and repeat both acceptance scenarios before any live fix.

## 7 November 2026 — acceptance passed on runner b1b17b633dfd; failures without an action deferred by code
- **Acceptance (live, after the reinstall):** confirm → `confirmed` (04:49:02 UTC); rollback → `rolled_back` (04:49:21 UTC). The execution gate is open for collector digest `b1b17b633dfd`.
- **Live rounds 04:43 and 04:52 UTC:** the orchestrator proposed **21 correct fixes**, all with `confirmed_failure`. It left out 6.3.1.2, which has no applicable action until auditd is installed by 6.3.1.1. The completeness rule refused the plan, the identical retry was blocked, and no plan was stored.
- **Changes:**
  - The completeness rule now covers only failures that have a registered action. A failure without one that the model leaves out is recorded by code in `deferred_by_code` as `no_registered_action`: a fact, not a judgement.
  - `delegate_analysis` also returns `without_registered_action`.
  - The reason text is now "No registered fix applies in the current state", and the AI plan table shows "Deferred (by the app)".
- **Replay:** the exact rejected 04:52 arguments are accepted under the new rule (21 fixes, 6.3.1.2 deferred by code).
- **Tests:** 4 new tests plus 1 rewritten, written first. Mutations caught: requiring eligible-less failures again, and dropping the eligible check.
- Full suite **546 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged (`b1b17b633dfd`).

## 7 November 2026 — fix reason renamed to match the analysis flag (live finding)
- **Live round 04:59 UTC:** a complete plan: 21 fixes, with 6.3.1.2 deferred by the model itself. 4.1.4 and 5.1.20 carried the analysis flag code `highest_risk` where the fix reason was `high_risk`, so the plan was refused, the identical retry was blocked, and no plan was stored.
- **Changes:**
  - The fix reason is now `highest_risk` ("Among the highest deterministic risk"), the same code as the analysis flag.
  - Stored rounds that use `high_risk` still read in words (`LEGACY_FIX_REASONS`).
  - Reason-code refusals now name the control and the rejected value.
- **Replay:** the exact arguments of the 04:52 and 04:59 rounds are both accepted (21 fixes each; 6.3.1.2 deferred).
- **Tests:** 3 new tests, written first; Ubuntu tests use the new code (Windows tests untouched). Mutation caught: a refusal without the control and value.
- Full suite **549 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged (`b1b17b633dfd`).

## 7 November 2026 — first live CIS fix (3.3.2) and the Fixes tab as per-control cards
- **First live CIS fix (administrator-approved):** 3.3.2 was applied at 05:08:58 UTC (`applied` / `expected_after_state`), and the automatic verification scan at 05:09:19 read **3.3.2 Compliant** (21 Non-Compliant).
  - An approved restore was then run (applied at 05:12:20); the following verification read 3.3.2 Non-Compliant again (22). The VM is back at its before-state for 3.3.2.
  - The fix, the verification scan and the approved restore all worked live. The UI did not show the verification on the Fixes tab, so the administrator saw no change.
- **Fixes tab redesign (administrator request):**
  - One expander card per Non-Compliant control replaces the plan table. Each card title gives the current state, with an icon: awaiting decision, approved, running, *Fixed, re-scan: Compliant*, *Applied, re-scan: …*, not applied, outcome unknown, restored, rejected or deferred.
  - Inside a card: the planner decision, reason and flag; each proposal's exact preview, recovery and outcome; and that control's Approve/Reject, Prepare restore and Run restore controls.
  - A summary line counts controls, proposed, approved and fixed.
  - Maintenance proposals and the execution controls stay below the cards. Windows keeps its previous Fixes tab (no plan rows).
- **Code:** `plan_cards` / `plan_summary` / card rendering in `system/ui/components.py`; `render_snapshot_tabs` takes `fix_header` and `control_actions`.
  - The page (`hardening/agentic_view.py`, authorized scoped edit) splits `_ubuntu_fix_actions` into header, per-card actions and the rest; button keys are unchanged.
  - `docs/authorized-ui-changes.patch` has been regenerated against `af43fbc`.
- **Tests:** 5 card-state tests, page assertions in the end-to-end Fixes flow (cards, buttons inside the card, states after execute and restore) and a card test replacing the table test, written first.
  - Mutations caught: the restore state removed, re-scan status ignored, and the cards rendered without actions.
- Full suite **554 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged (`b1b17b633dfd`). Not yet viewed in the real app.

## 7 November 2026 — plan refusals fit the Coordinator's error limit (live finding)
- **After 3.3.2 was fixed (re-scan Compliant):** the rounds at 06:40 and 06:42 UTC stored no plan ("Invalid calls blocked").
  - Both times the orchestrator first submitted only the two flagged fixes. The refusal listed all 18 undecided controls, but the protected Coordinator passes only the first 200 characters of a tool error to the model, so the list was cut after 6.3.1.3.
  - The model then fixed the 15 controls it could see and was refused again for 6.3.3.4, 6.3.3.6 and 6.3.3.8. Its third attempt deferred them as `no_registered_action` (refused, since they have registered actions), and the round stopped after 3 invalid calls.
  - The earlier 06:36 round succeeded only because the model's first plan was already complete.
- **Change (`backends/ubuntu/agents.py`):** the undecided-controls refusal is now compact (`Undecided, add each to fixes or defers: …`) and always fits 200 characters. When every name cannot fit, it says `+N more (every key of registered_actions)`. The live case now fits in 168 characters with all 18 controls.
- **Tests:** 3 new tests (`test_ubuntu_plan_errors`), written first: the live partial plan, the worst case (all 30 controls) and every other plan refusal stay within the limit. The first two failed before the change (225 and 319 characters).
- Full suite **557 tests, all passed**; baseline: no protected changes. Host only: collector digest unchanged (`b1b17b633dfd`).
