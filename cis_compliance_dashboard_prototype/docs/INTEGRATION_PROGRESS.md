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
