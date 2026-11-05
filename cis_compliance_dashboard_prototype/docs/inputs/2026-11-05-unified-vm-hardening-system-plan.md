# Unified Windows and Ubuntu VM Hardening System — Implementation Plan

> **For agentic workers:** After user review, use `superpowers:executing-plans` for task-by-task implementation. Use `superpowers:subagent-driven-development` only if that approach is selected or applicable instructions authorise it. Checkboxes track implementation; writing this plan does not authorise live VM changes.

**Goal:** Extend the teammate's completed interface into one system whose existing VM connection form can connect to a supported Windows or Ubuntu VM, verify its platform, and invoke the appropriate hardening functions through the same UI.

**Architecture:** Extend the teammate's existing Streamlit application in its current project, retaining its existing `cis_compliance_dashboard_prototype/app.py` entry point and pages. Add one connection/detection/router layer and two internal backends. WindowsBackend delegates to the existing Windows services in the same application; UbuntuBackend implements Teoh's Linux assessment, risk inputs, all 30 remediation families and verification. Platform modules and partitioned storage are internal implementation details.

**Tech stack:** Python/Streamlit on Windows; existing pypsrp/PowerShell for Windows; Paramiko SSH and fixed Python/Linux tools for Ubuntu; SQLite; local Ollama `qwen3:8b`; pinned OpenSCAP/ComplianceAsCode for Ubuntu assessment.

**Spec:** [Active one-system design](../specs/2026-11-05-unified-vm-hardening-system-design.md).

**Control specification:** [Active 30-control assessment/remediation catalogue](../specs/2026-11-05-unified-system-ubuntu-control-catalogue.md).

**Version/status:** Version 3, 5 November 2026, updated for the user's existing-application workflow. This supersedes version 2's separate development application/source-copy arrangement and `2026-11-05-ubuntu-rebuild-integration-plan.md`. The filenames remain stable. This document plans development; it does not report implemented functionality or authorise live VM changes.

## Global constraints

- One delivered application, one launch command, one browser interface. Extend the teammate's existing UI and its Agentic hardening connection form.
- No separate Ubuntu dashboard, OS-selection landing page, second Streamlit service or iframe integration.
- Develop on `integrate/unified-vm-hardening` in the teammate's project and retain its existing `app.py`. Controlled integration edits to that entry point and existing presentation files are authorised; preserve their Windows behaviour. Keep Windows assessment/scoring/execution/storage engine files and scripts unchanged, retain tests, and isolate dependencies/runtime data from existing environments/databases. See Section 3's edit boundary.
- Preserve the old Ubuntu mock-up as historical reference; it is not the UI foundation.
- Reuse the existing Ubuntu VM if inspection confirms compatibility; no automatic reinstall/reset. Require recoverable test states before changes.
- Ubuntu Server 22.04 LTS; CIS Ubuntu 22.04 v2.0.0; 30 selected assessments and 30 implemented control-remediation families.
- Follow the teammate's exact status terminology, score formula, bands, factor-rubric derivation and drift method. LLMs cannot change those results.
- Detect protocol only at the supplied endpoint; verify OS/identity through authenticated read-only probes before backend routing.
- No arbitrary shell/model-generated commands, credential logging, automatic human approval, or blind retry after a possible write.
- Reports are revised later; implementation maintains a report-change log only.

## Review focus

1. **Wrong backend:** SSH can exist on non-Ubuntu hosts; an IP/port or HTTP response must not classify the OS. Tasks 2–4 test routing and identity.
2. **Lost Windows behaviour during UI reuse:** per-request/bulk decisions, execution confirmation, goals and resumed rounds must survive adaptation. Tasks 0, 1, 4 and 17 test this.
3. **Cross-target authority:** changing form fields, switching VM, restoring snapshots or colliding proposal IDs must not reuse another target's approval. Tasks 3, 7, 10 and 16 test this.
4. **Uncertain remote writes:** lost receipts, dashboard crash, watchdog expiry and package/reboot continuation must not trigger replay. Tasks 10–15 and 17 test this.
5. **False compliance/risk:** partial compound results, manual reviews and platform-specific exposure must not invent a pass or factor. Tasks 5–9 and 16 test this.

## 1. Read this first: the intended user experience

The user's intended workflow is the product acceptance scenario:

1. Launch the teammate's existing `cis_compliance_dashboard_prototype/app.py` and go to **Agentic hardening**, as in the current system. After integration, this same entry point supports both platforms.
2. Enter VM hostname, machine identity, IP/host, port, username and password in the same form. Ubuntu key authentication is an optional advanced choice.
3. Click **Connect and check identity**.
4. The system identifies the supported transport, establishes trust/authentication and reads actual OS/identity facts. It does not use the LLM for detection.
5. If it verifies Ubuntu 22.04, it attaches **UbuntuBackend**, which invokes Teoh's Ubuntu functions. If it verifies the supported Windows Server 2022 target through WinRM, it attaches **WindowsBackend**, which invokes the teammate's existing functions.
6. The same page shows the connected VM and detected OS. The user starts a round; the correct catalogue and tools run.
7. Findings appear in the same **Fixes, Risk ranking, Controls, Results, Agent log** tabs.
8. The user reviews, approves/rejects and confirms execution using the same workflow. Verified results and history appear in the same system.

Example addresses/ports in documentation are examples only. The real VM endpoint and machine identity must be collected; the plan does not assume port forwarding exists.

### Short glossary

| Term | Meaning here |
|---|---|
| UI / presentation | Existing pages, forms, tables, buttons, messages and charts |
| Backend | Platform-specific implementation that performs assessment and controlled remediation |
| Adapter | Thin translation layer making an existing implementation satisfy the shared interface |
| Transport | Connection technology: WinRM or SSH |
| Router | Deterministic code selecting a backend after verified OS/identity checks |
| Catalogue | Reviewed control definitions, benchmark mappings, predicates and action links |
| Common presentation record | Data format both backends return so the same UI can display either platform |

## 2. What was inspected and what will be reused

The inspected Windows root is `C:\Users\teohk\OneDrive\Desktop\FYP_App-main\window_cis_compliance_dashboard_prototype`; its Python app is nested in `cis_compliance_dashboard_prototype`.

| Existing file/component | Verified role | Integration treatment |
|---|---|---|
| `app.py` | Navigation, status sidebar, CSS and page wiring | Modify the existing entry point to wire shared connections/backends; retain its title/layout/navigation |
| `hardening/connection_view.py` | Current six-field Windows connection flow and identity check | Extend this same form to call shared detection/identity services |
| `hardening/agentic_view.py` | Five tabs; six workflow steps; approval, comments, confirmation, history/resume | Adapt this existing view to shared records and typed commands; preserve all Windows behaviours |
| `hardening/overview_view.py`, `history_view.py`, `ui.py` | Summary, history, charts and common formatting | Make scoped platform-aware presentation edits only where required; retain reusable formatting |
| `hardening/agentic.py` | Windows orchestration and execution rounds | Invoke unchanged from WindowsBackend; do not pass Ubuntu targets into it |
| `hardening/winrm_channel.py` | `WinRmTarget`, `LiveScanner`, fixed PowerShell channel | Retain unchanged for Windows |
| `hardening/domain.py`, `risk.py` | Statuses, weighted score, factors, history comparison | Reuse platform-neutral rules; map Ubuntu attributes/evidence explicitly |
| `hardening/import_storage.py`, `framework.py`, `remediation.py` | Strict evidence and durable workflow/approval stores | Retain for Windows; implement versioned Ubuntu counterparts |
| Windows scripts | Registered collection, remediation and independent checks | Do not edit or rename |

Windows services are not presently generic: `windows:` target prefixes, Windows control imports, schema checks, prompts and field names occur in several modules. Merely accepting Ubuntu values in the old form would not make them work. The adapter boundary is therefore a required implementation, not a cosmetic change.

Earlier inspection described the Ubuntu prototype as a visual simulation; re-inspect its current state before reusing anything. It is historical/reference work, not the entry point or UI foundation for this integration. Never reuse simulated execution results or sample scores as production logic. The teammate's reported 178 fixture tests are historical documentation; establish the actual baseline count in Task 0. Verify repository access and current changes before branching without resetting existing work.

## 3. Directory, source preservation and team ownership

Develop inside the teammate's existing project: `C:\Users\teohk\OneDrive\Desktop\FYP_App-main\window_cis_compliance_dashboard_prototype`. Its application directory is `cis_compliance_dashboard_prototype`; continue launching that directory's existing `app.py`. Add the shared services and Ubuntu backend alongside the existing `hardening/` package. Do not create another application root or import a duplicated Windows source tree at runtime.

Inspect Git state and compare the Desktop project with any parent-GitHub copy to establish provenance; do not silently switch to a different copy or overwrite either. Use the existing repository's development branch `integrate/unified-vm-hardening`, preserving unrelated work. If the chosen folder is not under Git, record that fact and preserve a verified source-only archive before edits; establish version control without discarding files. A worktree is optional when needed for isolation, but must contain the same project layout and same entry point, not a new product. These planning documents currently live in the Ubuntu workspace; that does not make it the implementation root. Supply them to the agent operating in the teammate's project.

```text
window_cis_compliance_dashboard_prototype/   existing teammate project
  scripts/                             existing Windows scripts, unchanged
  .venv-integration/                   new isolated development environment
  cis_compliance_dashboard_prototype/   existing application directory
    app.py                             EXISTING entry point, integration edits
    hardening/                         existing Windows package
      connection_view.py, agentic_view.py, overview_view.py, history_view.py, ui.py
                                       existing views, scoped integration edits
      agentic.py, winrm_channel.py, domain.py, risk.py, import_storage.py, ...
                                       protected existing Windows engine
    requirements.txt                   existing requirements retained
    requirements.integration.in, requirements.integration.lock.txt
    README.md                          extend existing launch/setup documentation
    baseline_manifest.json             pre-change hashes and edit boundary
    system/
      contracts.py                     records/enums and WorkspaceBackend protocol
      config.py                        validated budgets, source locks, data paths
      bootstrap.py                     validates source import origins
      connection.py                    connect/detect/verify lifecycle
      discovery.py                     credential-free endpoint discovery
      identity.py                      OS/identity validation and registration
      router.py                        verified backend selection
      session.py                       one active target; secret/session cleanup
      history.py                       read-only facade across platform stores
      ui/                              shared helpers used by EXISTING views
        components.py
        fixes.py, risk.py, controls.py, results.py, agent_log.py
    backends/
      windows/adapter.py               delegates to existing hardening/ services
      ubuntu/
        adapter.py, contracts.py, ssh_channel.py
        catalogue.py, collector_client.py, scap.py, evidence.py, predicates.py
        storage.py, history.py, risk.py, workflow.py
        agents.py, prompts.py, tools.py
        actions.py, approvals.py, executor.py, jobs.py, recovery.py
    catalogues/
      ubuntu2204-cis2-selected30-v1.json
      ubuntu2204-risk-attributes-v1.json
      ubuntu2204-actions-v1.json
      source-lock.json
    vm/ubuntu/
      provision.md, collector.py, probes.py
      runner.py, ledger.py, file_transaction.py, connectivity_guard.py
      actions/
        packages.py, sysctl.py, services.py, coredumps.py
        passwords.py, sudo.py, sshd.py, ufw.py, audit.py, boot.py
    tests/                             existing tests remain here, unchanged
      integration/                     new discoverable test package
        test_baseline.py, test_contracts.py, test_discovery.py, test_routing.py
        test_identity.py, test_ssh.py, test_windows_adapter.py, test_shared_ui.py
        test_catalogue.py, test_evidence.py, test_scap.py, test_predicates.py
        test_storage.py, test_history.py, test_risk.py, test_agents.py
        test_approvals.py, test_runner.py, test_recovery.py
        test_packages.py, test_sysctl_services.py, test_password_sudo.py
        test_sshd.py, test_ufw.py, test_audit_boot.py
        test_system_acceptance.py, fixtures/
    tools/
      baseline.py, doctor.py, check_sources.py, backup.py
      consistency_check.py, independent_audit.py, evaluate.py
    docs/
      BASELINE.md, INTERFACES.md, VM_SETUP.md, RISK_DERIVATION.md
      OPERATIONS.md, RECOVERY.md, EVALUATION.md, REPORT_CHANGELOG.md
    data/windows/, data/ubuntu/         ignored, isolated platform runtime storage
    data/integration.sqlite3           shared operation/session coordination ledger
    artifacts/                         ignored evidence and test outputs
```

The tree's `system/`, `backends/`, `catalogues/`, `vm/`, `tests/`, `tools/`, `docs/`, `data/` and `artifacts/` are inside the existing application directory; the detailed module lists above are additive. All subsequent application-relative paths refer to that directory. New named test files belong under `tests/integration/` (with discovery-compatible package setup), while existing tests remain at their original paths. Inspect name collisions before creating any file; never replace an existing module merely because a proposed new filename matches.

Create `.venv-integration` at the teammate project root; do not change existing virtual environments. Keep Windows modules and scripts at their existing paths so `Path(__file__)` lookups remain valid. Record a pre-change Git commit/reference plus source hashes; preserve uncommitted source in a verified source-only archive if necessary. Archives are recovery/reference artifacts outside the runtime import path, not a vendored Windows dependency. Exclude environments, credentials, live databases and caches; preserve attribution. Back up live data separately only through its consistent backup procedure.

**Authorised edit boundary:**

| Category | Allowed treatment and verification |
|---|---|
| Existing `app.py`; `hardening/connection_view.py`, `agentic_view.py`, `overview_view.py`, `history_view.py`, `ui.py` | Scoped connection, routing, service injection, common-record rendering and label edits. Keep navigation, Windows controls and approval semantics; record every changed file/reason and verify its diff and regression tests. These files are not expected to retain pre-change hashes. |
| Existing Windows engine, catalogue, risk/domain rules, WinRM channel, storage decoders, agents and PowerShell scripts | Call through the new adapter; no deletion, renaming or logic rewrite. Hashes must match the recorded baseline. An engine change needs a concrete justification and separate review before implementation. |
| Existing tests, environments and databases | Retain test coverage and expected behavior; never weaken tests to hide regressions. Run with isolated environment and explicit new data paths. Do not overwrite existing live data or install into an existing environment. |
| New shared/Ubuntu modules, integration tests, dependency overlay, README/docs and ignore rules | Add in the existing project; review collisions and security-sensitive paths. Document additive metadata edits. |

The source verifier must distinguish protected files from authorised integration-edit files and additions. A protected-file change fails the gate; an authorised view edit requires a reviewed diff and behavioral evidence rather than blanket hash equality. No application file is deleted and no Windows feature is removed. Extending the existing UI is authorised by the user; it does not require a second permission request for every routine view edit.

Set explicit isolated development database paths before constructing any service. The existing entry point must not accidentally open its previous live databases because an old default or environment variable remains. Runtime imports of `hardening` must resolve to this project's existing package, not another checkout, an archive or the Ubuntu prototype.

Teoh owns `backends/ubuntu`, `vm/ubuntu` and the Ubuntu catalogues inside the existing application. Existing Windows logic stays under the teammate's ownership. Scoped edits to `app.py`/existing views, shared contracts, detection and integration tests are team integration work; review interfaces together before parallel implementation. Nobody needs to rewrite the other platform's tools to satisfy the contract.

## 4. Connection algorithm and identity rules

### 4.1 Form and state transitions

Keep the current form's position/layout. Rename `VM machine UUID` to `VM machine identity`, `WinRM host` to `VM IP address / host`, and `Administrator account` to `Username`. Add help explaining Windows UUID versus Ubuntu machine ID. All six familiar inputs remain. New profiles have neutral defaults; saved Windows settings remain valid. Password is masked and session-only. Advanced settings expose connection method Auto/SSH/WinRM, selected SSH key, optional sudo credential and trust information.

Connection states are:

```text
disconnected -> discovering -> trust_required (SSH first use, if needed)
             -> authenticating -> verifying_identity -> checking_capabilities
             -> connected
Any failure -> disconnected with a classified, sanitized diagnostic
```

No partially completed state enables Scan or Execute. A connected session has an opaque backend handle created only by the connection service. Changing address, port, hostname, identity or credentials invalidates that handle; switching target is blocked during a pending remote mutation/recovery. Refresh restores durable round history but requires credential re-entry/reconnection for further remote activity.

Use two distinct session identifiers. `connection_session_id` is ephemeral, owns credentials/channel state and ends on disconnect/refresh. `workflow_session_id` is durable and binds platform, target ID, registration epoch and the backend's existing session ID. On reconnect, verified identity must match that binding before the user can resume it; otherwise only read-only history is available. Do not pass the new connection ID to the Windows workflow engine. `start_round` can create a new workflow explicitly; merely reconnecting must not create another round or resume execution. Show the existing resume/new-round choice and reconcile outstanding operations first.

### 4.2 Endpoint discovery

`discover_transport` inspects only the submitted host/port, without credentials. Begin with a bounded SSH banner/protocol check; if it is not recognized, perform a bounded WinRM `/wsman` identity/protocol probe on a new connection to the same endpoint. Recognize WS-Man identity/protocol evidence where available; an authentication challenge alone is at most a candidate, never proof of Windows. Do not follow redirects or scan additional ports. Total initial discovery budget is ten seconds with capped response bytes; authentication/identity have separate budgets. Probe parsing must be unit-tested against delayed/malformed responses.

Saved verified connection profiles can reuse the known transport; OS/identity is still checked on every new connection. Auto discovery is a convenience, not a guarantee for every proxy/TLS configuration. If not conclusive, stop and offer the manual transport override inside Advanced settings. Never try submitted credentials on both protocols. Preserve the existing Windows NTLM/message-encryption channel. Initial transport support must match what that adapter actually supports; HTTPS-only or unusual configurations remain explicit unsupported/override cases until implemented and verified. Do not downgrade a TLS configuration to plaintext automatically.

### 4.3 Authentication, OS and registration

For SSH, verify the public server key before login against known trust or an independently acquired console fingerprint. Unknown keys require confirmation in the same form; changed keys require re-enrolment. Use only the chosen password/key method; disable implicit SSH-agent/key searching. The code must not treat credentials as portable between protocols. [Paramiko client documentation](https://docs.paramiko.org/en/stable/api/client.html).

After authentication, run a fixed read-only identity probe. On SSH, parse OS-release as data, never `source`/execute its contents; verify `ID=ubuntu` and `VERSION_ID=22.04`, hostname and machine ID. On WinRM, retain the original Server 2022 build/standalone/UUID checks. Validate the expected machine-identity field according to the detected platform: Ubuntu 32-hex machine ID and Windows UUID are not interchangeable. Registration also binds Ubuntu host key, optional DMI UUID and an inventory UUID. Reuse the original Windows target IDs unchanged; Ubuntu target IDs are `ubuntu:<inventory_uuid>`.

Routing is deterministic:

| Authenticated facts | Result |
|---|---|
| Supported Server 2022 identity + original WinRM channel | WindowsBackend |
| Ubuntu 22.04 identity + trusted SSH channel | UbuntuBackend |
| SSH to Windows, Debian, Ubuntu 24.04 or unknown OS | Unsupported combination; no Ubuntu tools |
| Expected identity mismatch, changed key or invalid facts | Refuse; no backend capable of hardening |
| Missing Ubuntu collector/sudo capability | Show specific setup/capability result; never silently install prerequisites |

For a new registered VM, bind verified facts to the entered expectations and persist only public registration data. Host-side inventory/epoch is authoritative. Snapshot restore requires an explicit restore/re-enrolment operation; refuse unexplained ledger regression. Undisclosed restores cannot always be detected from unchanged machine IDs/keys. Existing VM reuse is default, with a pre-change snapshot and console access. Clones must be registered separately and checked for duplicated identities/keys.

## 5. Shared application interfaces

### 5.1 Core records

Use immutable dataclasses/enums with strict serializers. Field names below are the contract, not optional examples. Optional values have explicit `None` semantics. UTC timestamps include timezone. Tuples represent immutable sequences. Each mutable command revalidates the record's platform, target and session against server-held state.

| Record | Required fields |
|---|---|
| `Endpoint` | `host: str`, `port: int`, `method: auto|ssh|winrm` |
| `ConnectionRequest` | endpoint, `expected_hostname`, `expected_machine_identity`, `credential_ref` (opaque in-memory reference), optional `saved_profile_id` |
| `ConnectionResult` | `state`, optional `connection_session_id`, `detected_platform`, `os_version`, `transport`, `target_id`, `capabilities`, `diagnostic_code`, safe `detail` |
| `WorkflowBinding` | `workflow_session_id`, `platform`, `target_id`, `registration_epoch`, `backend_session_id`, `created_at` |
| `Capabilities` | `can_assess`, `can_remediate`, `can_use_model`, `requires_setup`, `blocked_reasons` |
| `RecordRef` | `platform`, `target_id`, `record_id` (original backend ID) |
| `TargetSummary` | target reference, hostname, OS/release, transport, evidence mode, active connection state |
| `AssessmentSummary` | assessment reference, selected/compliant/non_compliant/unknown/error counts, coverage percent, compliance percent or None, catalogue ID, collected_at |
| `ControlRow` | control ID/title/area/profile/source, status, applicability, observed display value, expected display value, subchecks, evidence references |
| `FindingRow` | control ID, I/E/P/L/D, score, level, derivation reasons, risk-policy version, rank, history reference |
| `ProposalRow` | proposal reference, kind (`control_remediation`, `metadata_refresh`, `reboot`, `recovery`), optional control ID, action ID/title/version, exact preview, impacts, recovery, dependencies, decision/expiry, reason, eligible commands |
| `ResultRow` | proposal reference, execution state, verification status, receipt reference, verification assessment reference, recovery state, safe detail |
| `AgentEvent` | run/role, event kind, tool name, safe arguments/result summary, reason code, timestamp, evidence/model provenance |
| `WorkspaceSnapshot` | target, workflow binding, current round reference, summary, controls, findings, proposals, results, events, six step states, goal/read-as, available commands, revision |
| `HistoryRow` | run reference, target, time, catalogue, counts, evidence mode, round kind, compatible prior reference |

Do not normalize away platform-specific detail: `ControlRow.subchecks` can show a registry observation or Linux account list without changing the common status field. Frontend strings are escaped; metadata cannot become HTML or executable content. No secrets are permitted in these records.

### 5.2 Service methods

```python
# system/connection.py and router.py
connect(request: ConnectionRequest) -> ConnectionResult
disconnect(connection_session_id: str) -> None
backend_for(connection_session_id: str) -> WorkspaceBackend  # verified binding only
resume_workflow(connection_session_id: str, workflow_session_id: str) -> WorkflowBinding

# system/contracts.py: implemented by WindowsBackend and UbuntuBackend
capabilities(connection_session_id: str) -> Capabilities
snapshot(connection_session_id: str, workflow_session_id: str,
         round_ref: RecordRef | None = None) -> WorkspaceSnapshot
start_round(connection_session_id: str, workflow_session_id: str | None,
            goal: str | None, mode: AssessmentMode, operation_id: str) -> RoundHandle
decide(connection_session_id: str, workflow_session_id: str,
       proposal_ref: RecordRef, approved: bool,
       operator: str, comment: str, operation_id: str) -> DecisionResult
execute_approved(connection_session_id: str, workflow_session_id: str,
                 round_ref: RecordRef, expected_approved_request_ids: tuple[str, ...],
                 deterministic: bool, operation_id: str) -> ExecutionHandle
history(target_id: str | None, limit: int) -> tuple[HistoryRow, ...]
compare(before: RecordRef, after: RecordRef) -> ComparisonResult
operation_state(operation_id: str) -> OperationState
request_auxiliary(connection_session_id: str, workflow_session_id: str,
                  kind: AuxiliaryKind, basis: RecordRef | None,
                  inputs: AuxiliaryInput, operation_id: str) -> RecordRef
dispatch_auxiliary(connection_session_id: str, workflow_session_id: str,
                   proposal_ref: RecordRef, operation_id: str) -> ExecutionHandle
record_manual_review(connection_session_id: str, workflow_session_id: str,
                     review: ManualReviewInput, operation_id: str) -> RecordRef
cancel_operation(connection_session_id: str, workflow_session_id: str,
                 subject_operation_id: str, operator: str,
                 operation_id: str) -> OperationState
reconcile_operation(connection_session_id: str,
                    subject_operation_id: str) -> OperationState
```

`RoundHandle`/`ExecutionHandle` identify operation ID, durable workflow binding, backend round refs and state. `DecisionResult` identifies the decision and any existing matching decision; a repeated matching operation returns that result, a conflicting one refuses. `OperationState` is queued/running/cancel_requested/completed/refused/unresolved with result references. `ComparisonResult` contains comparable flag/reason and per-control changes. `AssessmentMode` is `agentic` or `deterministic`. These wrapper records do not modify Windows payload schemas.

`AuxiliaryKind` is metadata_refresh/reboot/recovery. `AuxiliaryInput` is a closed tagged union: metadata refresh binds repository-configuration digest; reboot binds completed staged-request IDs and maintenance window; recovery binds the original request/backup manifest and exact restoration choice. The backend fills these values from validated current facts and exposes an exact preview; inputs cannot contain arbitrary commands or paths. A missing basis is allowed only for pre-assessment metadata refresh on a verified registered target. These operations are proposed by `request_auxiliary`, approved/rejected through the same `decide` API, and dispatched only through `dispatch_auxiliary`. They appear in the existing Fixes/Results tabs but do not count toward CIS-family totals. WindowsBackend reports unsupported for these new Ubuntu-only operation kinds; no successful no-op.

`ManualReviewInput` contains assessment/control refs, bound evidence/package-index digests, policy version, reviewer, decision and reason. The backend validates facts and timestamps, then appends the review event specified in Section 6. It is not a config-change approval. Cancellation records a request to stop future steps; an already dispatched write remains running/unresolved until a receipt or reconciliation establishes its outcome. Reconciliation reads target/host state and updates coordination records, never dispatches another forward write; any restoration needs the separately approved recovery operation.

The frontend reads snapshots and issues these commands. It never sends raw target credentials into an agent or edits store rows, nor calls Ubuntu-private services for maintenance/manual review. Old rounds are read-only. Bulk approval resolves an exact displayed set of ProposalRefs, records an individual decision for each and reports partial failure; it cannot silently approve proposals added after the preview. Ubuntu high-impact prerequisites must be satisfied before its batch members are eligible. Windows bulk semantics remain as in the baseline. Execution confirmation binds `expected_approved_request_ids` to the currently approved pending set in the selected latest round; mismatches refuse and refresh the preview. Per-workflow command serialization prevents a concurrent decision changing that set during dispatch.

### 5.3 Windows adapter mapping

Construct the same services as the current `_services()` factory: `ImportedEvidenceStore(path)`, `AssessmentRuns(imports)`, `RemediationStore(agentic_path, imports)`, `LiveScanner(runtime, target)`, `AgenticHardening(runtime, store, scanner)`. Use explicit new data paths and the verified original `WinRmTarget`; no global environment switching.

| Shared operation | Existing Windows implementation |
|---|---|
| `start_round`, agentic mode | `AgenticHardening.run_round(binding.backend_session_id, goal=goal)` |
| `start_round`, deterministic mode | Original `LiveScanner.request` and deterministic risk/history services; persist an explicitly non-agentic assessment round through original storage APIs |
| `decide` | `RemediationStore.decide(proposal_id, approve=..., operator=..., comment=...)` |
| `execute_approved` | Confirm selected round is the latest in the durable binding, then `AgenticHardening.execute_approved(binding.backend_session_id, deterministic=...)` |
| Snapshot/round analysis | Existing store round/proposal records and `round_analysis`/`round_report` helpers |
| History/comparison | `HistoryService.runs`, `previous_records`, `compare`, drift records |
| Agent log | `AgenticHardening.traces` |

The adapter checks references and maps outputs, but does not recompute Windows risk or recreate its approvals. Preserve schema 2 approved bytes and collector schema acceptance. Guard duplicate UI dispatch using the separate atomic integration ledger in Section 6 plus original proposal/receipt states; after a crash do not call `execute_approved` again automatically. Report unresolved dispatch until reconciled. Shared dispatch intents live in the integration ledger, not invented Windows workflow rows. Add backend round records only through existing APIs and validate their shape against the original readers. Do not alter existing Windows tables/triggers or overwrite records.

### 5.4 UI adaptation

Modify the existing `cis_compliance_dashboard_prototype/app.py` to wire the connection service and verified backend into the existing views while retaining its title/navigation/sidebar/CSS. Modify `hardening/connection_view.py` in place to retain the same form; adapt the existing agentic/overview/history views to accept common records and issue typed backend commands. Move Windows service construction into the new Windows adapter and replace presentation-only hardcoded `LIBRARY` access with backend data. Keep Windows engine modules unchanged. New `system/ui/` helpers support these same views rather than duplicate whole pages. Review authorised UI diffs and protected-engine hashes separately. Do not embed the entry point inside another app, monkey-patch functions, or maintain parallel Windows/Ubuntu page implementations.

Platform counts come from the backend. Windows keeps its existing 32-control catalogue and action set; Ubuntu uses 30. Connection status and the current target's catalogue are always visible. The same History page may list both platforms, but selecting a row uses its RecordRef and platform-specific reader. Cross-platform drift comparison is refused with an explanation.

## 6. Ubuntu evidence and storage

The Ubuntu collector is a registered read-only tool over SSH. Provision fixed root-owned helpers separately; the scan never installs packages, refreshes repositories, reloads services or repairs prerequisites. Assessment artifacts may be written to an approved temporary directory. VM helpers support Ubuntu's Python 3.10; host Python is separately pinned.

Use namespace `ubuntu-cis`, schema 1, collector `ubuntu2204-readonly-v1`, catalogue `ubuntu2204-cis2-selected30-v1`. Envelope fields include target/epoch, request ID, benchmark/source-lock hash, timestamps, evidence mode, observations, effective context and artifact digests. Observations include control/probe ID, typed value, state, source and safe error. Export sanitized account aging facts, not shadow hashes; sanitize SCAP/OVAL results on the VM before host storage. Preserve exact sanitized bytes and transformation metadata.

Reject duplicate JSON keys/observations, wrong identity/catalogue/hash/version, invalid types/NaN, impossible timestamps and forged statuses/scores. Limits initially: JSON envelope 10 MiB, one observation 256 KiB, SCAP artifact 100 MiB. Oversize/truncated evidence is an explicit error. XML parsing forbids DTD/external entities and remote resource resolution.

OpenSCAP/ComplianceAsCode is the primary automated source where pinned rules match the benchmark. Resolve one-to-many CIS-to-XCCDF mappings and variables from a specific release/commit/datastream hash. Use reviewed direct probes for gaps/effective state; optional Lynis is supplemental, never a substitute risk/compliance score. No whole-profile automatic remediation. Fixed Ubuntu actions over SSH are the initial executor; Ansible is not a prerequisite. If later required academically, a separately reviewed adapter must satisfy the same approvals and ledger, not add an uncontrolled second execution path.

`Compliant` requires all applicable required subchecks to pass. A known failing subcheck can establish `Non-Compliant`; otherwise collection failure produces `Error`, missing/inconclusive evidence `Unknown`. Conflicting authoritative evidence for one subcheck is `Unknown` with a conflict reason. Keep not-applicable detail separate; it is not a pass. SCAP pass/fail are raw subcheck results, not a direct whole-control conclusion. Unknown/notchecked/notselected are unresolved; notapplicable requires applicability evidence; fixed/informational results do not prove a fresh pass.

Display compliance `C/(C+NC)` and coverage `(C+NC)/selected` together. For Ubuntu selected=30; Windows keeps its own value. Zero determinate findings gives unavailable compliance, not 100%.

Storage uses three files per platform:

| File purpose | Tables |
|---|---|
| Evidence/imports | `imported_assessments` |
| Framework | `framework_runs`, `framework_tasks` (legacy, no new tasks written) |
| Agentic workflow | `agentic_rounds`, `investigation_runs`, `investigation_events`, `rem_proposals`, `rem_decisions`, `rem_comments`, `rem_receipts`, `drift_records` |

Ubuntu payloads are versioned independently; SQL table purposes/columns follow the teammate's structure. Windows keeps strict original decoders. RecordRef prevents ID collisions in the common UI without changing legacy IDs. Use parameterized SQL, append-only triggers, raw-byte hashes and read-time validation/reassessment. Three files are not one atomic transaction: persist evidence first, recover using idempotent request IDs, validate logical links and report orphan records rather than invent completed rounds. Backup a quiesced consistent set, registry and artifact manifest; verify SQLite integrity and application links after restore. Secrets are never included.

### Shared coordination ledger

Use a separate `data/integration.sqlite3` owned by the common system. Thus the initial system has six platform data files plus one coordination file; the existing three-file/11-table Windows contract is unchanged. This is an implementation partition within one application, not a second framework. Define these new tables:

| Table | Keys and purpose |
|---|---|
| `workflow_bindings` | workflow_session_id primary key; immutable platform/target/epoch/backend_session_id/created_at mapping |
| `operation_claims` | operation_id primary key; unique dispatch_key, canonical command SHA-256, workflow/target/epoch, command kind, coordination state, timestamps and safe result refs |
| `operation_events` | sequence primary key; operation ID, time, event kind and safe payload; append-only audit of every transition |
| `target_owners` | platform-qualified target/epoch primary key; owning operation/workflow, lock generation and coordination state |

Before dispatch, one SQLite `BEGIN IMMEDIATE` transaction validates the durable workflow binding, inserts the unique operation claim, claims the target owner for a mutation and appends the intent event. The same operation ID with different command bytes is rejected; matching replay returns its recorded state/result. `dispatch_key` for execution is derived from platform/target/epoch, command kind, workflow/round and the exact approved request IDs/digests, so another tab using a new operation ID cannot dispatch the same approved work again. For intentional new read-only rounds, allocate a fresh explicit user-intent key; retain it across reruns. Serialize decisions/execution within a workflow and revalidate the approved set before calling the backend.

Only the claim owner may dispatch. Update mutable coordination rows with checked state transitions and append their audit events in the same transaction; immutable domain evidence/approval tables remain append-only. A process crash leaves a nonterminal claim/owner, not an expired permission for another worker. Do not steal it based solely on elapsed time: reconcile backend/target evidence first. If dispatch may have happened, retain unresolved ownership and require recovery/reconciliation before another mutation. OS/file locks may supplement this ledger but are not the durable authority. Include this file in quiesced backups and consistency checks. Test simultaneous independent processes/connections, not just sequential button clicks.

Manual patch assessment has an append-only `manual_review` event linked to evidence/target/epoch, package/index digest, reviewer/time, site-policy version and decision (`confirm_compliant`, `confirm_non_compliant`, `needs_review`). Preserve original machine observations. A compliant review requires fresh supporting evidence and cannot waive outstanding required updates. New state/evidence needs a new review; the maximum review/index age for new work is a proposed 24-hour project policy, not a CIS rule.

## 7. Shared risk rubric and compatibility

Authoritative compatibility references are the inspected Windows `risk.py` and `domain.py`; record their baseline hashes. Resolve report/code discrepancies explicitly in favour of the implemented compatibility baseline while documenting them for later report correction.

**Formula:** `R = 6I + 5E + 4P + 3L + 2D`. I/E/P/L are integer 1..5; D is 1, 3 or 5. Only confirmed Non-Compliant findings receive a risk score. Low 20–39; Moderate 40–59; High 60–79; Critical 80–100.

| Factor | Existing derivation to retain |
|---|---|
| I | Consequence categories: critical_protection_lost=5, protection_weakened=4, misuse_easier=3, minor_reduction=2, detection_only=2 |
| P | Privilege categories: admin_identity_or_stored_credentials=5, all_local_accounts=4, remote_admin_logon=4, guest_or_anonymous=2, logging_only=1 |
| L | (L1, Automated)=4; (L1, Manual)=3; (L2, Automated)=3; (L2, Manual)=2 |
| D | No comparable prior=1; prior failure/current failure=3 even if raw value changes; prior pass/current failure=5 |
| E | Reviewed surface baseline plus effective context; retain the existing semantic scale and explain every adjustment |

Existing surface baselines are network_logon=3, network_anonymous=4, network_boundary=4, remote_desktop=4, local_account=3, local_secret=2, detection=2. Windows's specific Public-firewall uplift and policy-missing/effective-protection E=1 exceptions remain unchanged for Windows. Linux uses corresponding reviewed Linux observations; do not fabricate a Windows firewall profile or use RDP facts for SSH. The shared exposure scale is minimal=1, limited local/controlled=2, controlled network/remote=3, significant network/remote=4, high/untrusted exposure=5. UFW disabled or NAT in use alone is not proof of Internet reachability.

Per Ubuntu control, store categorical consequence/privilege/surface, source rationale, Server level/classification and reviewed context mapping. Generate factors and the human-readable derivation. Unsupported Linux concepts require a named reviewed extension preserving the rubric scale; do not assign a category merely to keep an arbitrary number. The previous draft's numeric table is retired. The likelihood mapping is a compatibility heuristic, not measured exploit probability; this limitation must remain visible.

Drift comparisons require the same target/epoch, compatible benchmark/profile/predicate/evidence contract and a strictly earlier valid assessment. Exclude same-round superseded scans, synthetic-versus-live comparisons and incompatible control revisions. Live/imported evidence can compare only when the underlying collector contract matches. Rank by score descending with stable control-ID tie-breaks; show agent execution order separately.

## 8. Agents, operation state and local model

Both backends expose the same four role concepts: AI Agent Orchestrator, Scanner Agent, Analysis Agent, Remediation Agent. Windows behaviour stays unchanged. Ubuntu tools implement the same responsibilities and deterministic guards:

- Orchestrator delegates, selects eligible registered proposals, orders within dependencies and explains deferrals. It does not approve or construct commands.
- Scanner invokes read-only tools, checks coverage and performs fresh verification. Permit one bounded rescan for eligible transient errors.
- Analysis reads calculated risk, investigates at most two findings, flags at most three and triages gaps. It cannot change factors/statuses.
- Remediation prechecks, executes/skips exact approved requests, and stops on uncertainty. No arbitrary parameters or retries.

Reuse the original Ollama client/Coordinator where contracts truly fit; implement Ubuntu role adapters and prompts. Keep loopback `127.0.0.1:11434`, `qwen3:8b`, `think=false`, bounded requests and no cloud fallback. Model presence comes from `/api/tags`; it is not proof of successful inference or current generation. [Ollama model-list API](https://docs.ollama.com/api/tags).

Initial compatibility budgets: 600 seconds per interactive phase; Scanner/Analysis/Remediation role budgets 180/220/360 seconds within the remaining phase budget. Use the original per-role step/call limits, including assessment orchestrator 12 steps/16 calls/three invalid calls, ordinary loops eight/ten/two, and one no-tool reminder where supported. Measure actual performance before claiming the time target is met. Long maintenance is a durable job, not an unbounded LLM request.

Each user command has an operation ID and is atomically claimed in the integration ledger before dispatch. UI reruns display current operation state and cannot dispatch it again. Do not call `st.*` from background workers. Initial interactive operations can run synchronously with bounded status output; durable remote maintenance survives UI disconnect independently. Cancellation stops future dispatch; it does not prove an already dispatched write stopped. Reconnect rebinds the durable workflow only after target/epoch verification and reconciles state before offering another mutation.

Deterministic assessment/risk remains available through `start_round(..., mode=deterministic)`, exposed as **Assess without AI** in the existing page's action area. For Windows, the adapter invokes unchanged `LiveScanner.request` (which persists evidence/framework run), existing deterministic risk analysis and HistoryService, then adds a compatible assessment-round record with mode/provenance marking and no AI plan. For Ubuntu, invoke its collector/predicates/risk/history path directly and persist the equivalent round. Required round fields must match original Windows readers and be covered by fixtures; do not fabricate an orchestrator run ID or AgentEvent.

This mode makes Scan and deterministic Analyse available. Plan/Approve/Execute are not invented for a new assessment without proposals; show them as unavailable/skipped with the reason. Existing approved work can use the explicit execute-without-AI path only if it still belongs to the backend's current eligible round and passes all freshness/approval checks. A new assessment can invalidate older approvals; do not transfer them. If an agentic round fails, preserve it and offer the explicit deterministic assessment choice rather than silently continuing an altered workflow. Label log events as deterministic system activity, not real model decisions.

## 9. All-30 remediation and safety requirements

The companion catalogue specifies all 30 controls, exact proposed values and action obligations. Coverage is grouped as follows; counts refer to distinct control families, not helper steps:

| Group | CIS IDs | Families |
|---|---|---:|
| Packages/updates | 1.2.2.1, 1.3.1.1, 1.5.4, 6.3.1.1 | 4 |
| Sysctl/services/core dumps | 1.5.1, 1.5.3, 2.1.2, 3.3.1, 3.3.2, 3.3.8 | 6 |
| Password/sudo | 5.3.3.2.2, 5.4.1.1, 5.4.1.3, 5.4.1.5, 5.2.2, 5.2.3 | 6 |
| SSH | 5.1.20, 5.1.19, 5.1.16, 5.1.7, 5.1.10, 5.1.21 | 6 |
| UFW | 4.1.3, 4.1.4, 4.1.7 | 3 |
| Audit/boot, excluding package installation above | 6.3.1.2, 6.3.1.3, 6.3.3.4, 6.3.3.8, 6.3.3.6 | 5 |

Every family implements deterministic plan/preview, parameter schema, before-state read-set, eligibility, target-side precheck, execution, receipt, fresh verification and recovery/refusal behaviour. Installation/refresh/reboot prerequisites are displayed explicitly. Existing safe values and unrelated settings are preserved. No automatic account deletion, password reset, firewall reset, indiscriminate package removal or implicit reboot.

### Approval and execution protocol

Use `ubuntu-remediation` schema 1. Bind platform/target/epoch, proposal/request IDs, assessment/evidence digest, catalogue/predicate/action versions and hash, exact typed changes, account/package/port/file lists, before-state digest, approver, approval/expiry/job deadline and recovery scope. Canonical UTF-8 JSON has sorted keys, compact separators and no NaN. Hash exact approved bytes, never amend them after approval. The prototype's local operator/session is the authority boundary; a hash is not independent human authentication.

Default dispatch expiry is one hour; before-state evidence maximum age five minutes; always re-read at execution. The target runner, not just the UI, locks the target, verifies request/identity/hash/read-set, atomically claims it and checks step-relevant state immediately before writes. A conflicting/expired/rejected/claimed request refuses. The framework lock coordinates framework jobs, not unrelated root processes; exclude concurrent external maintenance and detect conflicts.

Install runner and imported modules in root-owned non-user-writable locations. Do not grant sudo to a writable Python script or unrestricted interpreter. Use fixed commands and JSON over a controlled input channel; secrets never enter command-line arguments. Sudo password handling is separate from SSH login, verified during setup, with no broad passwordless sudo assumption.

Execution states distinguish proposed, approved/rejected, prechecking, claimed, executing, waiting maintenance/reboot/reconnect, and terminal verified/non-compliant/refused/unresolved. Command exit zero is not compliance. Rejected/expired requests write nothing. A failed/uncertain result never triggers automatic re-execution; a subsequent attempt requires reconciliation, new evidence and new approval.

### Long jobs and recovery

Root-owned systemd job supervision with protected request/receipt files under `/var/lib/fyp-hardening/` survives SSH/dashboard loss. Package job cap initially 1,800 seconds under an approved deadline. A timeout does not imply apt/dpkg stopped; report unresolved and reconcile, never delete package locks or retry blindly.

For SSH/UFW transactions, preserve the current session, arm an explicitly approved recovery watchdog, apply the exact change, prove a fresh authenticated connection and acknowledge the same request to cancel recovery. Initial acknowledgement window: 120 seconds. The supervisor owns the target lock; an armed/unresolved persistent fence prevents newer jobs even after crash. Recovery stops the forward worker before restoring approved backups so an old timer cannot overwrite a newer change. Console/snapshot access remains required. No arbitrary rollback outside the approved recovery scope.

Ubuntu `maintenance.apt_refresh.v1`, `maintenance.reboot.v1` and `recovery.restore.v1` are auxiliary operation IDs with the same guards. They do not count as additional CIS families. Metadata refresh precedes an exact package/version solver plan; approval cannot cover unknown future package candidates. Reboot is a separately approved continuation tied to staged changes and a post-boot identity/boot-ID check. Boot/audit runtime verification remains pending until activation is observed.

Actions touching the same file/account/package read-set invalidate later stale plans. Start with sequential approvals; a later composite plan is allowed only if the exact combined diff, members, dependencies and recovery are approved. Package setup precedes restrictive UFW egress; audit packages precede service/rules; valid non-root management access precedes disabling root SSH. These dependencies are enforced by code, not left to the model.

## 10. Implementation tasks

The order deliberately proves one UI and correct routing early. Each behavioural task uses a focused test-first cycle: write the named failing cases, confirm the meaningful failure, implement the interface, run focused tests, then the applicable preservation gates. Commit coherent completed checkpoints on `integrate/unified-vm-hardening` after checking Git state; no push/merge is authorised by this document.

### Task 0 — Record the Windows baseline and authorised edit boundary

**Files:** create `tools/baseline.py`, `baseline_manifest.json`, `docs/BASELINE.md`, `tests/integration/test_baseline.py`; record pre-change Git reference/source archive outside runtime imports. No runtime Windows source copy.

**Produces:** `verify_baseline(root, manifest) -> tuple[str,...]`, protected-file hash checks, classified authorised-edit diffs, source provenance and UI behaviour checklist.

- [ ] Inspect repository/worktree/instructions and uncommitted changes; resolve access without reset/clean. Compare the Desktop and parent GitHub Windows copies.
- [ ] Establish the development branch in the teammate project without resetting current changes. Record pre-change source hashes, Git reference and any required recovery archive. Classify protected engine files and authorised UI/metadata edits before changing the application; other source copies remain untouched.
- [ ] Run original Python and four PowerShell fixture suites in isolation. Record actual results, dependency versions and pre-existing failures.
- [ ] Capture existing navigation, tabs, six-step workflow, approve/reject/all/comment/confirm/fallback/resume behaviours using fixture data. Record visual baselines with no credentials.
- [ ] In disposable fixtures, test protected-file changes fail, authorised UI changes appear in the diff report, and added files cannot shadow protected imports. Gate: recoverable pre-change baseline, documented edit boundary and reproducible Windows behaviour evidence.

### Task 1 — Common contracts and one UI shell

**Files:** modify existing `app.py`, `hardening/agentic_view.py`, `overview_view.py`, `history_view.py`, and `ui.py` only as required; create `system/contracts.py`, `system/config.py`, `system/bootstrap.py`, `system/ui/components.py`, integration dependency overlay/lock and `tests/integration/test_contracts.py`, `test_shared_ui.py`.

**Consumes/produces:** records and methods in Section 5, initially supplied by fake backends.

- [ ] Create isolated `.venv-integration` at the teammate project root; retain pypsrp 0.8.1 and compatible Streamlit >=1.63, then pin the tested complete environment in the integration dependency files. Verify actual version availability/compatibility before installing; record necessary adjustments. Pin Paramiko/XML parser versions after checks. Keep the original requirements and environments intact.
- [ ] Extend the existing `app.py` and existing views to receive shared snapshots/commands. Retain the Windows UI shell/styles/navigation, and add helpers only where needed. Verify launches use this same entry point and imports use this project's `hardening/`; no replacement application.
- [ ] Wire explicit isolated development data paths before any store is constructed. Test startup cannot fall back to the teammate's live databases or implicitly migrate them.
- [ ] Define serializers, RecordRef and all shared records. Test exact status/risk/evidence labels, counts, optional Linux detail and safe escaping.
- [ ] Define distinct connection/workflow IDs and the complete auxiliary/manual-review/cancellation/reconciliation API. Fake backends must implement it or return a typed unsupported result; UI code cannot bypass it.
- [ ] Render the same five tabs with fake Windows and Ubuntu snapshots. Assert the same tabs/actions exist, backend counts vary correctly and secrets never appear in records.
- [ ] Gate: one app renders either platform through one presentation contract, with Windows appearance/interaction baseline preserved.

### Task 2 — Extend the existing form and discover transport

**Files:** modify existing `hardening/connection_view.py`; create `system/discovery.py`, `system/connection.py`; add `tests/integration/test_discovery.py` and form cases in `test_shared_ui.py`.

**Produces:** `discover_transport(endpoint, deadline) -> DiscoveryResult`, validated ConnectionRequest without serialized secrets.

- [ ] Extend the existing six-field form and Connect button on Agentic hardening; add Auto default and advanced method/key/trust controls. Do not create a second connection page or duplicate form implementation.
- [ ] Implement bounded, credential-free SSH/WS-Man endpoint probing. Do not identify OS here or send passwords during discovery.
- [ ] Tests: SSH on a nonstandard port; WinRM lab-forward port; generic HTTP; delayed/malformed banners; redirect; timeout; unsupported TLS; invalid host/port; no credential/network scan leakage.
- [ ] Ambiguous discovery returns a safe diagnostic and manual override. Test no automatic second authentication method after failure.
- [ ] Gate: the form can identify a transport candidate or explain failure, without changing a VM or constructing a backend prematurely.

### Task 3 — Authenticate, verify OS/identity and bind the backend

**Files:** `system/identity.py`, `router.py`, `session.py`, Ubuntu `ssh_channel.py`; `test_identity.py`, `test_ssh.py`, `test_routing.py`; `docs/VM_SETUP.md`.

**Produces:** verified session/ConnectionResult and `backend_for(session_id)`; only this binding may drive later operations.

- [ ] Inventory the existing Ubuntu VM read-only: OS, current tools/hardening, SSH, privilege, firewall manager and recovery. Record actual values; no reinstall. Take a snapshot before any later approved setup changes.
- [ ] Implement host-key trust, selected authentication, fixed OS/identity probes and strict per-platform identity validation. Parse OS-release as data.
- [ ] Test Ubuntu through SSH, Windows through WinRM, SSH on other OS, wrong identity, cloned ID, changed key, failed privilege, missing helper and development-host rejection.
- [ ] Separate connection readiness from assessment/remediation capability. Test form edits/disconnect invalidate backend handles and credential cleanup occurs on every failure path.
- [ ] Test reconnect to the same verified target/epoch can resume the original durable workflow without creating a round; a different target/epoch cannot attach it or execute its pending work.
- [ ] Gate: the same form connects to each registered supported VM and correctly identifies the OS; unsupported inputs never reach a hardening function.

### Task 4 — Windows adapter and early end-to-end UI integration

**Files:** `backends/windows/adapter.py`, `system/history.py`; `test_windows_adapter.py`, shared UI/routing tests.

**Consumes:** verified original WinRmTarget; **produces:** WorkspaceBackend via Section 5.3 mapping.

- [ ] Import services from the existing sibling `hardening/` package and reproduce the original service construction with explicit isolated database paths. Map snapshots using existing round/history/score helpers. Verify no copied/archived/other-checkout package can satisfy these imports.
- [ ] Implement typed start/decide/execute/history methods; validate platform/target/record/session and operation IDs on every command.
- [ ] Test per-proposal and bulk decisions, comments, expiry, latest-round-only edits, execution confirmation, deterministic fallback, goal interpretation and resumed history against baseline expected behaviour.
- [ ] Map Windows workflow calls to the persisted backend session ID, not connection ID. Test reconnect/resume and deterministic read-only assessment through original scanner/risk/history APIs, with compatible persisted rounds and no fabricated agent activity.
- [ ] Add a fake Ubuntu adapter to exercise selection/return-to-same-tabs without pretending its simulated results are live.
- [ ] Keep real mutation dispatch disabled at this milestone. Approval/execution UI tests use fixtures; enable live Windows dispatch only after Task 7's host coordination ledger passes, and Ubuntu dispatch only after Task 10's runner/safety gate. Read-only Windows integration can be demonstrated now.
- [ ] Gate: the integrated UI's Windows path works and passes original backend plus wrapper/UI regression tests. Ubuntu routing can be demonstrated in that same UI before building its full engine.

### Task 5 — Source-lock the Ubuntu 30-control specification

**Files:** `catalogues/*`, Ubuntu `catalogue.py`, `tools/check_sources.py`, `test_catalogue.py`.

**Produces:** `load_catalogue(path, source_lock) -> Catalogue` and validated one-to-many SCAP mappings.

- [ ] Implement the exact IDs/predicates/action families from the active catalogue. Verify full benchmark applicability/audit procedures and PDF hash.
- [ ] Pin a real content release/commit, datastream hash, OpenSCAP version and selected-profile variables; never invent XCCDF IDs from CIS numbers.
- [ ] Review mapping gaps and content/PDF differences, including client-alive thresholds, UFW outgoing policy and account aging. Record direct-inspection precedence.
- [ ] Assert 30 unique IDs, six per area, 24 L1/six L2, 29 Automated/one Manual and 30 unique control-remediation families. Auxiliary operations do not inflate counts.
- [ ] Gate: reviewed source/predicate manifest with no unresolved executable mapping hidden behind a placeholder.

### Task 6 — Ubuntu collection and results in the same UI

**Files:** `vm/ubuntu/collector.py`, `probes.py`; Ubuntu `collector_client.py`, `scap.py`, `evidence.py`, `predicates.py`, `adapter.py`; evidence/SCAP/predicate tests.

**Produces:** `collect(target, request_id, deadline) -> EvidenceBundle`, `assess(bundle, catalogue) -> Assessment`, shared ControlRows/Summary via UbuntuBackend.

- [ ] Implement fixed probes and pinned SCAP evaluation with output/deadline limits. Add pass/fail/missing/error/conditional fixtures for every control.
- [ ] Test compound conditions: AppArmor package plus utilities; UFW active plus enabled; runtime plus persisted sysctl; defaults plus every applicable account; SSH Match/Include; loaded plus persistent audit rules.
- [ ] Reject malformed/forged/wrong-target evidence and XML entity attacks. Test source sanitization using secret sentinels, including SCAP artifact contents.
- [ ] Assert no scan can install packages, refresh indexes, change config, reload a service or invoke remediation. Display missing/manual/inapplicable evidence honestly.
- [ ] Feed actual Ubuntu results through UbuntuBackend to the existing Controls tab and Overview. Gate: a real read-only Ubuntu assessment appears in the same UI used for Windows.

### Task 7 — Durable stores, shared history and manual review

**Files:** Ubuntu `storage.py`, `history.py`, `recovery.py`; `system/history.py`, backup/consistency tools; storage/history/recovery tests.

**Produces:** evidence/run/event/proposal/decision/receipt APIs and platform-qualified read models.

- [ ] Implement three Ubuntu SQLite files/11 table purposes, strict versioned payloads, append-only triggers, raw hashes and reassessment on read.
- [ ] Implement the separate integration ledger and its atomic claim/state-transition API before enabling backend mutations. Concurrent SQLite-connection/process tests must prove one owner for the same operation/dispatch key and no takeover after an uncertain crash.
- [ ] Test duplicate/conflicting IDs, forbidden update/delete/replace, invalid links, corrupt bytes, mismatched predicate version and failure between file transactions.
- [ ] Persist manual patch-review events and derive a labelled reviewed result without altering original evidence. Test stale review/state, forged pass and comment-only attempts.
- [ ] Route manual reviews through `record_manual_review` and bind durable workflow/target/evidence ownership. Cancellation/reconciliation events and workflow bindings are included in backup consistency tests.
- [ ] Implement one History page facade over both stores, qualified references, per-target filters and cross-platform comparison refusal.
- [ ] Implement quiesced backup/restore and consistency checks. Gate: refresh/restart/backup retains correct cross-platform history without touching original databases.

### Task 8 — Risk derivation and rubric parity

**Files:** Ubuntu `risk.py`, risk-attributes manifest, `docs/RISK_DERIVATION.md`; `test_risk.py`, history cases.

**Produces:** `rank(assessment, previous, policy) -> tuple[FindingRow,...]` with reviewed reasons and policy provenance.

- [ ] Reuse compatible pure Windows score/band functions and fixed category mappings; review each Ubuntu attribute assignment and any named extension.
- [ ] Generate the factor report from categorical attributes and evidence, not handwritten per-control numbers. Tests reject unknown/unreviewed attributes and mismatched source classifications.
- [ ] Assert all four likelihood mappings, band edges, identical-factor score parity, D=1/3/5 and persistent-failure-with-changed-value D=3. Unknown/Error never receive fabricated scores.
- [ ] Test source/target/epoch/predicate/history incompatibility, same-round superseded exclusion, context missing/contradictory and unsupported Windows evidence keys in Ubuntu.
- [ ] Gate: the common Risk ranking tab shows deterministic, explainable Ubuntu scores following the teammate's method; Windows fixtures remain unchanged.

### Task 9 — Ubuntu agents behind the common workflow

**Files:** Ubuntu `workflow.py`, `agents.py`, `prompts.py`, `tools.py`; `test_agents.py`.

**Produces:** UbuntuBackend start/snapshot/execute orchestration methods and common AgentEvents/step states.

- [ ] Reuse the reviewed bounded Coordinator/Ollama client when compatible; add Ubuntu tools/prompts and durable role events.
- [ ] Enforce roles/states/argument schemas, goals, reason codes, dependency order, investigation/attention/rescan limits and absolute deadlines.
- [ ] Test injection in evidence, fabricated commands/tool names, altered factors, bad action IDs, repeated calls, model offline, timeout, omitted decisions and incomplete handoffs. Safe omitted proposals are deferred, never silently executed.
- [ ] Show the same six workflow steps and Agent log. Deterministic fallback is explicit and uses the same safety gates.
- [ ] Test `mode=deterministic` with Ollama stopped: actual assessment/risk/history are produced, no model client is called, no proposals/agent decisions are invented, and the frontend remains in the same page.
- [ ] Gate: complete simulated Ubuntu round in the shared UI, without real mutation permissions.

### Task 10 — Target runner, approval and failure recovery foundation

**Files:** Ubuntu `actions.py`, `approvals.py`, `executor.py`, `jobs.py`, `recovery.py`; VM runner/ledger/file-transaction/connectivity guard; approval/runner/recovery tests.

**Produces:** `plan_action(action_id, assessment, policy) -> ActionPlan`, `approve(plan, operator, now) -> ApprovedRequest`, `execute(request, deadline) -> ExecutionReceipt`, `reconcile(request_id) -> ReconciliationResult`.

- [ ] Implement Section 9's exact request/receipt schemas and root-owned helper deployment. No user-writable elevated imports or secret command arguments.
- [ ] Enforce target-side lock -> validate -> fresh read-set -> claim -> step checks -> execution -> receipt. Test a change between UI precheck and actual dispatch causes zero writes.
- [ ] Test duplicate workers/clicks, changed target/epoch/action/package/account/file, rejection, expiry, host-db failure, crash after claim and success with lost receipt. At most one forward execution.
- [ ] Implement systemd-supervised maintenance and watchdog recovery with an armed persistent fence. Kill SSH/dashboard/supervisor in test scenarios and prove the next action cannot overlap unresolved recovery.
- [ ] Define auxiliary maintenance/recovery schemas, reboot continuation and cancellation semantics. Gate: fault-injection proof before enabling any live family.
- [ ] Implement `request_auxiliary -> decide -> dispatch_auxiliary` for the three supported operation kinds, with the same claims/guards as control actions. Test manual-review and maintenance UI paths cannot call private Ubuntu services or bypass the common interface.

### Task 11 — Package, sysctl, core-dump and service families (10 controls)

**Files:** VM `actions/packages.py`, `sysctl.py`, `services.py`, `coredumps.py`; package/sysctl/service tests; action registry.

- [ ] Implement four package families with approved metadata refresh, exact solver/version/dependency plan, snapshot recovery, prelink reversal and package/state verification.
- [ ] Test lock contention, stale candidates, held packages, unintended removal, disk exhaustion, maintainer-script effects, partial dpkg state and still-running process after timeout. Never delete locks or retry blindly.
- [ ] Implement six sysctl/service/core-dump families with effective/persisted precedence, conditional coredump handling, IPv6 applicability and exact restoration.
- [ ] Test conflicting files, UFW sysctl overrides, symlinks, service dependencies and runtime/boot disagreement. Preserve unrelated settings.
- [ ] Gate: ten implemented families, independent fail-to-pass VM evidence and failure/recovery records; results appear in shared Fixes/Results tabs.

### Task 12 — Password and sudo families (six controls)

**Files:** VM `actions/passwords.py`, `sudo.py`; `test_password_sudo.py`.

- [ ] Implement minimum length, maximum age, warning, inactivity, sudo PTY and dedicated log policy according to the catalogue.
- [ ] Bind affected accounts by username/UID and previous fields; preserve stricter values and reject changed account sets. Never export password hashes or rewrite all of shadow.
- [ ] Test PAM/include precedence, immediate account expiry, protected management account, UID reuse, invalid sudo syntax and later overrides. Validate staged complete sudo configuration before install.
- [ ] Verify new authenticated/sudo-capable access and harmless log events; recover only approved changed fields/configuration.
- [ ] Gate: six additional families with preserved administrative access and no secrets in evidence/logs/prompts.

### Task 13 — SSH families (six controls)

**Files:** VM `actions/sshd.py`; `test_sshd.py`.

- [ ] Implement one guarded SSH transaction primitive and six fixed policy families. Resolve Include/Match semantics, syntax and effective values; do not append an ineffective drop-in.
- [ ] Preserve the active session, prove non-root/alternate authentication when needed, arm recovery, reload and verify a new authenticated connection.
- [ ] Test config errors, overrides, MaxAuthTries/key selection, wrong Match context, reload failure and channel loss. An old open connection or `sshd -t` alone does not prove success.
- [ ] Record watchdog restoration and external console recovery trials. Gate: all six independently verified and displayed through the same UI.

### Task 14 — UFW families (three controls)

**Files:** VM `actions/ufw.py`; `test_ufw.py`.

- [ ] Implement activation, loopback/anti-spoofing and default policy families with exact rule ordering, backups and no reset/flush.
- [ ] Resolve guest SSH port/source address and approved outbound requirements; host NAT forwarding port is not the guest service port. Preview management/egress allowances explicitly.
- [ ] Test earlier deny rules, IPv6 mismatch, another firewall manager, blocked repository/DNS access and lost connection mid-change. Default policy verification includes outgoing and routed directions.
- [ ] Require successful watchdog/console recovery trial before live activation. Gate: three verified families without losing management access.

### Task 15 — Audit and boot families (five controls)

**Files:** VM `actions/audit.py`, `boot.py`; `test_audit_boot.py`, maintenance documentation.

- [ ] Implement service enable/start, early-boot audit, time-change/identity-change/privileged-executable rules; package installation is already Task 11.
- [ ] Bind architecture, UID_MIN, syscall availability, eligible filesystems and exact discovered executable paths. Do not execute discovered binaries or scan unbounded remote mounts.
- [ ] Test immutable audit state, invalid/conflicting rules, changed discovery set, unsupported bootloader and failed boot configuration generation.
- [ ] Demonstrate separate reboot approval, durable awaiting-reconnect, VM/epoch/boot-ID verification and fresh loaded/persistent-rule checks. Staged state is not runtime compliance.
- [ ] Gate: all five validated; total implemented control-remediation families now exactly 30.

### Task 16 — Complete shared UI, maintenance and session behaviour

**Files:** scoped edits to the existing `app.py`/`hardening` view files plus new `system/ui/` helpers/session/history; both adapters; `tests/integration/test_shared_ui.py`, `test_system_acceptance.py`.

- [ ] Add Ubuntu-specific previews, manual review, package/maintenance/reboot/recovery details inside existing tabs. No alternate dashboard or application switcher.
- [ ] Preserve Windows goals, approvals, bulk actions, comments, confirmation, deterministic fallback and old-round read-only behaviour. Compare against Task 0 baselines.
- [ ] Test refresh/two tabs/double clicks, operation resumption, stale commands, record-ID collisions, modified form fields, disconnect and reconnect to another VM. Every backend command validates its session/reference server-side.
- [ ] Test simultaneous execution attempts from independent clients with different operation IDs but the same approved request set: only one dispatch is possible. Test the separate connection/workflow lifecycle for refresh, resume, cancellation and unresolved remote jobs.
- [ ] Test Windows -> disconnect -> Ubuntu -> disconnect -> Windows within the same app. Histories remain visible through filters; approvals never move between targets.
- [ ] Gate: complete one-system workflow for both platforms, with visual and behavioural evidence and no secret/global cached authenticated-session leaks.

### Task 17 — Live evaluation and handover

**Files:** evaluation/independent-audit tools, OPERATIONS/RECOVERY/EVALUATION/REPORT_CHANGELOG and README.

- [ ] Define independent expected outcomes before tests; cross-checks must not simply call the implementation's own predicates.
- [ ] For all 30 controls record compliant/non-compliant cases, missing/error/manual/applicability cases, a successful approved remediation and required refusal/recovery evidence on disposable/revertible VM states. Mark any family lacking live evidence as unvalidated.
- [ ] Exercise wrong OS/identity, model offline, stale/rejected/duplicate requests, partial collection, host crash, channel loss, lost receipt, package timeout, immutable audit, reboot and snapshot-epoch scenarios.
- [ ] Repeat representative agentic scenarios at least three times with a deterministic baseline, reporting completion, latency, safe deferrals, invalid calls, verification/recovery and failures. Do not claim AI superiority without evidence.
- [ ] Run complete existing Windows and integrated regression gates, verify protected engine/script hashes and review authorised UI/metadata diffs against the pre-change baseline. Verify dependency/data isolation and demonstrate both VMs through the existing `app.py` and same form.
- [ ] Deliver one launch command, setup/backup/recovery instructions, architecture/interfaces and report-change log. Gate: all Section 12 criteria evidenced; no report rewrite or deployment/merge implied.

## 11. Verification commands and milestone order

These are future implementation commands, not checks run while drafting. Run from the teammate's existing application directory, `C:\Users\teohk\OneDrive\Desktop\FYP_App-main\window_cis_compliance_dashboard_prototype\cis_compliance_dashboard_prototype`, using `.venv-integration` at its parent project root:

```powershell
# Focused example; test suites use fake transports by default
..\.venv-integration\Scripts\python.exe -B -m unittest discover -s tests/integration -p test_routing.py -v

# Shared-system deterministic suite
..\.venv-integration\Scripts\python.exe -B -m unittest discover -s tests/integration -v

# Existing Windows tests plus discoverable integration tests
..\.venv-integration\Scripts\python.exe -B -m unittest discover -s tests -v

# The SAME existing application entry point, now supporting both platforms
..\.venv-integration\Scripts\python.exe -m streamlit run app.py
```

Use Streamlit AppTest for widget/state tests and visual captures for appearance. Run existing Windows tests in the existing nested application with the isolated Python executable; run the four existing PowerShell fixture suites from their expected project root, after inspecting their setup and confirming isolated fixture destinations. Do not change test expectations to hide regressions. Use separate process-scoped temporary directories. Normal tests never connect to a real VM; live mutating evaluation requires explicit target/action approval and recovery readiness.

Run focused tests, protected-file hash checks and authorised-diff review at each checkpoint. Run the full Windows suite at baseline capture, adapter/shared-dependency changes, UI completion and final acceptance. No need to rerun unrelated expensive tests after documentation-only changes.

| Milestone | Tasks | Demonstration |
|---|---|---|
| M0 Preserve and define | 0–1 | Recoverable pre-change baseline + existing app/views wired to shared contracts |
| M1 Prove the required integration | 2–4 | Same form detects/verifies/routes; Windows read-only path and fixture-tested workflow work |
| M2 Ubuntu assessment in that UI | 5–8 | 30-control scan, common statuses/risk/history |
| M3 Agents and controlled execution | 9–10 | Four roles, approval/ledger/recovery foundation |
| M4 Full Ubuntu remediation | 11–15 | All 30 action families with validation records |
| M5 Team system acceptance | 16–17 | Same form/UI for both real VMs, regression proof and runbooks |

Indicative solo effort remains roughly 6–11 working weeks for the complete scope, depending on VM condition, configuration complexity and live recovery testing. This is an estimate, not a promised date. Demonstrate M1/M2 early so architectural integration is proven before investing in all 30 actions. Do not remove fault/recovery validation merely to meet an assumed deadline.

## 12. Definition of done and handover checklist

- [ ] Existing teammate `cis_compliance_dashboard_prototype/app.py` remains the single entry point/server/UI; no separately launched Ubuntu app or replacement application root.
- [ ] Same Agentic hardening form accepts the supported Windows and Ubuntu connection details.
- [ ] Protocol discovery is bounded; OS detection uses authenticated facts; wrong/unsupported identities cannot route to hardening.
- [ ] Existing Windows UI style, tabs, stages, wording and actions preserved through common components.
- [ ] Windows engine/scripts unchanged; existing Windows functionality/tests retained. Every authorised entry-point/view/metadata edit is recorded and regression-tested against a recoverable pre-change baseline. Original environments/live databases remain untouched.
- [ ] Existing Ubuntu VM reused if compatible; setup/test changes backed by recovery snapshots and explicit approvals.
- [ ] Ubuntu 30-control catalogue accurately labels L1/L2/Manual scope and pins evidence sources.
- [ ] All 30 Ubuntu remediation families implemented and live-validated, with exact previews, safety/refusal, verification and recovery records.
- [ ] Shared statuses and risk method/rubrics are enforced; per-control numbers derive from reviewed attributes, not LLM/sample data.
- [ ] Windows retains its catalogue/action set; Ubuntu counts do not overwrite Windows counts.
- [ ] Shared history handles both platforms with qualified references, separate decoder/store ownership and no cross-target drift or approvals.
- [ ] Model-offline operation, duplicate UI events, crash/lost receipt, stale state, authentication/firewall recovery and reboot continuation tested.
- [ ] No credentials/hash/private-key leakage in database, model prompts, artifacts, UI or logs.
- [ ] Another developer can use the interfaces, task files, catalogue and runbooks without relying on this chat.

## 13. Inputs and decisions to confirm during execution

The product direction is confirmed: one system, teammate UI, same form, verified platform routing, Ubuntu functions implemented by Teoh, original Windows preservation, shared terminology/risk and full 30-family coverage. Do not reopen these choices as if the user requested separate applications.

Review the proposed exact 30 controls (including six L2 audit controls and one Manual update control), fixed-runner execution choice and site policy values in the companion catalogue before enabling them. Actual VM endpoint, identity, host-key fingerprint, sudo capability, snapshot/console access and maintenance window must be obtained from the real environment; never invent them. Pin actual dependency/content releases when implementing, with source/hash evidence.

The user has authorised scoped integration edits to the existing entry point and views; do not seek permission again solely because these files need to change. If source inspection requires a change to protected Windows engine logic or removal of an existing feature, prepare a concrete compatibility-tested alternative for review before that change. Preserve decisions in the active design and change log. Earlier version-1 plans and version-2 source-copy/alternate-entry-point instructions are historical, not implementation instructions.
