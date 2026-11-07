# Unified Windows and Ubuntu system: architecture and interfaces

One application (`app.py`, Streamlit), one connection form and one workspace serve two platforms. The Windows framework is unchanged and is described in `../docs/design/ARCHITECTURE.md`; this page covers how the two platforms share the system and where the Ubuntu side lives. Daily use is in `OPERATIONS.md`; the development record is in `INTEGRATION_PROGRESS.md`.

## Layers

| Layer | Code | Responsibility |
| --- | --- | --- |
| Pages | `app.py`, `hardening/*_view.py` (authorized scoped edits) | One form, the same tabs (Fixes, Risk ranking, Controls, Results, Agent log), Overview and History for both platforms |
| Shared UI | `system/ui/` | Renders a `WorkspaceSnapshot`; never calls a backend directly. Fixes cards for Ubuntu plans |
| Connection | `system/connection.py`, `discovery.py`, `identity.py`, `session.py` | Bounded transport discovery, host-key check before login, authenticated OS and machine identity, credentials in memory only, no fallback across protocols |
| Routing | `system/bootstrap.py`, `backends/base.py` | A verified identity selects exactly one backend; a wrong or unsupported OS reaches none |
| Contracts | `system/contracts.py` | Platform-neutral records and the `WorkspaceBackend` protocol (below) |
| Coordination | `system/ledger.py` → `data/integration.sqlite3` | Workflow bindings, operation claims (at most once), acceptance runs; shared by both platforms |
| Windows backend | `backends/windows/adapter.py` over the protected `hardening/` engine | Maps the original engine to the contracts without changing it |
| Ubuntu backend | `backends/ubuntu/` | Catalogue, predicates, risk, agents, plans, approvals, executor, storage |
| Ubuntu target | `vm/ubuntu/` (installed on the VM by `install-runner.sh`) | Read-only collector and fixed runner: preview, execute, supervised jobs, commit-confirm, restore, reconcile |

## The backend interface

Every page action goes through `WorkspaceBackend` (`system/contracts.py`). Each method takes the connection session (and the workflow where it applies) and validates it on the server side, so a stale form, another tab or another VM cannot act.

| Method | Purpose |
| --- | --- |
| `capabilities` | What this platform offers (agentic rounds, maintenance, manual review) |
| `snapshot` | Everything a page shows: target, assessment, controls, findings, proposals, results, agent events, plan rows |
| `start_round` | Assessment, `AssessmentMode.DETERMINISTIC` (no AI) or `AGENTIC`, at most once per operation ID |
| `decide` | Approve or reject one proposal; an approval binds the exact request bytes and expires |
| `execute_approved` | Dispatch exactly the expected approved set, at most once |
| `request_auxiliary` / `dispatch_auxiliary` | Restore, package-list refresh, reboot: proposed, approved and run like fixes, never counted as CIS fixes |
| `operation_state`, `reconcile_operation`, `cancel_operation` | Long or interrupted operations, settled from the target's own record |
| `history`, `compare` | Per-platform history and drift, with qualified record references |
| `record_manual_review` | Bound human review for Manual controls (1.2.2.1) |

## Ubuntu round, end to end

1. **Collect:** one helper invocation over SSH returns an envelope (`backends/ubuntu/envelope.py`) that is validated and stored before use (`storage.py`, `data/ubuntu/`).
2. **Assess:** predicates (`predicates.py`) decide all 30 controls from direct effective-state probes. OpenSCAP results corroborate and never override a direct failure. Statuses: Compliant, Non-Compliant, Unknown, Error.
3. **Risk:** `R = 6I + 5E + 4P + 3L + 2D` from the reviewed manifest (`risk.py`); the LLM never scores (D2).
4. **Agents (optional):** Orchestrator, Scanner and Analysis over the protected Coordinator (`agents.py`). The Orchestrator decides by deferring; every registered fix it does not defer is proposed (D4). Every list shape and reason is validated.
5. **Plan and preview:** each proposed fix gets a read-only VM preview and a stored deterministic plan (`actions.py`). A refused preview means no fix plan, and the card says so.
6. **Approve and execute:** the administrator approves each fix. The executor checks workflow, target and registration epoch, claims the operation once and dispatches the exact bytes. The VM runner checks identity and hash, fences the target and writes. Long changes run as systemd jobs; SSH/UFW changes need confirmation after reconnecting, or roll back by themselves.
7. **Verify:** a fresh scan runs automatically, and only it can show a control as fixed.

## Stores

| File (under `data/`) | Owner | Contents |
| --- | --- | --- |
| `integration.sqlite3` | coordination ledger | bindings, operation events, acceptance runs |
| `ubuntu/integration_imports.sqlite3` | Ubuntu storage | validated scan envelopes |
| `ubuntu/integration_imports_framework.sqlite3` | Ubuntu storage | assessment runs |
| `ubuntu/integration_imports_agentic.sqlite3` | Ubuntu storage | rounds, agent logs, proposals, decisions, receipts |
| `windows/…` (three files) | Windows engine | the original three-file contract |

Backup and restore: `tools/backup_stores.py` (see `OPERATIONS.md`).

## Evidence and evaluation tools

| Tool | Output |
| --- | --- |
| `tools/baseline.py` | Protected-file check against the pre-integration baseline (`BASELINE.md`) |
| `tools/live_validation_register.py` | `evaluation/LIVE_VALIDATION.md`: per-control live status from stored receipts |
| `tools/scap_cross_check.py` | `evaluation/SCAP_CROSS_CHECK.md`: direct probes against OpenSCAP |
| `tools/fault_scenarios.py` | `evaluation/FAULT_SCENARIOS.md`: required fault scenarios and their tests |
| `../scripts/evaluation/evaluate_ubuntu_agentic_rounds.py` | Real-model agentic evaluation (`evaluation/UBUNTU_AGENTIC_EVALUATION.md`) |
