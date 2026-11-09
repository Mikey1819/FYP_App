# Unified Windows and Ubuntu system: architecture and interfaces

One application (`app.py`, Streamlit), one connection form and one workspace serve two platforms. The Windows framework is unchanged and is described in `../docs/design/ARCHITECTURE.md`; this page covers how the two platforms share the system and where the Ubuntu side lives. Daily use is in `OPERATIONS.md`; the development record is in `INTEGRATION_PROGRESS.md`.

## Layers

| Layer | Code | Responsibility |
| --- | --- | --- |
| Pages | `app.py`, `hardening/*_view.py` (authorized scoped edits) | One form, the same tabs (Fixes, Risk ranking, Controls, Results, Agent log), round picker, round report, Overview and History for both platforms |
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
| `request_auxiliary` / `dispatch_auxiliary` | Restore, package-list refresh, reboot: proposed, approved and run like fixes, never counted as CIS fixes. The Ubuntu page offers the refresh only after a package install (1.3.1.1, 6.3.1.1) could not be planned or run, and the reboot only after an applied fix that completes at the next boot (6.3.1.3) |
| `operation_state`, `reconcile_operation`, `cancel_operation` | Long or interrupted operations, settled from the target's own record |
| `history`, `compare` | Per-platform history and drift, with qualified record references |
| `record_manual_review` | Bound human review for Manual controls (none in catalogue v2; 1.2.2.1 was retired 2026-11-08) |

## Ubuntu round, end to end

1. **Collect:** one helper invocation over SSH returns an envelope (`backends/ubuntu/envelope.py`) that is validated and stored before use (`storage.py`, `data/ubuntu/`).
2. **Assess:** predicates (`predicates.py`) decide all 30 controls from direct effective-state probes. OpenSCAP results corroborate and never override a direct failure. Statuses: Compliant, Non-Compliant, Unknown, Error.
3. **Risk:** `R = 6I + 5E + 4P + 3L + 2D` from the reviewed manifest (`risk.py`); the LLM never scores (D2).
4. **Agents (optional):** Orchestrator, Scanner and Analysis over the protected Coordinator (`agents.py`). The Scanner may inspect observations (states only) and rescan once on an Error; the Analysis Agent reads the ranking, may inspect a finding or check its history (two calls in total), flags with fitting attention codes and triages every gap (`rescan` only for an Error). The Orchestrator may delegate the Scanner once more (after a stop without a decision, or a rescan request), decides by deferring and lists fixes in the order they run; every registered fix it does not defer is proposed (D4). Every list shape and reason is validated.
5. **Plan and preview:** each proposed fix gets a read-only VM preview and a stored deterministic plan (`actions.py`). A refused preview means no fix plan, and the card says so.
6. **Approve and execute:** the administrator approves each fix. With the model, the remediation phase runs (`remediation_agents.py`): the Orchestrator delegates the Remediation Agent, which prechecks read-only (expiry, fresh preview against the approved digests), skips what is not ready, executes the rest in its order and, after a refusal, goes on or stops; nothing runs after an uncertain outcome. **Confirm and execute** runs the remediation phase (in plan order only while the model is unavailable); as on Windows, **Execute remaining without AI** is offered once the agents stopped early with approved fixes still waiting, and the outcome then reads "Executed without AI". Either way the executor checks workflow, target and registration epoch, claims the operation once and dispatches the exact bytes; the VM runner checks identity and hash, fences the target and writes. Long changes run as systemd jobs; SSH/UFW changes need confirmation after reconnecting, or roll back by themselves.
7. **Verify and review:** a fresh scan (by the Scanner Agent in the remediation phase, or by code when it was left out) is the only thing that can show a control as fixed. The Orchestrator then chooses finish, next round or remediation review, with a reason code checked against the results.
8. **Explain (optional, FR17):** as on Windows, the chosen finding's details under Risk ranking (factors, rules, rationale) can ask the local model for a plain-language explanation of one finding (at most 90 words, code-written facts only), shown as unverified; it changes nothing.

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
