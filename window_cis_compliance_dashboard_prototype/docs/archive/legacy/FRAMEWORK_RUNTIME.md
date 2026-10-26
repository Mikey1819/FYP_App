# Imported-assessment framework foundation

> **Archived 26 October 2026.** Describes the legacy **Evidence upload** page (manual file exchange and the earlier agent team), not the current agentic framework. Current design: [ARCHITECTURE.md](../../../ARCHITECTURE.md); current status: [PROGRESS.md](../../../PROGRESS.md).

Implementation status: 23 October 2026, Asia/Kuala_Lumpur (UTC+08:00). F1 now includes the assessment runtime and a durable service linking each run to exact proposals, decisions and returned verification. The full adaptive AI orchestrator remains unfinished. See [the framework plan](../../../REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md) for the final target and [progress](../../../PROGRESS.md) for exact validation results.

## Delivered behaviour

The Streamlit upload flow and the command-line client use the same UI-independent `AssessmentOrchestrator`. A new run binds the selected VM identity to one immutable imported evidence file. The controller performs at most three read-only stages and persists each result and state transition in one SQLite transaction.

| State before task | Role and permitted operation | Result |
| --- | --- | --- |
| `assessment_requested` | Scanner Agent: revalidate stored source and assess the five reviewed controls | Coverage and per-control classifications; `assessment_checked` |
| `assessment_checked` | Analysis Agent: classify follow-up needs | Non-compliant and unavailable-evidence IDs; explicit unavailable real risk and AI-not-invoked labels; `findings_analysed` |
| `findings_analysed` | Remediation Agent: inspect registered action eligibility | Password-length candidate or assessment-only findings; terminal assessment outcome |

Terminal outcomes are `ready_for_review` when a supported candidate exists, `needs_review` when only unsupported findings or missing/error observations remain, and `assessment_complete` when neither remains. A candidate can coexist with other unresolved checks: `ready_for_review` does not mean all controls passed. Eligibility never creates approval or executes a change.

These are policy-driven operational roles. The controller currently uses a fixed stage sequence with evidence-dependent outcomes. The local-model investigation and approved VM bridge remain separate components, now connected through run-bound proposal creation and durable lifecycle references. This foundation is not evidence of new model-driven coordination.

## Local clients

The dashboard still starts blank. Analyze an uploaded collector JSON to create a new framework run; expand **Assessment steps for this test** to see its three recorded roles. Starting a new test clears the displayed run without deleting audit data. Another browser session does not automatically reopen historical runs.

From the application directory, replace the example path and identity placeholders with the selected VM's collector file and console identity:

```powershell
.\.venv\Scripts\python.exe -B -m hardening.framework --database data\cli_imports.sqlite3 --evidence 'C:\path\server-evidence.json' --hostname '<VM computer name>' --machine-uuid '<VM UUID>'
```

The JSON output contains `run_id`, target, evidence hash, state and recorded tasks. To resume a particular run using the same database:

```powershell
.\.venv\Scripts\python.exe -B -m hardening.framework --database data\cli_imports.sqlite3 --resume-run '<run_id from output>'
```

Both commands perform local assessment only. They do not invoke Ollama, collect fresh VM data, approve proposals or execute security commands. Repeating an evidence import creates a distinct run while reusing the identical stored snapshot. Resuming a completed run returns its existing results.

## Python dispatch contract

`start(raw, expected_hostname=..., expected_machine_uuid=...)` validates evidence and creates a run. `get(run_id)` reads its state. `complete_assessment(run_id)` advances the bounded read-only sequence; `advance(run_id)` atomically advances whichever stage is current.

For a caller that retains a task before dispatching it, use:

```python
task = runtime.next_task(run_id)
if task is not None:
    run = runtime.dispatch(task)
```

`AssessmentTask` is a frozen contract containing run ID, evidence SHA-256, target ID, expected state, role and operation. The controller compares the entire request with the only permitted next task under the same database transaction used to commit the result. Altered roles, execution operations, target/evidence mismatches and stale states fail before a role is invoked. Replaying the same task cannot silently advance the following stage. Completed runs have no next task. Callers should fetch current state after a stale-message error; this is not a network authentication protocol.

## Persistence and recovery

For `preview_imports.sqlite3`, runtime state is saved separately in `preview_imports_framework.sqlite3`. Schema version 1 has `framework_runs` and `framework_tasks`; each committed task has a unique ID, role, operation, completion time and result. Input identity/hash is retained on the parent run. Existing version-one files gain additional triggers when opened, without rewriting snapshots or task results.

Task updates, deletion and replacement inserts are refused. Run identity, source binding and creation time cannot be changed through ordinary table writes; deletion and replacement are also refused. These application protections are not tamper-proof storage against an administrator who can alter the schema or database files.

Concurrent callers serialize through `BEGIN IMMEDIATE`. A failed read-only stage rolls back its task and transition; a later call can resume it. Failure attempts themselves are not yet durable events. A successful import followed by a failed run creation can leave an unused valid snapshot because the two databases are separate. No VM write is involved in either case. Back up databases with the application stopped.

## Remediation lifecycle service

[RemediationLifecycle](../../../cis_compliance_dashboard_prototype/hardening/lifecycle.py) uses the existing framework and bridge stores without importing Streamlit or the model client. Instantiate it with stores pointing to the same imported-evidence database:

```python
from hardening.framework import AssessmentOrchestrator
from hardening.import_storage import ImportedEvidenceStore
from hardening.lifecycle import RemediationLifecycle
from hardening.vm_bridge import BridgeStore

imports = ImportedEvidenceStore("data/preview_imports.sqlite3")
runtime = AssessmentOrchestrator(imports)
bridge = BridgeStore("data/preview_imports_bridge.sqlite3", imports)
lifecycle = RemediationLifecycle(runtime, bridge)
state = lifecycle.get(run_id)  # Explicitly selected completed assessment run.
```

`prepare(run_id)` creates a proposal and its immutable run association in one transaction in the bridge database. Concurrent initial calls return the same undecided proposal. A rejected proposal remains in the audit trail; preparing another requires its exact ID as `expected_previous_id`. Pending or approved attempts cannot authorize another attempt through this service, including after failed verification. Another assessment test and new explicit approval are required.

`decide(run_id, proposal_id, approve=..., operator=...)` requires exact run association before calling the existing bridge approval gate. `accept_receipt(run_id, proposal_id, raw)` requires that association plus all existing request-hash, target, time and precondition checks. Even another run with identical evidence cannot consume its decision or receipt. Neither API invokes a security command; VM execution remains an administrator-launched file exchange.

`get(run_id)` returns the assessment outcome plus ordered attempts, operator decision records, receipt hashes, and separate pre-action/post-action evidence hashes. The assessment state remains historical; lifecycle progress never overwrites it. Lifecycle outcomes derive from the linked immutable bridge records:

| Outcome | Meaning |
| --- | --- |
| `awaiting_approval` | An eligible proposal exists; no decision or executable request |
| `rejected` | Administrator rejected it; no request issued |
| `awaiting_receipt` | Approved request exists, but no result has been received; execution is not inferred |
| `receipt_import_incomplete` | Receipt was retained but its evidence import was interrupted; reupload the identical receipt, never rerun the action for this reason |
| `verified` | Matching receipt contains a compliant post-action observation |
| `unresolved` | Execution failed, postcheck was unavailable, or verification failed; no automatic retry |

An approved request retains its expiry in the decision record; `awaiting_receipt` does not assert that it is still executable. The VM runner enforces expiry, and receipt validation checks collection times against the approval interval. A receipt received later can still describe a valid earlier attempt.

The additive `framework_proposals` table lives beside proposals/decisions/receipts in the bridge database. Its keys enforce one proposal association and ordered attempts per run. Link and bridge audit records refuse updates, deletes and replacement inserts. Existing historical proposals stay unlinked; they are not automatically assigned to a new test. No framework database version bump or snapshot rewrite is needed.

Receipt and snapshot storage use separate databases. A receipt may be saved before its snapshots; the service exposes incomplete import until both required snapshots exist. Reimporting identical bytes repairs this idempotently. The dashboard derives displayed results from the persisted lifecycle instead of trusting cached success flags and labels a returned pre-action snapshot explicitly when no postcheck exists. Fresh browser sessions still start blank; the service can reopen an explicitly supplied run ID without adding an automatic history selector.

The bounded investigator receives a trusted proposal callback from `investigation_tools(run_id)`. Its proposal uses this same association transaction and remains unapproved. Investigation log payloads include `framework_run_id`, including model-unavailable runs. The model still cannot approve, execute or choose arbitrary commands. [F2 operational-context investigation](ADAPTIVE_INVESTIGATION.md) now replaces the four-lookup policy with context-dependent clarification, deferral, no-action and proposal outcomes. New lifecycle proposals require a saved compatible report and bind its immutable revision; this is not approval or collected VM evidence.

## Validation and requirement evidence

- [Framework tests](../../../cis_compliance_dashboard_prototype/tests/test_framework.py): process restart and CLI reuse, concurrent advance/dispatch, invalid identity and altered/stale messages, coverage outcomes, failed-stage rollback, eligibility boundaries, immutable records and additive storage guards.
- [Dashboard tests](../../../cis_compliance_dashboard_prototype/tests/test_import_view.py): current upload creates three persisted stages, unrelated run blocks solution review, blank restart, two test cycles, exact approval and rejection of the previous receipt.
- [Lifecycle tests](../../../cis_compliance_dashboard_prototype/tests/test_lifecycle.py): atomic/concurrent proposal linkage, cross-run rejection with identical evidence, retained rejection and guarded retries, process restart without UI/model modules, interrupted receipt recovery, unresolved outcomes, model proposal linkage and immutable audit records.
- Existing bridge/workflow tests continue to verify approval, rejection and receipt handling. The new service references those records without replacing their gates.

This supports N1/N3, the limited-scope FR05/FR08–FR12/FR16 handoffs, NFR04 persistence and part of NFR05/E02 reuse. It does not close the full requirements, registry-extension evaluation, adaptive behaviour E03, or live evaluation. Five controls and one eligible executable action remain the scope; real-evidence numeric risk and drift remain pending.

## Next development slice

Extend and repeat the [F2 evaluation](ADAPTIVE_INVESTIGATION.md) across missing evidence, compliant findings, changed context and effective/policy distinctions; review factual claims and compare review burden with the fixed-rule baseline. F1 still needs registry-extension evaluation and durable failure-attempt events before its full exit criteria can be claimed. Real risk and drift remain later F3 work.
