# F2: operational-context investigation

This implementation adds bounded, evidence-dependent decisions for the existing imported minimum-password-length finding. It does not expand the five-control catalogue, add a new executable action, or complete the full multi-role adaptive orchestrator. [FRAMEWORK_RUNTIME.md](FRAMEWORK_RUNTIME.md) describes the underlying assessment and approval lifecycle.

## Operational context and authority

Collected password length cannot establish whether account-provisioning scripts and applications support a 14-character minimum. Firewall and NLA observations cannot answer that question either. The dashboard therefore accepts an explicit administrator report for the current assessment run:

- `unknown`: compatibility has not been established.
- `compatible`: the administrator reports support for passwords of at least 14 characters.
- `incompatible`: a dependency or provisioning limitation needs review first.

The report records operator label, note, timestamp, revision, context ID and run ID. It is unverified administrator-supplied context, separate from imported observations and from approval. No password contents are collected. A compatible report does not authorize a VM command.

The new `framework_context` table keeps immutable revisions in the bridge database. A nullable `context_id` column is added to existing `framework_proposals` rows without rewriting historical records. New proposals bind the exact current compatible context. Old pending proposals without that binding must be rejected and recreated before they can be approved through the lifecycle service; historical approvals/receipts remain readable.

The normal deterministic proposal button and model proposal callback share the same compatibility gate. Unknown or incompatible context withholds new proposals. Context freezes when a proposal is pending or approved; reject a pending proposal before correcting it. After rejection, a revised report and a fresh proposal are allowed. A model investigating a superseded revision cannot submit a proposal. A new test starts with unknown context and empty context input fields, even on the same VM.

The lower-level legacy `BridgeStore` API remains the earlier one-action transport component. Normal application proposal and decision calls use `RemediationLifecycle`; the application does not expose the legacy API as a context bypass. The VM runner still independently checks identity, action, expiry, precondition and replay protection. It does not independently verify provisioning compatibility.

## Investigator decisions

The local model selects registered tools and observes their returned evidence. Reference and related-configuration lookups are optional; there is no longer a mandatory four-lookup sequence. Proposal submission still requires reading the finding, the operational context and the supported action, plus the deterministic finding/context checks.

| Observed situation | Permitted structured conclusion | Proposal |
| --- | --- | --- |
| Already compliant password length | `no_action` through `finish_no_action` | None |
| Missing/error password observation | `awaiting_context` through `request_admin_clarification` | None |
| Non-compliant, provisioning compatibility unknown | `awaiting_context` after inspecting the context | None |
| Non-compliant, known provisioning dependency | `deferred` through `defer_remediation` | None |
| Non-compliant, reported compatible | `awaiting_approval` after reading the supported action, or a justified defer decision | Unapproved only |

These conclusions concern the password-length finding, not the overall five-control compliance result. A no-action decision for password length does not imply that other controls passed.

The coordinator stops immediately after a valid terminal tool result, including within a batch of model calls. A later call in that batch cannot submit a proposal after deferral. The terminal record contains its public reason, evidence digest, context ID and optional proposal ID. No private model thinking is stored. Prompt/tool notes are untrusted data; instruction-like notes cannot override the structured compatibility status.

The existing bounds remain eight model steps, ten tool calls, 90 seconds per request and 240 seconds total. Unknown tools, wrong targets/controls, unexpected arguments, repeated calls and malformed outputs retain their existing guards. Model prose without a terminal decision is labelled `No structured decision` (or the applicable failure status), never inferred as an approval or successful outcome. If the model is unavailable, deterministic assessment and the guarded non-model proposal path remain usable.

## User and Python flows

In the dashboard, open **Password provisioning compatibility**, report the status with an operator label and supporting note, then save. **Investigate this VM finding with local Ollama** can ask for clarification while compatibility is unknown. The deterministic proposal button remains disabled until compatibility is reported as compatible. Review and approval are still separate steps. Investigation traces label earlier context if the report has since changed.

The UI-independent service exposes:

```python
context = lifecycle.save_context(
    run_id, compatibility="compatible", operator="Administrator",
    note="Describe the actual provisioning check and its result.",
)
tools = lifecycle.investigation_tools(run_id)
# Pass tools to Coordinator with the existing local client.
# Saving context and creating tools do not approve or execute anything.
```

Each investigator holds a snapshot of its context. The callback rechecks its ID against current context during proposal creation. Rejection/retry, exact run binding and receipt verification remain in the lifecycle service. The resulting investigation log includes the framework run ID and context snapshot, so a reviewer can see what the model was told.

## Reproducible evaluation

[probe_adaptive_vm.py](scripts/probe_adaptive_vm.py) runs the actual installed local `qwen3:8b` against labelled synthetic fixtures conforming to the imported-evidence schema. It never approves or executes a proposal. Every invocation creates an isolated folder under application `data/adaptive_probes/` containing databases, per-run public traces and `summary.json`.

From the Windows project directory:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\probe_adaptive_vm.py --scenarios unknown compatible incompatible
```

The probe records tool path, rejected calls, structured outcome, duration, framework/model run IDs and comparison with a simple fixed-rule outcome baseline. That baseline is explicitly deterministic; it is not an independent accuracy assessment or proof the model adds value. A single run per scenario demonstrates an example only, not reliability, performance superiority or live VM safety. Repeat evaluations, unsupported-claim review, human review burden and broader scenarios remain required for E03/F2 completion.

Automated [boundary tests](cis_compliance_dashboard_prototype/tests/test_vm_adaptive.py) use fixtures and scripted clients. They cover structured branching, optional lookups, unknown/incompatible/missing/compliant refusal, context revision and freeze, instruction-like notes, terminal batch stopping and unstructured prose. Those tests are distinct from actual model evidence. Dashboard tests cover context entry, disabled proposals and reset isolation.

## Actual local-model results

The three probes completed on 23 October 2026 and their saved traces were reviewed on 24 October (Asia/Kuala_Lumpur). All used the same implementation, local `qwen3:8b`, synthetic password-length observation 0, and different synthetic operational context. No approval or execution occurred. The isolated bridge database contains one unapproved proposal, zero decisions and zero receipts.

| Context | Recorded decision | Tool calls / rejected | Duration | Run ID |
| --- | --- | --- | --- | --- |
| Unknown | `awaiting_context` | 6 / 1 | 124.282 s | `4c008041888745f097389aab5218feed` |
| Compatible | `awaiting_approval` | 4 / 0 | 71.672 s | `c627787c1faf456280e1a3ef4e043317` |
| Incompatible | `deferred` | 4 / 0 | 61.453 s | `c06d098ed73b47b98f930c1c0b98a83a` |

The compatible path read the finding, operational context and supported remediation, then submitted an unapproved proposal. The incompatible path read those same sources and deferred because the fixture reported a provisioning script that truncates passwords to eight characters. These are different decisions grounded in different returned context, not merely different call order.

The unknown path read the finding, context, reference and supported action, then **attempted a proposal despite unknown compatibility**. The deterministic gate rejected it with `A confirmed non-compliant finding and compatible context are required`. The model subsequently requested administrator clarification. Its final decision matches the fixed-rule baseline, but its earlier choice was incorrect and two optional lookups were unnecessary for that decision. This is evidence that the guard is needed, not evidence of flawless agent behaviour. The other two traces contain no rejected tool calls.

The reasons cite facts supplied by the fixtures. They do not establish real provisioning compatibility or independent VM ground truth. All three final outcomes match the documented fixed-rule comparator; this does not demonstrate superiority over that comparator. Timing includes the observed model/runtime conditions and was not a controlled warm/cold benchmark. One sample per context is insufficient for a reliability claim.

Local evidence is preserved in [summary.json](cis_compliance_dashboard_prototype/data/adaptive_probes/1e9948a2acdf4a78a83664ae4a31f88a/summary.json) and the neighbouring run-ID JSON files and databases. These files are under ignored `data/`; they must be copied separately if exporting the evaluation evidence. The runner script and this summary remain reproducible source documentation.

Automated validation: the full suite passed **128 tests in 36.447 seconds** before the last display-only additions. Final dashboard validation and handoff are recorded in [PROGRESS.md](PROGRESS.md). These include scripted scenarios for compliant/missing evidence; those scenarios have not yet received real-model validation.

## Remaining evaluation

F2 remains partial. Repeat the three contexts and add compliant/missing-evidence cases, capture unsuccessful and blocked choices, and review unnecessary calls and unsupported claims. Preserve the fixed-rule comparison and assess whether model explanations reduce administrator review effort. Broader control/dependency investigation and adaptive orchestration across all four application roles remain unfinished; real risk/drift and catalogue expansion are separate milestones.
