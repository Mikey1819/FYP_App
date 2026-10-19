# CIS Compliance Dashboard

Local Streamlit preview for a Windows Server 2022 Hardening Framework. It evaluates synthetic evidence using deterministic comparison/risk rules, stores assessment and workflow records in SQLite, and offers a bounded local `qwen3:8b` investigation loop. It does not execute PowerShell or change Windows settings.

The five controls use `DEMO-*` identifiers because their candidate benchmark references and target profile are not yet validated. Their outputs demonstrate the application logic, not verified CIS compliance on a real server.

## Run locally

1. Open PowerShell in the repository root, enter the application folder, and create a local environment if needed:

   ```powershell
   cd cis_compliance_dashboard_prototype
   py -m venv .venv
   ```

2. Install the dependency:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```

3. Start the dashboard:

   ```powershell
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

4. Open the local address shown by Streamlit, normally `http://localhost:8501`.

## Demonstrate the current workflow simulation

1. Open **Dashboard / Overview** and select **Run sample assessment**.
2. The app prepares an NLA proposal from the five saved synthetic results. It does not perform a new scan.
3. Review the calculated risk scores: NLA 85, lockout 70, and password length 56. The lockout and NLA factors both reflect regression in the synthetic history.
4. The workflow stops at **Awaiting Approval**. Select **Review remediation** and choose **Approve** or **Reject**.
5. Review the exact target, assessment, action and parameters. Enter an optional comment and choose a simulation outcome: successful verification, verification failure, execution failure, or collection error. Approve saves the decision and runs the simulation; Reject saves the decision with no executor call.
6. Return to Overview to see that the original assessment snapshot is retained and later simulated verification is reported separately. A failed verification leaves the finding unresolved.
7. Reopen the app to restore the latest saved proposal. **New demonstration** prepares the view for another proposal without deleting prior decisions. Use **Configuration Drift / Assessment History** to reopen an earlier proposal. Each fresh attempt needs its own approval.

The dashboard’s **Current device situation** and **Device security context and decision support** sections translate each sample weakness into plain language, an administrator decision, and the likely consequences of approving or delaying that decision.

The workflow activity log shows saved simulation events. The separate **Local AI investigation** panel shows real model-selected tool calls when Ollama is invoked, with model/provenance labels. Assessment evidence, risk factors, proposals, decisions, execution, verification and investigation events are persistent. The administrator identity is currently `demo-admin`; production authentication is not implemented. No Windows settings are changed.

## Demonstrate the local AI coordinator

On Overview, choose **Compatible RDP clients** or **Legacy clients need operational review**, then click **Investigate with local Ollama**. The app sends only synthetic fixture evidence to `127.0.0.1:11434` using the installed `qwen3:8b`. It does not download a model or use a cloud fallback.

The model can select six investigative tools: reference, evidence, related configuration, prior results, supported remediation and proposal submission. The application checks exact arguments and selected scope. A proposal requires the relevant evidence lookups and only permits the registered simulated NLA action. Approval and execution are excluded from the model's tools. Legacy-client fixture context blocks proposal submission pending operational review. Numeric risk scores and required assessment coverage are unchanged by the model.

The loop stops after at most 8 model requests, 10 tool calls or 240 seconds, with a 90-second request deadline. Identical repeated calls are blocked. Model errors leave the stored assessment and manual demonstration usable. Saved traces include tool results and concise public summaries; raw model thinking is discarded. A failed/interrupted investigation remains labelled as such.

For a reproducible local integration check from the repository root:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\probe_investigation.py --scenario compatible_clients
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\probe_investigation.py --scenario legacy_clients
```

These commands make real local model calls and save traces to the ignored application `data/investigation_probe.sqlite3` and `data/probe_*.json`. They never approve or execute a proposal. Normal unit tests mock the model and do not call Ollama. The client follows Ollama's [tool-calling protocol](https://docs.ollama.com/capabilities/tool-calling) and [chat API](https://docs.ollama.com/api/chat).

## Stored assessment evidence

The dashboard uses `cis_compliance_dashboard_prototype/data/preview.sqlite3`, created automatically on first launch and ignored by Git. It seeds two explicitly synthetic historical snapshots (1041 and 1042) once, then reads assessment, risk and history views from the database. Replaying the sample workflow does not collect new evidence or create a new assessment. The sample dates remain fixture dates, not today's scan time.

Each saved snapshot preserves the comparison rules, source references, typed evidence, timestamps, result status, risk inputs and the historical assessment used for drift. New history does not rewrite a saved score. Conflicting reuse of an assessment ID is rejected. An unsupported database schema displays a storage error rather than resetting saved data.

For a separate local demo database, set `$env:CIS_DASHBOARD_DB` to an explicit file path before starting Streamlit. Tests use temporary databases and do not modify your saved demonstration data. To preserve a backup, stop the app and copy the database file; it includes workflow and investigation records. Schema versions 1/2 upgrade additively to version 3 without rewriting assessments.

Approval is bound to one saved proposal and can be consumed only once. The app records an execution attempt before invoking its simulator. If the process is interrupted after that point, the outcome can remain unknown or verification unavailable; reopening the app never automatically repeats the write. Review the saved record before preparing a new demonstration. If approval was saved but no execution attempt began, **Run approved simulation** can continue that exact proposal once.

## Run checks

For the new standalone VM collection/import stage, follow [VM_EVIDENCE.md](VM_EVIDENCE.md). The guarded PowerShell script runs inside the lab VM; its offline Python inspector runs on the laptop. This path is fixture-tested and remains separate from the dashboard database until real evidence/manual checks are completed. See [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md) for the five source-reviewed rules and current limitations.

From `cis_compliance_dashboard_prototype`:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

The suite checks comparison boundaries, missing/failed/malformed evidence, history compatibility, risk factors and thresholds, SQLite recovery in a separate process, schema migration, overwrite protection, concurrent duplicate saves/execution, exact approval binding, rejected writes, failed verification, interrupted execution, and the six-view Streamlit workflow. No test changes Windows configuration.

## Contents

- `cis_compliance_dashboard_prototype/app.py` - the Streamlit prototype and representative data.
- `cis_compliance_dashboard_prototype/hardening/domain.py` - typed evidence, comparison, coverage, history and risk rules, independent of the UI.
- `cis_compliance_dashboard_prototype/hardening/demo.py` - labelled fixtures and calculated display data with candidate source references.
- `cis_compliance_dashboard_prototype/hardening/demo_context.py` - fixed explanatory text for the demonstration.
- `cis_compliance_dashboard_prototype/hardening/storage.py` - versioned SQLite assessment snapshots, persisted risk inputs and compatible history lookup.
- `cis_compliance_dashboard_prototype/hardening/demo_storage.py` - explicit fixture seeding and dashboard projections from saved evidence.
- `cis_compliance_dashboard_prototype/hardening/workflow.py` - validated proposals, durable decisions, one-shot simulated execution and independent read-back.
- `cis_compliance_dashboard_prototype/hardening/workflow_schema.py` - additive SQLite workflow tables and audit-record protection.
- `cis_compliance_dashboard_prototype/hardening/investigation_tools.py` - exact-schema permitted investigative tools and proposal prerequisites.
- `cis_compliance_dashboard_prototype/hardening/investigation.py` - bounded model/tool loop and saved investigation events.
- `cis_compliance_dashboard_prototype/hardening/ollama_client.py` - fixed loopback-only client, request limits and thinking exclusion.
- `scripts/probe_investigation.py` - real local model checks using synthetic evidence only.
- `scripts/rehearse_preview.py` - opt-in timed UI rehearsal with real local model calls, simulated actions, restart verification and incremental evidence.
- `cis_compliance_dashboard_prototype/tests/` - domain and Streamlit integration checks.
- `cis_compliance_dashboard_prototype/screenshots/` - placeholder directory; no PNG captures are currently checked in.
- `AGENTS.md` - development instructions and scheduled-run boundaries.
- `DEVELOPMENT_PLAN.md` - architecture, milestones, acceptance criteria, and completion rules.
- `PROGRESS.md` - current handoff, verified environment, test evidence, and open dependencies.
- `TEACHER_PREVIEW.md` - teacher walkthrough, failure demonstration and backup instructions.
- `REHEARSAL_RESULT.md` - passed technical rehearsal, saved backup, measured timings and untested visual/live boundaries.
- `LIVE_VALIDATION_PLAN.md` - proposed standalone lab, matching benchmark decision, future device eligibility and real-evidence checklist.
- `BENCHMARK_MAPPING.md` - source-reviewed Stand-alone v2.0.0 five-control subset, audit locations and manual validation.
- `VM_EVIDENCE.md` - Guest Additions/shared-folder setup, read-only collector and offline inspection instructions.
- `scripts/Collect-Server2022Evidence.ps1` - guarded VM-only configuration export; no hardening commands.
- `scripts/inspect_server_evidence.py` - validates and evaluates transferred JSON; no dashboard database writes.
- `hardening/server2022_catalogue.py` and `hardening/evidence_import.py` (under the application folder) - reviewed catalogue and strict offline import boundary.
- `LOCAL_MODEL_VALIDATION.md` - actual two-scenario local model traces, measured timings and retained failure evidence.
- `scripts/development_guard.py` - cooperative overlap protection for development runs.

## First preview preparation

The teacher preview is **22 October 2026**. The delivery target is **21 October 2026, 23:59 Malaysia time**. The synthetic application is **DEMO_READY** following a 137.547-second automated technical walkthrough. A visual browser check, spoken presentation practice and validated benchmark/server evidence remain outstanding. The current application uses synthetic evidence and simulated execution with real local model investigation; PREVIEW_COMPLETE is not set.

**Initial-preview acceptance progress: 10/11 criteria supported = 90.9% (about 91%).** This counts A01-A10 equally; A11 (validated baseline and real-server evidence) remains pending. It is not a percentage of engineering effort or the entire FYP, and the remaining criterion may involve substantial work. See PROGRESS.md for evidence and LIVE_VALIDATION_PLAN.md for the next stage.

Ollama was confirmed on this laptop with `qwen3:8b` installed. A real multi-step investigation succeeded on 18 October 2026. No model training is planned. Read PROGRESS.md for the measured timings and acceptance status; availability is not assumed between runs.

Scheduled runs should use this same repository checkout, read the three planning files, acquire the development lock, complete the next bounded task, run relevant checks, update the progress log, and release their own lock. During active work, save a progress checkpoint at least every two minutes with unfinished work and the exact next action. If another run holds the lock, skip. Real Windows hardening must never target the development laptop.

The user has installed a standalone Windows Server 2022 Standard Evaluation VM (64-bit, build 20348), shown in a screenshot, and confirmed creating its clean snapshot. Five mappings are now source-reviewed against the supplied Stand-alone v2.0.0 PDF. Real VM collection, independent manual comparison, transfer setup and dashboard integration remain pending; see VM_EVIDENCE.md. Future physical/VM support depends on matching the OS and role to a reviewed catalogue; this preview does not support arbitrary Windows devices. The schedule itself is managed in the desktop app; these files neither activate it nor guarantee that a run will have usage allowance available.
