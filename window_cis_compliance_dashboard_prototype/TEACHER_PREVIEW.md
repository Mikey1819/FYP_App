# Initial teacher preview walkthrough

This is a local development preview. The dashboard's five rules and server evidence are **synthetic and benchmark-unverified**. Ollama investigation is real when explicitly run; configuration changes are simulated. A standalone Server 2022 VM is installed per the user's screenshot, with a clean snapshot user-confirmed. A separate five-control Stand-alone v2.0.0 catalogue has now been source-reviewed and a read-only collector/importer prepared. Actual VM evidence/manual comparison and dashboard integration remain pending; see VM_EVIDENCE.md. Do not present the existing 40% demo score as this VM's posture.

## Preparation

1. Launch Streamlit using README's commands and leave local Ollama running with `qwen3:8b` available.
2. Use a separate rehearsal database if you want to keep prior demonstration history untouched. Set `$env:CIS_DASHBOARD_DB` to a new local file before starting Streamlit.
3. Explain the architecture: deterministic assessment/risk rules, one AI investigator, permitted tools, explicit administrator decision, separate execution and verification.

## Walkthrough

1. **Overview and Assessment Results:** show the fixed scope of five controls, 5/5 evaluated coverage, synthetic sources and 40% original compliance. Explain that the model cannot omit checks or alter the numeric scores.
2. **Risk Details:** select lockout and show score 70 and D=5 from a prior compliant snapshot. NLA is 85; these are project-defined scores, not CIS/CVSS values.
3. **Real investigation:** on Overview select Compatible RDP clients and click Investigate with local Ollama. Open the saved tool evidence. Explain that each returned result is fed back to the model, which chooses another tool or concludes. The model may prepare a proposal; it cannot approve it.
4. **Contrasting context:** repeat with Legacy clients need operational review. Show the returned compatibility evidence and whether the model stops for review. If a run is blocked or times out, show its actual status; do not claim a saved previous trace is the current run.
5. **Rejection:** open an undecided proposal, enter a comment and Reject. Show the durable rejection and absence of any execution event.
6. **Approval and verification:** start New demonstration, prepare another proposal, and select Successful verification. Approve and show separate execution and read-back evidence. Return to Overview: the original 40% snapshot remains historical, while the selected verification is displayed separately.
7. **Failure case:** start another demonstration and select Verification failure. Execution reports success, but the unchanged read-back fails the rule. Show that the finding stays unresolved and approval cannot be reused.
8. **History and restart:** reopen a saved proposal from history. Restart/reopen the app and show that its decision/comment/outcome persists. A claimed but interrupted execution is never retried automatically.

## What makes this agentic

The model chooses investigative tools, observes their results and selects subsequent actions within a bounded loop. Deterministic services enforce scope, comparison rules, risk arithmetic and approval. Those services are tools, not independent AI agents. Model training is unnecessary for this workflow.

## Progress and device scope to explain

"The initial preview has evidence for 10 of its 11 acceptance criteria, about 91% by checklist count. The remaining criterion is validated CIS mappings and real-server evidence. This percentage does not measure completion of the whole FYP or remaining work. The working demonstration uses synthetic server evidence, a real local AI investigator and simulated configuration changes."

"The eventual design can support physical computers and VMs, but each OS and machine role needs a matching reviewed catalogue. Our standalone Server 2022 lab is installed, with a clean snapshot reported. Its real security settings have not yet been assessed by the application. Applying a Server benchmark to an arbitrary Windows laptop would not establish compliance."

See LIVE_VALIDATION_PLAN.md for the proposed standalone benchmark decision and the steps to collect and independently verify real evidence. Browser visual QA and spoken practice remain outstanding even though the automated technical walkthrough passed.

## Timing and backup

The automated technical walkthrough passed on 18 October in **137.547 seconds**, including two real local model investigations through the dashboard. See REHEARSAL_RESULT.md for step timings, evidence and limits. This is software runtime, not a timed spoken presentation. The loop has a 240-second budget and a 90-second request deadline, so allow time for model loading. Fixture loading and simulated verification are not measurements of real Windows scanning/hardening performance. A visual browser check and your own spoken rehearsal are still needed before presenting.

To reproduce the automated rehearsal from the repository root:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\rehearse_preview.py --live-model
```

This creates a fresh directory under application `data/rehearsals/`, makes real local model calls, exercises simulated decisions and saves a JSON report after each step. A failed/interrupted run keeps its partial evidence and is not silently retried. It never accesses a live Windows Server or changes the laptop's configuration.

Local integration traces live in `cis_compliance_dashboard_prototype/data/investigation_probe.sqlite3` and `probe_*.json`. To display those saved runs, point `CIS_DASHBOARD_DB` at that database before launch. Label this as viewing a previous run. Keep original probe records unmodified if using them as validation evidence; use a copy for approval demonstrations.

For a complete captured workflow including rejection, approval, failure and fallback, use the rehearsal database and instructions in REHEARSAL_RESULT.md.

No live remediation, production authentication, arbitrary PDF ingestion, trained model or full 30/36-control catalogue is claimed for this preview.
