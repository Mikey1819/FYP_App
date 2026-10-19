# First system preview development plan

## Outcome and deadline

Prepare a demonstrable Windows Server CIS assessment application with a real local AI investigation loop for the teacher preview on **22 October 2026**. Finish implementation and verification by **21 October 2026, 23:59 Asia/Kuala_Lumpur**, leaving rehearsal time earlier on 21 October.

This is an initial preview, not completion of the entire FYP. The final report's minimum 30 controls and proposed 36-control catalogue remain later milestones.

## Confirmed inputs

- Existing application: `cis_compliance_dashboard_prototype/app.py`, a six-view Streamlit prototype with five synthetic controls and simulated approval/verification.
- Report reference: `C:\Users\User\Downloads\RIS_KhooTengYi_Report.docx`.
- User agreed to fixed validated CIS rules, deterministic checks, and a bounded AI coordinator with adaptive tool use. Model training is unnecessary for the preview.
- User confirmed Ollama runs on the laptop. On 17 October, its local API reported version `0.40.5` and installed `qwen3:8b` (Q4_K_M, 8.2B, tool capability advertised).
- Development is local. Real Windows hardening of the host laptop is prohibited.

## Decisions still needed

| Dependency | Current status | Independent work allowed |
| --- | --- | --- |
| Windows Server test VM and role | 19 October screenshot: Server 2022 Standard Evaluation x64, build 20348, standalone (PartOfDomain=False, DomainRole=2); user confirms clean snapshot | Prepare collection interface; machine-readable identity and real control evidence still needed |
| Exact benchmark PDF, edition and profile | Stand-alone v2.0.0 supplied; five selected mappings reviewed under its exact Level 1 - Member Server label; see BENCHMARK_MAPPING.md | Validate collection/manual agreement on VM; retain separate synthetic catalogue |
| Target access method | Proposed VirtualBox Guest Additions shared folder FYP-Exchange; user needs setup help, not yet confirmed working | VM_EVIDENCE.md and guarded collector ready; do not assume WinRM or expose a service |
| One live remediation and test window | Not selected/authorized | Build proposal, approval, simulated executor, and verification contracts |

These block live validation, not all implementation. Save concrete questions and continue other work. The report is a design reference, not proof that all listed identifiers and comparison values are correct.

See [LIVE_VALIDATION_PLAN.md](LIVE_VALIDATION_PLAN.md) for the baseline decision, proposed read-only import milestone and future device eligibility checks. The user's eventual physical/VM Windows support objective does not expand the first preview beyond one validated Server 2022 target. Client Windows versions need their own reviewed catalogues; no current multi-platform support is claimed.

## Architecture

1. Streamlit starts an assessment with a fixed selected scope and shows stored results.
2. Collectors obtain typed evidence. A deterministic evaluator applies the reviewed catalogue's comparison and applicability rules.
3. SQLite stores immutable assessment results, evidence provenance, errors, and benchmark/target metadata.
4. The risk engine calculates factor scores from explicit rules/baselines and applies `R = 6I + 5E + 4P + 3L + 2D`.
5. A local Qwen3 coordinator receives findings and a constrained tool catalogue. It selects an investigative tool, observes the returned evidence, and chooses the next step until a proposal, useful conclusion, or bounded stop.
6. A deterministic controller validates proposals and binds the administrator's decision to the exact proposed action. Approved execution is followed by deterministic reassessment.
7. The dashboard displays evidence, concise action reasons, model/tool events, decisions, verification, and history.

One LLM coordinator is sufficient. Scanner, risk, storage, and executor components are deterministic services/tools. Do not add multiple independent LLM agents for appearance.

Suggested tools: `get_control_reference`, `get_finding_evidence`, `inspect_related_configuration`, `get_previous_results`, `get_supported_remediation`, and `submit_remediation_proposal`. IDs and arguments must be validated. Tool names are design proposals, not existing implementation.

The required scan coverage is fixed by the administrator's selected scope, even if the model stops early. The agent can choose supplementary investigation; it cannot suppress failed checks, invent a score, or grant itself approval.

## Benchmark and evidence preparation

Start with about five representative controls, subject to the confirmed benchmark and target. The existing sample topics are password length, account lockout threshold, Guest account status, firewall state, and RDP NLA. They are candidates, not yet a validated catalogue.

Each control needs version/profile, exact source ID/title/section, applicability, typed expected value and comparison operator, collector reference, source rationale, fixed risk baselines, and supported remediation/verification references. Numeric minima and permitted ranges must not become string-equality checks.

Initially use direct reference lookup by control ID. Arbitrary PDF ingestion, vector databases, automatic activation of extracted rules, and model training are deferred. When the benchmark is unavailable, use clearly labelled demo identifiers/rules; do not present guessed mappings as verified CIS compliance.

Existing discrepancies to resolve:

- Guest sample ID `CIS-2.3.1` differs from report Table 3.2's `2.3.1.1`.
- NLA sample ID `CIS-18.9.1` differs from Table 3.2's `18.10.57.3.9.4`.
- Lockout sample history shows compliant-to-non-compliant drift but factors use D=1. Under the report's rubric D=5 yields 70, not 62, with other factors unchanged.
- Original scan results must remain distinguishable from the later successful verification.
- Review comments currently are not used in the decision record.

For an initial deterministic drift rule, propose D=1 for no comparable history, D=5 for compliant-to-non-compliant regression, and D=3 for previous/current non-compliance (including a changed value). This extends the report's incomplete case coverage and must be labelled an implementation decision. Score only valid non-compliant findings. Store improvements and other changes separately from regressions.

Exposure rules need observable inputs or explicit administrator-provided context. Local RDP/firewall settings do not prove internet reachability. Unknown context must be visible rather than invented. Risk categories are project-defined priorities, not CIS/CVSS scores or probabilities.

## Ordered backlog

Dates are targets, not permission to claim unfinished work is complete. Update status in PROGRESS.md rather than silently expanding scope.

| ID | Target | Deliverable and completion evidence |
| --- | --- | --- |
| P0 | 17 October | Save instructions, plan, progress, overlap guard; verify local model availability and baseline UI |
| P1 | 18 October | Extract typed domain/configuration models and deterministic rules from the UI; validate comparison/error cases and correct sample consistency |
| P2 | 18-19 October | Add SQLite persistence for assessments, findings, history, risk inputs, agent events, proposals, approvals, executions and verification; prove restart/retrieval |
| P3 | 19-20 October | Integrate real local model tool loop with validation, limits, fallback, and two evidence-dependent investigation scenarios |
| P4 | 20 October | Connect proposal, approve/reject, simulated executor, and independent verification; test rejection, duplicate reruns, execution failure, and failed verification |
| P5 | 20-21 October | Connect validated controls to the confirmed test VM or imported real evidence; document provenance; exercise one approved live action only if authorized |
| P6 | 21 October | Integrate six UI views, run acceptance checks, prepare teacher walkthrough and backup demonstration; freeze working preview |

P5 can proceed alongside P3/P4 when the external dependencies arrive. If time becomes tight, reduce optional polish and live remediation breadth, not evidence accuracy or approval enforcement.

## Acceptance criteria

Every checked item needs a command, saved result, or reproducible walkthrough recorded in PROGRESS.md or a linked validation record.

| ID | Required observable result |
| --- | --- |
| A01 | App launches from documented commands; six views work; actual backend/model/evidence mode and selected target are visible |
| A02 | About five selected checks have typed evidence, expected rule, status, timestamp and provenance; coverage/errors are displayed; fixtures are labelled |
| A03 | Comparison and risk tests cover boundaries and invalid/missing evidence; the same valid inputs reproduce the same score; the model cannot alter it |
| A04 | Assessment results survive process restart; history compares compatible target/control/version/profile results; verification does not overwrite original evidence |
| A05 | Real `qwen3:8b` responses choose permitted tools and receive their results; at least two different evidence scenarios produce meaningful differing investigative calls; record actual traces |
| A06 | Unknown tools/invalid arguments/out-of-scope targets are rejected; repeated calls and overall steps are bounded; model timeout/unavailability leaves deterministic assessment usable |
| A07 | A proposal identifies target, finding, action and parameters; rejection records the decision and causes zero executor writes; approval cannot be reused for another action or a duplicate rerun |
| A08 | A successful command alone is insufficient: verification reruns the comparison; failures remain unresolved and require a new approval before another write; simulated execution is labelled |
| A09 | Agent events show tools, returned evidence references and short decision summaries; no fabricated logs, claims of live scans, or raw model thinking are required |
| A10 | Teacher walkthrough covers assessment, risk, adaptive investigation, rejection, approval/verification and history; run timings and tested/untested boundaries are recorded |
| A11 | Exact baseline/profile and mappings are checked against the source; real Windows Server evidence is compared with independent manual checks for the selected controls; collect target identity and method |

A05 cannot be satisfied by scripted replay or only a forced single-tool probe. Demonstrate model selection among multiple useful tools after observing results. Test synthetic cases first; label them. If the local model cannot do this reliably, report the limitation and retain the working deterministic demo rather than relabelling it agentic.

Measure scan/verification time separately from LLM investigation. Record the report's ten-minute requirement against the actual test scope. Do not advertise the report's preliminary 12-second explanation measurement as a guarantee.

## Completion and deadline behavior

- `IN_PROGRESS`: Implementation or required verification remains.
- `DEMO_READY`: A01-A10 pass using explicit fixtures and/or simulated execution, but A11 is unresolved. This is useful for rehearsal, not verified live CIS assessment.
- `LIVE_PREVIEW_READY`: A01-A11 pass. Execution may remain explicitly simulated if live execution was not authorized; state this limitation in the teacher walkthrough.
- `PREVIEW_COMPLETE`: Set only after LIVE_PREVIEW_READY and a successful rehearsal, or after the user explicitly accepts DEMO_READY as the preview deliverable. List any accepted limitations.
- `DEADLINE_HANDOFF`: Deadline reached with unmet criteria. Preserve the working demo, report gaps, and stop unattended feature changes pending user direction. Do not mark success merely because time ran out.

After PREVIEW_COMPLETE or DEADLINE_HANDOFF, scheduled runs make no development changes unless the user gives further direction. The plan cannot itself disable a scheduler; runs must honor this stop condition.

## Teacher demonstration

1. Explain fixed CIS requirements and the AI's bounded investigative role.
2. Show selected target, baseline and evidence mode; run the selected assessment.
3. Open one finding and trace observed value, comparison and risk factors.
4. Show two situations that lead the real coordinator to different investigative tools.
5. Reject a proposal and show zero execution; approve a supported proposal and show separate execution and verification results.
6. Show history and explain precisely which parts are live, imported, simulated, or unfinished.

Prepare a short backup walkthrough with captured results, clearly marked as a previous run. Do not replace a failed live model call with a prerecorded trace without disclosure.

## References

- Report: local DOCX path above; Chapters 3-4 define scope and initial design. The later conversation authorizes an investigative AI coordinator beyond the report's explanation-only LLM role.
- CIS editions: https://www.cisecurity.org/benchmark/microsoft_windows_server
- Ollama tools: https://docs.ollama.com/capabilities/tool-calling
- Ollama local/cloud behavior: https://docs.ollama.com/faq

No report rewrite, benchmark download, server configuration change, or cloud model migration is part of this preparation step.
