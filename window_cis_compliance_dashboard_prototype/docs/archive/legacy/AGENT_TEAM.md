# AI hardening agent team

> **Archived 26 October 2026.** Describes the legacy **Evidence upload** page (manual file exchange and the earlier agent team), not the current agentic framework. Current design: [ARCHITECTURE.md](../../../ARCHITECTURE.md); current status: [PROGRESS.md](../../../PROGRESS.md).

The normal dashboard now offers **Run multi-agent hardening review** after uploading and assessing VM evidence. Four isolated model conversations use the existing local qwen3:8b model. Separate model downloads or processes are not required for separate agent responsibilities.

| Agent | Responsibility | Permitted decisions/tools |
| --- | --- | --- |
| AI Agent Orchestrator | Delegate from specialist outcomes | Delegate Scanner, Analysis or Remediation; finish the team review |
| Scanner Agent | Validate imported evidence and assess collection quality | Revalidate coverage, inspect observations, hand off to Analysis or request recollection |
| Analysis Agent | Interpret fixed findings and operational context | Read findings/references/context, hand off an eligible finding, request human review or conclude all checks compliant |
| Remediation Agent | Prepare a supported change proposal | Independently read finding/context/action; propose, defer or request clarification through existing guarded lifecycle |

Each agent has its own system instructions, conversation, tool allowlist, task trace and terminal decision. The orchestrator receives structured handoffs, not the specialists' private conversations. Calls are model-selected; prerequisites are enforced in code. A model cannot skip Scanner/Analysis prerequisites, turn unsupported findings into actions, approve a proposal or execute a command. The same selected evidence hash, target, framework run and context revision bind every task.

PowerShell remains a restricted collection/execution tool. It does not perform the AI decision-making. With the [Scanner connection](SCANNER_CONNECTION.md), recollection queues a fixed read-only job for a bounded worker started inside the registered VM. The team waits for evidence; a returned response creates a new assessment for review. Without a running worker, the request remains pending/expired. A real VM trial is pending. Remediation currently supports one executable action, minimum password length to 14, followed by separate human approval and VM execution. Other non-compliant controls remain unresolved even if this proposal succeeds.

Model roles are separate from the existing deterministic `agents.py` assessment stages. Deterministic services remain authoritative for compliance and capability checks. No real-evidence numeric risk scoring, autonomous target discovery, arbitrary command execution or full 30-control coverage is claimed.

## Records and failures

Public request/tool/rejection/terminal events are stored in the bridge database with `agent_role`, `team_id`, `framework_run_id`, incoming handoff and context metadata. Existing immutable-record guards apply. The dashboard recovers the current test's latest team traces from storage. Incomplete/interrupted tasks are labelled; a child without a structured terminal decision cannot authorize the next specialist. A stopped team can be reviewed and a new review started; automatic task resumption is not implemented.

Team status summaries are derived from validated workflow outcomes, not model prose. Raw model commentary remains in the audit as unverified text. This separation addresses an actual trial where the orchestrator falsely described an unapproved proposal as an executed change. Analysis now receives observed values and required rules in separate fields. These measures protect workflow reporting; they do not prove every model-authored explanation is factually correct.

One team run is bounded to five minutes. Each specialist is bounded to six model steps and ten calls, with at most 100 seconds or the remaining team budget. Tool repeats, role violations and stale context are rejected. Timeouts/model failures leave deterministic assessment available and do not authorize writes.

## Verification

`tests/test_agent_team.py` covers separate conversations, guarded handoffs, compliant/missing/unknown/incompatible branches, unavailable models, cross-role tools, context revisions and persistent unapproved proposals using scripted models. The UI test runs the team button and checks the four role records and unapproved result. These tests establish contracts, not real model reliability.

For an actual local-model trial using synthetic evidence only:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B scripts\probe_agent_team.py
```

The probe writes isolated databases and traces under ignored `data/team_probes/`. It never runs a collector or executor on the host/VM. Actual observations and limitations belong in the dated PROGRESS.md handoff.
