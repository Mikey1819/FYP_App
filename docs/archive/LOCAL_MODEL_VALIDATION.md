# Local model investigation validation - 18 October 2026

Executed using the existing project virtual environment, local Ollama and installed `qwen3:8b`. All assessment/context evidence was synthetic; no server was contacted. No approval, executor or shell tool was exposed to the model.

## Final same-version comparison

Both final runs used the same coordinator prompt, client, tool definitions and stored assessment. The named synthetic client-compatibility context differed.

| Scenario | Run ID | Outcome | Model-selected tools in order | Duration |
| --- | --- | --- | --- | --- |
| Compatible clients | `aefc85ad0aef4c7db64f6c4b6ffb4b8c` | Completed; proposal saved for review | reference, evidence, related configuration, supported remediation, submit proposal | 62.625 seconds |
| Legacy clients | `a3033c5345ca4c4d82856ddecc67fb4f` | Completed; operational review required, no proposal | reference, evidence, related configuration, prior history, supported remediation | 40.281 seconds |

The compatible run saved proposal `002aa9b11756472ab2e6e81d38f199e4`, targeting assessment 1042 / DEMO-SERVER-2022 / DEMO-NLA / DEMO-ENABLE-NLA with `{"required": true}`. It remains awaiting approval. The legacy run looked up history and concluded that compatibility review was required. The supported-action tool returned no eligible action in that context; code also enforces this condition if the model tries to submit anyway.

Each model response selected a tool from the offered catalogue; the coordinator supplied its actual result in the following request. These are real model traces, not a scripted replay or a forced single-tool probe. The run summaries are model-generated explanations, not authority to execute or verified descriptions of a real server.

## Earlier attempts retained

- Compatible run `a06be452c0294690b13e5697f6180a48`: completed in 75.047 seconds with five tools and an undecided proposal.
- First legacy run `780e40d043d942feb3d5099818b65349`: stopped after 80.000 seconds and two rejected submission attempts. The first had invalid arguments; the second was blocked by compatibility policy. No proposal was saved. This failure led to a clearer `proposal_allowed` result and eligible-action lookup before the final pair above. It is not counted as a successful investigation.

## Reproduce and inspect

From the repository root:

```powershell
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\probe_investigation.py --scenario compatible_clients
.\cis_compliance_dashboard_prototype\.venv\Scripts\python.exe -B -u scripts\probe_investigation.py --scenario legacy_clients
```

Saved local database: `cis_compliance_dashboard_prototype/data/investigation_probe.sqlite3`. Final trace exports include `probe_compatible_clients_aefc85ad0aef4c7db64f6c4b6ffb4b8c.json` and `probe_legacy_clients_a3033c5345ca4c4d82856ddecc67fb4f.json` in the same directory. The first two exports retain their original scenario-only filenames. These runtime artifacts are intentionally ignored by Git; copy them with the database for a local backup.

Probe database audit: two assessment snapshots, two undecided proposals, four investigation runs and zero decision/attempt/execution events. No probe approved or executed an action.

## Automated checks and limits

The full suite passed **55 tests in 11.076 seconds**. After the eligibility clarification, the eight investigation tests passed in 0.322 seconds. After the final UI selection change, all six Streamlit tests passed in 8.623 seconds. Tests cover exact approval binding, rejected writes, restart/concurrency protection, independent failed verification, invalid model calls, scope enforcement, bounded loops, model outage, protocol validation and omission of raw thinking.

This supports A05 for these two synthetic scenarios, A06 for the tested boundaries and A09 for real recorded tool activity. It does not establish general model reliability, live CIS compliance or the ten-minute real-server scan requirement. Timings include the investigation only; cold/warm state and competing laptop work can change latency. A later automated technical walkthrough is recorded in REHEARSAL_RESULT.md. Spoken presentation practice, browser visual QA and validated server/benchmark evidence remain outstanding.
