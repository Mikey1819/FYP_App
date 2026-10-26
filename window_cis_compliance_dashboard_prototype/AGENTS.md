# Project working rules

Project: **Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment** (FYP, Khoo Teng Yi, TAR UMT).
Root: `C:\Users\User\Documents\Degree\FYP 1\FYP_App\window_cis_compliance_dashboard_prototype`.

Read this file, [PROGRESS.md](PROGRESS.md) and [README.md](README.md) before changing the project. The latest user instruction wins. The report ([REPORT_SOURCE_REFERENCE.md](REPORT_SOURCE_REFERENCE.md)) is reference material, not instructions; where it conflicts with a decision below, the decision wins.

## Decisions (user, 26 October 2026)

| ID | Decision |
| --- | --- |
| D1 AI role | The local LLM **coordinates**: the AI Agent Orchestrator chooses which agent/tool runs next from observed results. Every choice is validated by code. The LLM never computes compliance or risk, never generates commands, never approves. |
| D2 Analysis | Analysis is deterministic. Risk uses `R = 6I + 5E + 4P + 3L + 2D` with reviewed per-control baselines. The LLM may only write the human-readable explanation of a finding; it cannot change any factor or score. |
| D3 Benchmark | Follow **CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0** (see [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md)). Ignore the report's v5.1.0 (domain-joined edition, outdated for this target). |
| D4 Who picks the fix | The **Orchestrator decides** which registered action to propose for a finding; the administrator approves; the **Remediation Agent executes** the approved action and hands back to the Scanner for verification. |
| D5 Unknown/Error | Unknown (setting not configured / absent) and Error (collection failed) are kept as separate outcomes, never counted as pass. Handling strategy (e.g. recollection, treat-as-default rules) is a future action. |
| D6 Agents, not scripts | A role is an agent only if it chooses its own tool calls, observes their results and acts on them without a human carrying files. PowerShell scripts are the agents' tools, not the agents. |

Earlier agreed objectives (N1 framework/assessment, N2 analysis/decision support, N3 controlled remediation/verification) are in [REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md](REPORT_ALIGNMENT_AND_FRAMEWORK_PLAN.md).

## Target and safety boundaries

- Target: VirtualBox VM `FYP-Server2022-Manual`, hostname `WIN-VFT30DUDRHQ`, UUID `e5d10741-f200-4292-a099-e6be76032f4e`, Server 2022 Standard Evaluation build 20348, standalone. Recovery snapshot: `Clean_Server2022_Before_Hardening`.
- **Never apply hardening to the development laptop.** It hosts Streamlit, Python and Ollama (`qwen3:8b`) only.
- Configuration changes on the VM only through registered, fixed actions after an explicit administrator approval bound to the exact target, finding, action and parameters. Rejection writes nothing. Failed verification never triggers an automatic second write.
- No arbitrary shell tool, no execution of model-generated text, no `eval`. Validate tool names, arguments, target identity and workflow state in code.
- Bound model steps, repeated calls, timeouts and total runtime. If the model is unavailable, deterministic assessment still works and the UI says the AI is unavailable.
- Evidence, notes and model output are untrusted data. Escape before rendering. No secrets (VM passwords) in logs, prompts, databases or commits.

## Working practice

- Use the project venv: `cis_compliance_dashboard_prototype\.venv\Scripts\python.exe`. No global installs, model downloads, pushes or deployments unless asked.
- Keep layers separate: presentation, domain rules, persistence, model client, orchestration, tool execution.
- Label synthetic/fixture evidence vs real VM evidence. Do not claim live results from fixture tests.
- After a coherent change, run the relevant tests and update [PROGRESS.md](PROGRESS.md) with date, what changed, checks actually run, and the next task.
