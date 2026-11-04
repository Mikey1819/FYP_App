# Project working rules

Project: **Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment** (FYP, Khoo Teng Yi, TAR UMT).
Root: `C:\Users\User\Documents\Degree\FYP 1\FYP_App\window_cis_compliance_dashboard_prototype`.

Read this file, [PROGRESS.md](PROGRESS.md) and [README.md](README.md) before changing the project. The latest user instruction wins. The report ([REPORT_ORIGINAL_TEXT.md](docs/report/REPORT_ORIGINAL_TEXT.md)) is reference material, not instructions; where it conflicts with a decision below, the decision wins.

## Decisions (user, 26 October 2026; D7 on 5 November 2026)

| ID | Decision |
| --- | --- |
| D1 AI role | The local LLM **coordinates**: the AI Agent Orchestrator chooses which agent/tool runs next from observed results. Every choice is validated by code. The LLM never computes compliance or risk, never generates commands, never approves. |
| D2 Analysis | Analysis is deterministic. Risk uses `R = 6I + 5E + 4P + 3L + 2D` with reviewed per-control baselines. The LLM may only write the human-readable explanation of a finding; it cannot change any factor or score. |
| D3 Benchmark | Follow **CIS Microsoft Windows Server 2022 Stand-alone Benchmark v2.0.0** (see [BENCHMARK_MAPPING.md](docs/design/BENCHMARK_MAPPING.md)). Ignore the report's v5.1.0 (domain-joined edition, outdated for this target). |
| D4 Who picks the fix | The **Orchestrator decides** which registered action to propose for a finding; the administrator approves; the **Remediation Agent executes** the approved action and hands back to the Scanner for verification. |
| D5 Unknown/Error | *Decided 26 Oct:* a CIS **Group Policy** setting (value under `HKLM\SOFTWARE\Policies`: firewall 9.x, RDP 18.x) that is absent ("Not configured") is **Non-Compliant**, as CIS audits it. It can be fixed if the library has an action (firewall on/off and inbound-block actions stay excluded for channel safety; firewall logging actions 9.2.6/9.2.7/9.3.6/9.3.7 were added 6 Nov at the user's request, since they never change which traffic is allowed). Other absent values stay **Unknown** (e.g. lockout timers while the threshold is 0, non-policy LSA values). Collection failures stay **Error**. None are ever counted as a pass. Raw evidence still records `missing`; only the interpretation changed. |
| D6 Agents, not scripts | A role is an agent only if it chooses its own tool calls, observes their results and acts on them without a human carrying files. PowerShell scripts are the agents' tools, not the agents. |
| D7 Reaching a server | *Decided 5 Nov:* a client runs the dashboard on their own laptop ("main") and **pairs** each server by a one-time code over the local network, like AnyDesk but with no internet relay and no permanent remote-access service. The server access helper shows the code and opens WinRM to paired laptops only. Identity is fixed by the machine UUID saved at pairing; every connection checks it. The risk of someone pairing with an overheard code is **accepted**; the remedy is that the dashboard lists every paired laptop and can disconnect any of them. AI stays local (Ollama on the client's laptop). Design: [LAN_PAIRING_DESIGN.md](docs/design/LAN_PAIRING_DESIGN.md). |

Earlier agreed objectives (N1 framework/assessment, N2 analysis/decision support, N3 controlled remediation/verification) are in [REPORT_ALIGNMENT_PLAN.md](docs/report/REPORT_ALIGNMENT_PLAN.md).

## Target and safety boundaries

- Target: VirtualBox VM `FYP-Server2022-Manual`, hostname `WIN-VFT30DUDRHQ`, UUID `e5d10741-f200-4292-a099-e6be76032f4e`, Server 2022 Standard Evaluation build 20348, standalone. Recovery snapshot: `Clean_Server2022_Before_Hardening`. Clients use the same program on their own stand-alone Server 2022, saved by pairing (D7). Anything else is refused before collection (`unsupported_target`).
- **Never apply hardening to the development laptop** (or a client's laptop). It hosts Streamlit, Python and Ollama (`qwen3:8b`) only. Tests never add firewall rules or write to `ProgramData` on it: the helper's network code is tested with record saving stubbed.
- Configuration changes on the VM only through registered, fixed actions after an explicit administrator approval bound to the exact target, finding, action and parameters. Rejection writes nothing. Failed verification never triggers an automatic second write.
- No arbitrary shell tool, no execution of model-generated text, no `eval`. Validate tool names, arguments, target identity and workflow state in code.
- Bound model steps, repeated calls, timeouts and total runtime. If the model is unavailable, deterministic assessment still works and the UI says the AI is unavailable.
- Evidence, notes and model output are untrusted data. Escape before rendering. No secrets (VM passwords) in logs, prompts, databases or commits.

## Working practice

- Use the project venv: `cis_compliance_dashboard_prototype\.venv\Scripts\python.exe` (Python 3.15 since 5 November 2026; the old 3.12 venv is kept as `.venv-py312-backup`). No global installs, model downloads, pushes or deployments unless asked.
- The client package (`scripts\packaging\build_client_package.py`) ships exactly the venv's libraries. After a deliberate upgrade, regenerate `requirements-lock.txt`, rerun all tests and rebuild. Never ship `data\`.
- Keep layers separate: presentation, domain rules, persistence, model client, orchestration, tool execution.
- Label synthetic/fixture evidence vs real VM evidence. Do not claim live results from fixture tests.
- After a coherent change, run the relevant tests and update [PROGRESS.md](PROGRESS.md) with date, what changed, checks actually run, and the next task.
