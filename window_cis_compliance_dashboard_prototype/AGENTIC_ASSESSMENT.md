# Is the delivered system agentic AI? An honest assessment

Reviewed on 29 October 2026 against the code at `be3cd43` and the final 20-run evaluation (`data/agentic_evaluations/20261027_144751`, real `qwen3:8b`, simulated VM). The title promises an **Agentic AI Framework for Windows Systems Hardening and CIS Compliance Assessment** built from multiple agents.

## Verdict

**Structurally, yes. In effect, only partly.**

- **Structurally agentic.** It has four LLM agents, each with its own prompt, tools and conversation. The model chooses every tool call. The Orchestrator delegates to the specialists, and each agent observes the VM, decides and acts in a loop until it reaches a terminal decision. This meets the usual definition of a tool-using multi-agent system.
- **Narrow in effect.** The AI's freedom is deliberately small (D1, D2). In the 20-run evaluation, almost every AI decision matched what a short fixed rule would produce. An examiner can therefore ask *"what does the AI do that a script could not?"* The answer is currently weak, and the report should not overclaim.

The fix is not to remove the safety guards. It is to give the AI one task where a fixed rule genuinely cannot do the job, then to measure it (see **Recommendations**).

## What makes it agentic (evidence in the code)

| Agentic property | Present? | Where |
| --- | --- | --- |
| The LLM chooses actions (tool calls), not just text | Yes | `investigation.py` `Coordinator.run`: the model's tool call is executed and its result is fed back to the model |
| Multi-step observe → decide → act loop | Yes | Each agent loops for up to 6–12 steps; for example, the Scanner scans, reads coverage, may rescan, then hands off |
| Several distinct agents with separate roles and context | Yes | `ScannerTools`, `AnalysisTools`, `RemediationTools`, and `OrchestratorTools` / `OrchestratorReviewTools`, each with its own `PROMPTS` entry |
| Delegation and hand-offs between agents | Yes | `delegate_scanner`, `delegate_analysis`, `delegate_remediation`, `delegate_verification`; structured hand-off outcomes |
| Acts on a real environment | Yes | WinRM collection, precheck, execution and verification against the VM |
| Behaviour depends on what it observes | Partly | Rescan only after an Error; skip only when the precheck shows a change; stop after an uncertain outcome. Most of these are **forced by code**, not chosen (see below) |
| Memory across rounds | Partly | History and drift (D factor, `check_history`); the agents themselves hold no memory beyond one round |
| Goal-directed planning | Weak | The Orchestrator's `submit_plan` chooses which fixes to propose and in what order, but the plan always matched the risk rank, apart from a consistent reordering |

## What the AI decides, and what code decides

Code computes every fact, score and safety rule. The AI chooses among the options that code allows at that moment. In most steps `available()` offers exactly **one** valid tool, so the tool sequence itself is effectively scripted. The real AI choices are listed in the table below.

| Agent | Real AI choice | Constrained by code | Observed in 20 runs |
| --- | --- | --- | --- |
| Scanner | Rescan after an Error result or not; inspect observations or not | Rescan allowed once, and only when an Error exists | Rescanned 4/4 when an Error existed (after inspecting it); never otherwise (not allowed) |
| Analysis | Which findings to investigate (0–2); which ≤3 findings to flag, under which attention code; which triage code for each gap | Only codes that are true for a finding are offered; scores are read-only (D2) | **0 investigations in 20 runs.** The same flags in every run (1.2.2, 9.2.1, 9.3.1; 1.2.2 as `regression` in drift), and the same triage |
| Orchestrator (assessment) | **Which fixable findings to propose, and in what order**; the reason codes | Blocked findings cannot be proposed; every reason code must be true; every finding decided once | Same set as "all fixable findings" in **17/20**; 2 low-impact fixes left out in 3/20. **Order differed from the risk rank in 20/20**, always the same way: prerequisite 1.2.2 first, audit controls last |
| Remediation | Execution order; whether to continue after a *failed* (not uncertain) result | Not-ready requests cannot be executed, ready ones cannot be skipped, and execution must stop after an uncertain outcome | Execution order = approved rank order **20/20**. Skips (4/4) and stops (4/4) were the only valid moves |
| Orchestrator (remediation) | `finish` or `next_round` when both are true | `remediation_review` is the only option after any failure, uncertainty or non-attempt | Chose `next_round` in 5/5 runs where both were possible; in the other 15 runs only one step was valid |
| Explanations (FR17) | Free text explaining one finding | Labelled unverified; changes nothing | Generated on request in the dashboard; not part of the evaluation |

### What a fixed rule would have done

The baseline rule is: *propose every fixable finding in risk-rank order, execute in that order, rescan once on Error, finish when nothing fixable remains.* It reproduces the AI's observable behaviour except for the following:

1. **Plan order:** the AI put the prerequisite 1.2.2 first and the auditing controls last, in all 20 runs. It is a sensible ordering, but it is consistent enough to be a rule. Within one round it changes nothing functionally, because the controls waiting for 1.2.2 are blocked and not proposed anyway.
2. **Deferring low-impact fixes** in 3/20 runs (1.1.3 and 18.10.57.3.9.4). This is a genuine judgement, but it was inconsistent across identical scenarios.
3. **`next_round` instead of `finish`** in the 5 runs where both were allowed. This is a defensible preference, and it is consistent.

Everything else, including the safety behaviour the evaluation reports as 20/20, 4/4, 11/11 and 4/4, is **guaranteed by code**. That is the right design for safety, but those results show that the guards work, not that the AI judged well.

## Questions an examiner is likely to ask

| Question | Honest answer today |
| --- | --- |
| "What does the AI add over a script?" | Coordination via tool calls, the plan order and composition, gap triage and attention flags, the next-step choice, and explanations. In the test scenarios its choices were nearly constant and close to a rank-order rule. |
| "Are the agents just following the prompt's numbered steps?" | Largely, yes. The prompts give step lists, and code offers one valid tool at most steps. This was done for reliability and speed on an 8B local model on a laptop GPU (26–27 Oct probes). |
| "Did the AI ever make a decision the code did not force?" | Yes, a few: rescan 4/4, deferring low-impact fixes 3/20, `next_round` 5/5, plan order 20/20, which findings to flag. The examples are listed in the table above. |
| "Why is the AI not allowed to change scores or choose values?" | By design (D1, D2): deterministic, auditable compliance and risk; the AI coordinates and decides within guardrails, and a human approves every change (NFR01). This is a strength if framed as *bounded autonomy*. |
| "Does it still work without the AI?" | Assessment and scoring yes (deterministic fallback); remediation yes via **Execute without AI**. This shows safety, but it also shows the AI is not required for the core result. |

## Recommendations, in order of value

1. **Give the Orchestrator a task only an LLM can do: administrator goals in natural language.** For example: *"Keep RDP usable for remote support this week"*, *"Only audit and password policy during today's window"*, *"Prioritise anything that helps detect intrusions"*.
   - The Orchestrator turns the goal into its plan, choosing which findings to fix now, which to defer, and in what order. It records which goal each choice serves.
   - Code still validates every entry, and the administrator still approves every change, so safety does not change.
   - Evaluate it with goal scenarios (goal satisfied? anything wrongly deferred or included?) compared against the rank-order baseline. A fixed rule cannot read free-text goals, so this shows the AI adding real value. It also matches the report's human-in-the-loop story.
2. **Report the decision audit above in Chapter 5**, rather than only the safety counts. Use the table of AI choice points, what the model chose, and how often it differed from the baseline rule. Examiners trust a system more when its limits are measured.
3. **Reword the report's claims to "bounded-autonomy agents".** State plainly in §3.3 and §4.3 what the AI decides and what code guarantees, using the second table above. Avoid wording that implies the AI decides compliance, risk or values.
4. **Optional:** make the Analysis Agent's investigation count, for example by requiring a `check_history` call before a `regression` flag. As it stands, the agent never investigated in 20 runs, and the report should not describe investigation as a behaviour it shows.
