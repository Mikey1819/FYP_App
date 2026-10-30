# Plan: administrator goals for the Orchestrator (proposal, not built)

30 October 2026. This is AGENTIC_ASSESSMENT Recommendation 1. It was set aside on 29 October because free text has endless possible inputs, so a few scenarios could not show that it behaves well. The design below addresses that objection. **Nothing is implemented until you approve.**

## Idea in one paragraph

Before a round, the administrator may type a goal, for example *"Keep RDP usable for remote support this week"*. The Orchestrator does the one thing a fixed rule cannot do: it reads the sentence and translates it into a small, **closed** set of constraints. Code checks the constraints, shows the interpretation to the administrator next to the proposals, and enforces it on the plan. The AI handles the language. Code still guarantees safety, and the administrator still approves every change.

## How it answers the 29 October objection

| Objection | Answer in this design |
| --- | --- |
| Free text has endless inputs | Only the input is open-ended. The output is finite: a handful of fields with fixed values, which code validates. |
| A wrong reading could cause a bad plan | The interpretation is shown before any approval ("Goal read as: leave Remote Desktop Services alone"). A goal can only **narrow or reorder** the plan. It can never add a fix that is not already fixable, choose values or skip approval. |
| Too few scenarios to prove it | A pre-registered paraphrase set: each goal in several wordings, plus ambiguous and irrelevant goals. We measure how often the interpretation is right. This tests robustness to wording, not one lucky sentence. |
| Goal text could carry a prompt injection | The goal is untrusted data. No tool can approve, execute or change a score. The worst case is a wrong interpretation, and that is visible to the administrator. |

## Design

1. **Dashboard:** an optional "Goal for this round" field (at most 300 characters) above **Start/Run next round**. It is stored with the round.
2. **New Orchestrator tool `interpret_goal`**, called first when a goal is present. Its arguments are code-checked enums only:
   - `exclude_areas`: subset of the 5 security areas
   - `only_areas`: subset of the 5 areas (empty means all)
   - `exclude_controls`: control IDs from the current findings
   - `focus`: `detection` | `account_security` | `remote_access` | `none`
   - `max_fixes`: 1–10, or none
   - `unclear`: true when the goal cannot be mapped (then no constraint applies, and the page says so)
3. **Plan codes:** a new skip code `outside_goal`, true only for findings the constraints exclude. A new fix code `serves_goal`, true only for findings matching `focus`. Code refuses a plan that fixes an excluded finding or exceeds `max_fixes`. The order of the remaining fixes stays the AI's choice.
4. **Shown on the Fixes tab and in the round report:** the goal text, the interpretation, and which choices it changed.
5. **Unchanged:** risk scores (D2), the action library, approval binding and expiry, execution confirmation, and verification.

## Evaluation (pre-registered before any run, like JUDGEMENT)

- **Goals:** about 6, each in 3 wordings. For example: keep RDP usable; only audit and password policy today; prioritise intrusion detection; at most two changes; plus 1 ambiguous goal and 1 irrelevant or unsafe goal (*"turn off the firewall"*, which must give `unclear` or no change).
- **Measures:** interpretation matches the expected constraints; the plan satisfies the goal; nothing is wrongly deferred; time per round (NFR06, 600 s).
- **Baselines:**
  - the risk-order rule, which ignores goals;
  - a **keyword rule**, which matches words like "RDP" or "audit" to areas. This is the honest, stronger baseline: the AI should beat it on paraphrases and negations ("anything except remote desktop").
- **Cost:** assessment phase only, about 4–5 minutes per run. 18 runs ≈ 1.5 hours; 2 repeats ≈ 3 hours.

## Work involved

`agentic.py` (tool, validation, codes, prompt), `agentic_view.py` (field and display), `round_report.py`, unit tests with scripted models, goal scenarios in `scripts/evaluate_agentic_rounds.py`, and docs (ARCHITECTURE, AGENTIC_ASSESSMENT, REPORT_REVISIONS for Chapter 5). One extra model call per round, about 15–40 s.

## Decisions for you

1. Go ahead, given that this was set aside on 29 October?
2. Is the constraint list above enough, or are there goals you want supported?
3. Evaluation size: 1 repeat (about 1.5 h) or 2 repeats (about 3 h)?
