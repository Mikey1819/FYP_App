# Report changes to consider later

The academic reports have not been rewritten.

- Describe one existing Streamlit entry point with shared connection/workflow contracts and internal Windows/Ubuntu backend modules.
- Distinguish connection identity from durable workflow identity and target registration epoch.
- Preserve the Windows catalogue/risk method and 32-control baseline; Ubuntu selection is exactly 30 recommendations, 24 L1/six L2, 29 Automated/one Manual.
- Explain separate compliance and coverage denominators, explicit Unknown/Error states and manual update review.
- Record content/source hash pins and PDF-versus-site-policy differences; do not call draft attributes human-approved.
- Describe host coordination and target recovery only to the extent actually implemented and tested. Current separate-process claim tests do not prove a finished runner/watchdog.
- Report synthetic predicate/parser/UI evidence separately from authenticated read-only collection and live remediation. Current SSH observation was handshake-only; local Ollama inference succeeded independently.
- ~~Remaining work includes complete Ubuntu collection/storage/risk/agent integration, all 30 remediation families, recovery, live evaluation and complete visual regression evidence.~~ Superseded 2026-11-07; current state below.

## Update, 7 November 2026 (still not rewritten into the reports)

- **Implemented and fixture-tested:** Ubuntu collection, storage, risk and agents; all 30 remediation families; recovery (approved restore, commit-confirm, boot rollback, reconciliation). Windows regression is evidenced in `BASELINE.md`: protected files unchanged, fixture suites passing, side-by-side visual comparison.
- **Live evidence must be reported separately from fixture evidence:**
  - read-only assessment of all 30 controls (29 stored live scans);
  - one CIS fix validated live (3.3.2, applied and verified, restored, applied again);
  - 5.1.20 attempted but not applied (a defect, fixed since);
  - 28 controls not run live (`evaluation/LIVE_VALIDATION.md`).
- **Independent cross-check:** direct probes against OpenSCAP over 29 live scans show no unexplained disagreement. The SSH explicit-line difference is a documented interpretation (`evaluation/SCAP_CROSS_CHECK.md`).
- **Agentic evaluation (offline, real qwen3:8b, simulated collection):**
  - Before the plan-format fixes, 3 of 12 rounds stored a plan; after them, 12 of 12, all on the first call.
  - The plans equal a fixed rule in 12/12; the Scanner never used its rescan after a collection error.
  - Do not claim AI superiority (`evaluation/UBUNTU_AGENTIC_EVALUATION.md`).
- **Design changes since the original reports:**
  - The Ubuntu orchestrator decides by deferring: every registered fix it does not defer is proposed.
  - Round goals are disabled for Ubuntu.
  - The Fixes tab shows one card per Non-Compliant control.
  - The connection form is neutral and empty for both platforms.
- **Fault scenarios:** each scenario required by the plan is exercised by fixture tests (`evaluation/FAULT_SCENARIOS.md`, 35/35); these are not live trials.
