# Progress

Full run-by-run history up to 26 October 2026: [docs/archive/PROGRESS_LOG_2026-10-17_to_2026-10-26.md](docs/archive/PROGRESS_LOG_2026-10-17_to_2026-10-26.md). Current design: [ARCHITECTURE.md](ARCHITECTURE.md).

## Current status — 26 October 2026 (Asia/Kuala_Lumpur)

| Area | State |
| --- | --- |
| Controls | **32 assessed** (Stand-alone v2.0.0, schema 5 `full1`): Account 9, Local Security 5, Firewall 8, Audit 5, RDP 5. Report's minimum 30 met. 16 new controls source-reviewed by extracted PDF text; VM comparison pending. Report ID errors documented in [BENCHMARK_MAPPING.md](BENCHMARK_MAPPING.md). |
| Scanner Agent | LLM agent with its own WinRM channel. Real VM scan validated with collector v4 (16 controls, ~2.4 s); **collector v5 (auditpol backup, firewall/RDP policy) not yet run on the VM**. |
| Analysis Agent | Deterministic risk engine. I/P/L **derived by rule** from per-control benchmark attributes (Table 4.15), approved by the user 26 Oct; see [RISK_DERIVATION.md](RISK_DERIVATION.md). Category assignments await the researcher's review. |
| Orchestrator | LLM delegates, then one `submit_plan` with fact-checked reason codes. Real qwen3:8b, 32 controls, simulated VM: 112 s, 0 rejected calls, 7 fixes in risk order. |
| Remediation Agent | 20 library actions (password/lockout, Guest, LSA, audit, RDP policy) executed over WinRM after exact approval. **Real VM remediation not yet run.** |
| Legacy | Upload/manual-exchange page (`legacy_app.py`) and its modules kept; legacy scan queue moved to schema 5. |

## 26 October 2026 changes

- Decisions D1–D6 recorded ([AGENTS.md](AGENTS.md)); scheduled automation retired; preview-era docs archived.
- WinRM channel ([VM_CONNECTION.md](VM_CONNECTION.md)); first real live scan succeeded (run `34d6be89…`, schema 4): 8 Compliant, 4 Non-Compliant (1.2.2, 1.1.1, 1.1.3, 2.3.10.3), 4 Unknown (9.3.1, NLA, 1.2.1, 1.2.4). (An earlier note said 7 Compliant; recounted from the stored record.)
- **Risk derivation** (user-approved method): hand-assigned baselines replaced by `ControlAttributes` (consequence, privilege scope, profile level, assessment status, surface, rationale) and rules `CONSEQUENCE`/`PRIVILEGE_SCOPE`/`LIKELIHOOD` in [risk.py](cis_compliance_dashboard_prototype/hardening/risk.py); page shows a per-factor derivation table; [RISK_DERIVATION.md](RISK_DERIVATION.md) generated from code. LAB_STATE ranking now 1.2.2 (69), 1.1.1 (63), 2.3.10.3 (60), 1.1.3 (57). Real-model probe re-run: 124 s, 0 rejected calls, 7 fixes in derived order. Checks: **222 passed**.
- **History and drift** (FR12/FR13, UC07, Fig 4.16): [history.py](cis_compliance_dashboard_prototype/hardening/history.py) stores immutable ConfigurationDrift records (previous run, current run, control, before/after, kind) automatically after every agentic round and verification scan; new **History and drift** page with assessment history, drift records (regressions flagged) and two-run comparison. Comparability now means same control, benchmark source, profile, rule and collection method; the catalogue *scope* label (5/12/16/32) no longer breaks history, so the next v5 scan compares with the v4 scan above and D=5 is reachable. Checks: **219 passed**.
- Agentic loop: action library + PowerShell runner, risk engine, remediation store/agent, LLM orchestration, agentic page (`app.py` default).
- **Model prose accuracy.** Free-text reasons replaced by reason codes that are checked against the analysis and rendered by code (trial evidence: free text produced "remove unused services" for an anonymous-access fix). One validated `submit_plan` instead of a call per fix (one call per fix exceeded the 300 s budget at 32 controls). Specific argument errors; compact model inputs; Orchestrator `num_predict` 1024 and request timeout 120 s.
- **Control expansion** to 32 (firewall Private/Public policy, 5 audit subcategories via `auditpol /backup` numeric values with new `has_flags` rule, 4 RDP policies); 9 new library actions (audit enable-only, RDP policy). Firewall policy actions deliberately excluded (channel safety). Extraction script [scripts/extract_benchmark_audit.py](scripts/extract_benchmark_audit.py).
- Checks: Python suite **214 passed**; PowerShell `test_collector_helpers` (now with audit parsing), `test_scan_worker`, `test_vm_runner`, `test_remediation_runner` all PASS; real-model probe passed as above. All against fixtures or the simulated VM.

## Still stale

- FRAMEWORK_RUNTIME, ADAPTIVE_INVESTIGATION, AGENT_TEAM, VM_BRIDGE, SCANNER_CONNECTION, VM_EVIDENCE describe the legacy page only. REPORT_REQUIREMENTS_AND_COVERAGE's 36-row status column predates schema 5; BENCHMARK_MAPPING is authoritative for control status.

## Next tasks

1. **User (at home):** VirtualBox snapshot, then one agentic round on the real VM; check the 5 audit controls read real values (not Unknown) — confirms the `auditpol /backup` `Setting Value` assumption; approve one fix, execute, confirm verification. Record outcome here.
2. **User review of risk attributes:** check each control's consequence category and privilege scope in [RISK_DERIVATION.md](RISK_DERIVATION.md) against the benchmark rationale; update the report's Section 4.6.2 examples (62/70 become 69/77) and state the constant-L limitation. Regenerate the doc after any change with `scripts/generate_risk_derivation.py`.
3. Decide D5 (Unknown = not configured): e.g. treat unconfigured policy as non-compliant per CIS and enable RDP/firewall policy actions, with a channel-safety precheck for firewall.
4. Independent manual comparison of the 16 new controls in the VM (gpedit/auditpol).
5. Retire legacy orchestration paths once the agentic page covers their evaluation evidence.
