# Preview rehearsal result - 18 October 2026

**Passed: automated technical walkthrough using the actual Streamlit UI callbacks, real local qwen3:8b and simulated execution.** Total software runtime: **137.547 seconds (2 minutes 18 seconds)**. This excludes spoken explanation and manual browser interaction. It is not a real Windows Server scan-time measurement.

Run started at 18:39 Malaysia time (UTC+08:00). A new database was used; earlier model-validation records and the normal preview database were not modified.

| Step | Result | Elapsed time |
| --- | --- | --- |
| Launch, all six views, original 40% compliance and lockout risk 70 | Passed | 1.813 s |
| Compatible-client investigation through the UI | Passed; proposal prepared, no automatic execution | 84.281 s |
| Legacy-client investigation through the UI | Passed; history inspected, operational review, no proposal | 47.891 s |
| Reject the model-prepared proposal | Passed; no execution attempt | 0.219 s |
| Approve a new simulated action and verify | Passed; original assessment preserved | 0.640 s |
| Simulate command success with failed read-back | Passed; finding unresolved and repeat approval disabled | 0.625 s |
| History plus a separate Python process reopening all six views | Passed; failed-verification state/comment restored | 1.687 s |
| Deliberately injected model timeout and previous-run fallback | Passed; outage labelled, assessment retained, earlier trace accessible | 0.313 s |

The compatible model run was `17ecd9966ceb487fbe7f146292814d09` (84.094 seconds model time). It selected reference, evidence, related configuration, supported remediation and proposal submission.

The legacy model run was `8edde04716b94a0d8cdf86eea0b86562` (47.688 seconds model time). It selected reference, evidence, related configuration, prior history and supported remediation, then concluded that operational review was needed. Both model scenarios ran from the dashboard's investigation button, not only the command-line coordinator.

The fallback failure was intentionally mocked and labelled **Mock outage (rehearsal only)**. It is not evidence that Ollama failed during the two real investigations. No model-provided approval or live execution was used.

## Saved evidence and backup

Directory: `cis_compliance_dashboard_prototype/data/rehearsals/20261018_183916_19d507f8/`

- `rehearsal.json`: incremental step results, timings and full real investigation traces.
- `preview.sqlite3`: original synthetic snapshots, three proposal histories (rejected, successful verification, failed verification), and investigation records.

These local runtime artifacts are ignored by Git. They remain available in the workspace; copy the directory for an offline backup. To show the captured run, launch from the application directory:

```powershell
$env:CIS_DASHBOARD_DB = (Resolve-Path '.\data\rehearsals\20261018_183916_19d507f8\preview.sqlite3').Path
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Clearly identify this as a **previous rehearsal**. The newest investigation is the injected outage; select one of the real run IDs above under Saved investigation to show its tool evidence. History can reopen each proposal. For an interactive repeat that preserves these records, copy the directory and use the copied database. To return to the normal demo database in that PowerShell session, use `Remove-Item Env:CIS_DASHBOARD_DB`.

## Other checks and limits

- The documented Streamlit executable started a temporary loopback-only server; its HTTP readiness endpoint returned `ok` after **3.860 seconds**. The temporary process was stopped after the check.
- Full automated suite: **55 tests passed in 6.414 seconds** using `.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v` from the application folder.
- No browser or app automation surface was exposed in this session. Browser screenshots, visual layout, responsive sizing and a spoken human presentation remain **untested**. Streamlit AppTest verifies UI behavior, not pixel appearance.
- No real server, benchmark mapping, live collector or Windows hardening was validated. A11 remains blocked on the confirmed VM, server role and matching CIS source/profile.

This completes the documented technical walkthrough for A10 and supports **DEMO_READY** for the synthetic preview. It does not set PREVIEW_COMPLETE or establish LIVE_PREVIEW_READY. Before presenting, do a visual check in your browser and practise the spoken walkthrough in TEACHER_PREVIEW.md.
