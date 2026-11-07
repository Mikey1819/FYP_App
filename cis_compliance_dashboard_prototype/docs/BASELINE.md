# Windows preservation baseline

Working project: `C:\Users\teohk\OneDrive\Desktop\FYP_App-main\window_cis_compliance_dashboard_prototype`. Branch: `integrate/unified-vm-hardening`. No Git repository existed at this location or its parents before the task. Baseline commit: `af43fbccaea5a5818396a376468afb44bd439c40`.

Before integration edits, 86 source files were archived outside runtime imports in `..\..\integration-recovery\windows-pre-integration-20261105.zip` (relative to the app directory), verified SHA256 `b85cbd26e9a3429210679d69385df5a2f239c214d883077823605775b61b6e08`. `baseline_manifest.json` preserves original per-file byte hashes and categories. No original environment, database, cache or credential is included.

The preexisting `.streamlit/config.toml` was excluded by the original archive's broad `.streamlit` exclusion. It has not been changed. A verified supplemental archive and its hashes are recorded in `baseline-theme-supplement.json`; the original archive was not rewritten. This preserves the existing cream/yellow/black theme configuration.

The Desktop source was compared with the GitHub-folder Windows counterpart without overwriting either. All 86 files match after CRLF/LF normalization; 85 differ in raw bytes due to line endings. The recovery directory contains the comparison records.

Protected: existing domain/engine/risk/storage/channel/action modules, PowerShell scripts and original tests. Authorized presentation edits: `app.py`, `hardening/connection_view.py`, `agentic_view.py`, `overview_view.py`, `history_view.py`, and `ui.py`. Metadata and additive modules are separate categories. No protected source change is currently detected.

Verification from the app directory:

```powershell
..\.venv-integration\Scripts\python.exe -B -m tools.baseline
```

The original pre-change Python suite passed 178 tests. With the first two preservation tests it passed 180 in 18.775 seconds. All four original PowerShell fixture suites passed: remediation runner, collector helpers, cross-check values, and server access. These are actual local fixture runs, not live VM results or repeated historic claims.

Original Streamlit tests exercise individual/bulk decisions, comments, confirmation, fallback, goals and resumption. Added tests cover the same existing connection form, both platform tabs, Windows/Ubuntu/Windows switching, workflow resume, cross-platform page isolation and stale form invalidation. The original Overview styling was observed in the browser. A later browser-control failure prevented completing the visual comparison; automated UI coverage does not close that visual gate.

No integration milestone is declared complete. Review the current progress record for exact later regression counts and outstanding UI migration work.

## Visual and fixture regression check, 7 November 2026 (task 16 gate)

- **Protected files:** `python -B -m tools.baseline` reports `protected: []`, `missing: []`. The only changes are the five authorized UI files and `PROGRESS.md`.
- **Original PowerShell fixture suites:** all four pass again (remediation runner, collector helpers, cross-check values, server access). Before running, each was inspected: every library is dot-sourced with `-FunctionsOnly` and returns before any action, and only parsing/planning helpers are called. The server-access window is built and disposed without being shown or used.
- **Python suite:** 572 tests pass, including the original Windows tests.
- **Side-by-side visual comparison:** the verified pre-change archive (SHA256 `b85cbd26…`, plus the theme supplement `afeb2f96…`) was extracted to a scratch folder, and the current committed tree was exported with `git archive HEAD`. Both ran with the same `.venv-integration` on empty, isolated stores, and the browser compared them (no live data or VM).
  - **Overview** and **History and drift:** identical text, theme (cream background, yellow highlights, black sidebar), navigation, status badges and empty states.
  - **Agentic hardening:** identical layout, styling, password notice, server-access helper, button and empty state. The connection form differs only as authorized by task 2 (one neutral form for both platforms): "VM machine UUID" → "VM machine identity", "WinRM host (…)" → "VM IP address / host", "Administrator account" → "Username", and an added "Advanced settings" (transport) expander.
  - **Open observation for review:** the baseline pre-filled the Windows lab values (host `127.0.0.1`, port `55985`, account `Administrator`). The neutral form starts empty, so Windows users now type them. This was not changed; it awaits the administrator's choice.
- **Not covered visually:** pages after a live Windows connection (no Windows VM in this check). Those states are covered by the original Streamlit AppTest decision, comment, confirmation, fallback, goal and resumption tests, which pass.
