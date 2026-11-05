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
