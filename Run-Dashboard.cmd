@echo off
rem Developer shortcut: start the unified dashboard from any folder. Double-click it, or type its path in a terminal.
rem Extra Streamlit options can follow, for example:  Run-Dashboard.cmd --server.port 8502
cd /d "%~dp0cis_compliance_dashboard_prototype"
"..\.venv-integration\Scripts\python.exe" -m streamlit run app.py %*
if errorlevel 1 pause
