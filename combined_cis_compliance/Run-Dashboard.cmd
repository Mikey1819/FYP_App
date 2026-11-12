@echo off
rem Starts the dashboard. The first time, it sets itself up: it needs Python 3.13 or newer and an internet
rem connection, and takes a few minutes. Options for launch.py may follow, for example: Run-Dashboard.cmd --no-browser
setlocal
cd /d "%~dp0"
set "VENV=%~dp0.venv-integration"
set "READY=%VENV%\setup-complete.txt"
if exist "%READY%" goto start

echo Setting up the program for the first time. This takes a few minutes and happens only once.
set "PY="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 13))" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "import sys; sys.exit(sys.version_info < (3, 13))" >nul 2>nul && set "PY=python"
if not defined PY goto nopython
if not exist "%VENV%\Scripts\python.exe" %PY% -m venv "%VENV%" || goto failed
"%VENV%\Scripts\python.exe" -m pip install --disable-pip-version-check --quiet -r "%~dp0cis_compliance_dashboard_prototype\requirements.integration.lock.txt" || goto failed
echo Setup finished.> "%READY%"
echo Setup finished.

:start
cd /d "%~dp0cis_compliance_dashboard_prototype"
"%VENV%\Scripts\python.exe" -s launch.py %*
if errorlevel 1 pause
exit /b

:nopython
echo.
echo Python 3.13 or newer was not found on this computer.
echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH" during the installation.
echo Then double-click Run-Dashboard.cmd again.
pause
exit /b 1

:failed
echo.
echo The setup did not finish. Check the internet connection, then double-click Run-Dashboard.cmd again.
pause
exit /b 1
