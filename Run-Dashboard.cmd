@echo off
rem Starts the dashboard from the top of the project folder. The real launcher, with the first-time setup, is
rem combined_cis_compliance\Run-Dashboard.cmd; options are passed on to it, for example: Run-Dashboard.cmd --no-browser
call "%~dp0combined_cis_compliance\Run-Dashboard.cmd" %*
