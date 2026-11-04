@echo off
rem Opens the FYP Server Access Helper as administrator (Windows asks for confirmation first).
powershell.exe -NoProfile -Command "Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','\"%~dp0FYP-ServerAccess.ps1\"')"
