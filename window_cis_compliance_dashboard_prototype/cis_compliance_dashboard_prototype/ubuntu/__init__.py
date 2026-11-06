"""The Ubuntu Linux workspace: the same three pages as Windows (Overview, Agentic hardening, History and drift),
kept in this folder so Ubuntu's files never mix with the Windows Server 2022 ones in hardening/.

Status: placeholders. Ubuntu is recognised when it pairs (hardening/system_detect.py), but its checks are not
linked to the program yet, so an Ubuntu server cannot be connected and these pages say so.

Linking it later means:
  1. An Ubuntu server helper that shows a pairing code and answers with os = "ubuntu" (the ID in /etc/os-release).
  2. A Linux connection channel (SSH instead of WinRM) whose target carries `workspace = 'ubuntu'`; app.py then
     opens these pages for it.
  3. An Ubuntu CIS catalogue and evidence collector, and the real pages here in place of the placeholders.
  4. Marking Ubuntu as supported in hardening/system_detect.py.
"""
