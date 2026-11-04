FYP Server Access Helper
========================

Run this ON the Windows server you want to scan, as an administrator. It lets the scanning
laptop reach the server over WinRM (TCP 5985) while you scan, and undoes that afterwards.

OPTIONAL. You do NOT need it for the lab VM through the VirtualBox port forward
(127.0.0.1:55985): WinRM is already set up inside the VM (see docs/vm/VM_CONNECTION_SETUP.md
in the project). Use it only when you scan a server by its network address, such as
another server or the VM through a host-only adapter.

1. Copy the three files to the server, into one folder.
2. Optional but recommended: check the file was not changed on the way. In PowerShell:
       Get-FileHash .\FYP-ServerAccess.ps1 -Algorithm SHA256
   It must match the SHA-256 shown in the dashboard under the download button.
3. Double-click Start-ServerAccess.cmd and accept the administrator prompt.
4. The window shows this server's computer name, machine UUID and IP addresses.
   Type them into the dashboard's connection form.
5. Type the laptop's IPv4 address and click "Allow scanning".
6. Scan from the dashboard.
7. When you have finished, click "Revert changes".

What "Allow scanning" changes
- Adds one firewall rule, FYP-ServerAccess-WinRM, that lets ONLY the laptop's address reach
  TCP 5985.
- If PowerShell Remoting was off, it turns it on and keeps the built-in WinRM firewall rules
  as they were, so only the rule above lets traffic in.
- It saves the previous state first, in C:\ProgramData\FYP-ServerAccess\state.json.

What "Revert changes" does
- Removes the rule. If the helper turned Remoting on, it turns it off again and restores the
  WinRM service, listener, firewall rules and LocalAccountTokenFilterPolicy as they were.
- Anything that was already on before "Allow scanning" stays on.

It never changes a CIS setting, never enables Basic login or unencrypted WinRM traffic, and
never asks for or stores a password. It refuses to run on a workstation (such as the laptop).

Command line (same actions, no window):
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Status
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Allow -ScannerAddress 192.168.56.1
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Revert
