FYP Server Access Helper
========================

Run this ON the Windows server you want to check, as an administrator. It pairs the server with the laptop that
runs the dashboard, so that laptop can reach the server over WinRM (TCP 5985). It undoes that afterwards.

1. Copy the three files to the server, into one folder.
2. Optional but recommended: check the file was not changed on the way. In PowerShell:
       Get-FileHash .\FYP-ServerAccess.ps1 -Algorithm SHA256
   It must match the SHA-256 shown in the dashboard under the download button.
3. Double-click Start-ServerAccess.cmd and accept the administrator prompt.
4. Click "Start pairing". The window shows a one-time code such as 482-913-075.
5. On the laptop, in the dashboard: Servers > Add a server > type the code > Find. Then type the Administrator
   password. The laptop and the server must be on the same network (for example the same Wi-Fi).
6. Check the server from the dashboard.
7. When you have finished, click "Revert changes".

The pairing code
- Works once, for 10 minutes, and only while this window shows it.
- Is never sent over the network. The laptop and the server only prove to each other that they know it.
- Pairing stops after 5 wrong codes from one device, or 20 in total. Click "Start pairing" for a new code.

What pairing changes
- Adds one firewall rule, FYP-ServerAccess-WinRM, that lets ONLY paired laptops reach TCP 5985.
- While a code is shown, a temporary rule lets the local network reach UDP 47815, so the laptop can find this
  server. It is removed when pairing ends.
- If PowerShell Remoting was off, it turns it on and keeps the built-in WinRM firewall rules as they were.
- It saves the previous state first, in C:\ProgramData\FYP-ServerAccess\ (readable by administrators only),
  together with the list of paired laptops.

Paired laptops
- "Check status" lists them. The dashboard also lists them and can disconnect any of them.
- A laptop that pairs again (for example after its address changed) keeps one record, at its new address.

What "Revert changes" does
- Removes the rules and the list of paired laptops. If the helper turned Remoting on, it turns it off again and
  restores the WinRM service, listener, firewall rules and LocalAccountTokenFilterPolicy as they were.
- Anything that was already on before the helper's first change stays on.

It never changes a CIS setting, never enables Basic login or unencrypted WinRM traffic, and never asks for or
stores a password. It refuses to run on a workstation (such as the laptop).

Command line (same actions, no window):
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Pair       (shows the code, waits)
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Status
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Revert
If the network blocks pairing (some guest or campus Wi-Fi does), allow one laptop by its address instead:
    powershell -ExecutionPolicy Bypass -File FYP-ServerAccess.ps1 -Action Allow -ScannerAddress 192.168.1.23
and add the server in the dashboard by address (Servers > Add a server > by address).
