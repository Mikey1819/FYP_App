# Agent connection to a server (PowerShell Remoting)

The Scanner Agent reaches the VM itself over WinRM. Nobody copies scripts in or JSON out. It sends only the repository's fixed collector ([scripts/vm/Collect-Server2022Evidence.ps1](../../scripts/vm/Collect-Server2022Evidence.ps1)) with typed parameters. Model text is never sent to the VM. The Remediation Agent uses the same channel for its read-only precheck and for approved actions.

```text
Laptop: Streamlit + agents (Python, pypsrp)  --NTLM-encrypted WinRM-->  server 192.168.x.y:5985 (WinRM HTTP listener)
        found by its pairing code on the same network (UDP 47815); the address is never typed
```

**Servers are added by pairing code only** (since 5 November 2026). The administrator never types an address or a port. The server's pairing answer also says which operating system it runs, and the dashboard shows that as a note (`hardening/system_detect.py`). The program supports only **Windows Server 2022 (stand-alone) and Ubuntu 22.04.5 LTS**; only those go on to the login. Ubuntu servers are reached over SSH with their own pairing helper (section *Ubuntu 22.04 servers* below).

## Already done on the laptop (26 October 2026)

- `pypsrp==0.8.1` installed in the project venv (in `requirements.txt`). No laptop WinRM service, TrustedHosts or firewall change is needed. The laptop is only the client.
- VirtualBox NAT rule on `FYP-Server2022-Manual` (UUID `e5d10741-…`): `fyp-winrm,tcp,127.0.0.1,55985,,5985`. It is bound to loopback, so only this laptop can reach it. **The dashboard no longer uses it** (it cannot carry the pairing broadcast). Only the lab cross-check tool (`scripts/tools/cross_check_controls.py`) still connects through it.
  - Inspect: `VBoxManage showvminfo e5d10741-f200-4292-a099-e6be76032f4e --machinereadable | findstr Forwarding`
  - Remove: `VBoxManage controlvm e5d10741-f200-4292-a099-e6be76032f4e natpf1 delete fyp-winrm`

## One-time setup inside the VM

Open **Windows PowerShell as Administrator inside the Server 2022 VM**:

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Test-WSMan -ComputerName localhost
```

`Test-WSMan` should print a `wsmid` / `ProtocolVersion` block. This step creates the HTTP listener on port 5985 and its inbound firewall rule. Leave `AllowUnencrypted` and Basic auth at their defaults (off); the agent uses NTLM with message encryption.

Use the **built-in Administrator** account. Windows strips the admin token from other local administrators over the network (UAC remote restrictions). The collector needs a full admin token for `secedit /export`, and the dashboard reports `not_admin` if the token is filtered.

Restoring `Clean_Server2022_Before_Hardening` undoes this setup. Run it again after a restore.

**After a snapshot restore, check the VM's network adapters too.** Restoring brings back the VM's VirtualBox settings from when the snapshot was taken. That can remove the host-only adapter the dashboard needs, and the `fyp-winrm` forward the cross-check tool uses (this happened on 30 October). Re-add the forward from the laptop (allowed while the VM is running):

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm e5d10741-f200-4292-a099-e6be76032f4e natpf1 "fyp-winrm,tcp,127.0.0.1,55985,,5985"
```

Check: `Invoke-WebRequest http://127.0.0.1:55985/wsman -Method Post` should fail with **401**. A 401 means the WinRM listener answered and wants a login; no answer at all means the forward or `Enable-PSRemoting` is missing.

## Pairing a server: the server access helper

Every server, the lab VM included, is added by pairing with the server access helper. Design: [LAN_PAIRING_DESIGN.md](../design/LAN_PAIRING_DESIGN.md).

The helper lives in [scripts/server_access/](../../scripts/server_access/): `FYP-ServerAccess.ps1`, `Start-ServerAccess.cmd`, the README, the shared pairing examples (`pairing_vectors.json`) and the fixture test `test_server_access.ps1`. The **Servers** page offers the first three as **Download helper (.zip)**. On the server, as administrator:

1. Check `Get-FileHash .\FYP-ServerAccess.ps1` against the SHA-256 shown under the download button.
2. Double-click `Start-ServerAccess.cmd` and click **Start pairing**. The window shows a one-time 9-digit code. It works once, for 10 minutes, and only while the window shows it. On Server Core: `FYP-ServerAccess.ps1 -Action Pair`.
3. On the laptop: **Servers → Add a server**, type the code, **Find server**. The page shows the server's name and the system it reported (for example *Windows Server 2022 · Supported*). Then log in with the built-in Administrator account. For a system that is not supported yet, the page shows a note instead of the login, and nothing is saved.
4. Check the server from **Agentic hardening**.
5. When finished, click **Revert changes** on the server.

**What pairing changes on the server:**
- Before its first change, the helper saves the server's state to `C:\ProgramData\FYP-ServerAccess\state.json`. The folder is readable by Administrators and SYSTEM only.
- If Remoting was off, it runs `Enable-PSRemoting` and puts the built-in WinRM firewall rules and `LocalAccountTokenFilterPolicy` back as they were.
- While a code is shown, a temporary rule `FYP-ServerAccess-Pairing` admits the local subnet on UDP 47815.
- On the right code, it records the laptop in `pairings.json` and sets one rule, `FYP-ServerAccess-WinRM`, that admits **only the paired laptops' addresses** on TCP 5985 (at most 10).
- A laptop that pairs again replaces its old address.
- After 5 wrong codes from one address, or 20 in total, pairing stops.

**Revert** removes both rules and the pairing records, and undoes only what the helper changed. Anything that was already on stays on.

**From the dashboard** (Servers → *Who can reach …*, while connected), the helper's own text runs over WinRM. It can list the paired laptops, disconnect one, or close every laptop's access. Closing all access does not turn Remoting off, because that would cut the session doing it. The page then says to click Revert on the server.

**When the laptop cannot find the server** although the code is right: some guest or campus Wi-Fi stops devices talking to each other. There is no fallback by address any more (removed on 5 November 2026, with the helper's `-Action Allow`). Put both machines on another network, such as an office or home router, and start pairing again.

The helper refuses to run on a workstation, never changes a CIS setting, never enables Basic login or unencrypted traffic, and never handles a password. Its tests use fixtures and UDP on the laptop's own address only. **Start pairing and Revert have not yet been run on a real server.**

### The lab VM

The NAT port forward does not carry the pairing broadcast, so the dashboard needs the VM on a network it shares with the laptop. Give the VM a second network adapter: **Host-only** (laptop `192.168.56.1`), or **Bridged** to the Wi-Fi to test exactly what a client does. Then pair it like any server. Keep the NAT forward only if you still use the cross-check tool.

## Use it

1. Start the dashboard: `.\.venv\Scripts\python.exe -s launch.py` from the application folder, or `Start.cmd` in the client package.
2. Open **Servers** and pair the server: *Add a server*, as above.

   The dashboard reads the hostname, machine UUID and system from the server itself, checks the administrator token and that it is a stand-alone Server 2022, and saves the server under **My servers**. Next time, pick it there and type the password: every connection checks that the same hostname and UUID answer.
3. Once connected, the sidebar shows the server on every page, and **Disconnect** (top of the Servers and Agentic pages) ends the session without changing anything on the server.
4. **Agentic hardening → Start agentic round**: the Orchestrator delegates the Scanner Agent, which collects over this channel. After you approve fixes, **Execute approved fixes… → Confirm and execute** uses the same channel for the Remediation Agent's precheck, the approved actions and the verification rescan.

The password stays in the Streamlit session's memory only. It is never written to SQLite, logs, prompts or traces.

## Failure states

| State | Meaning |
| --- | --- |
| `unreachable` | Nothing answered: the server is off, its address changed, access was reverted, or (lab VM) its host-only adapter or `Enable-PSRemoting` is missing. Start pairing on it and **Re-pair** |
| `auth_failed` | Wrong username or password |
| `not_admin` | Connected, but without an administrator token (use built-in Administrator) |
| `wrong_target` | The machine answering is not the saved hostname and UUID, or not the one that answered the pairing code. Nothing is collected or saved |
| *Not supported yet* (after Find server) | The server reported a system this program does not check yet: Ubuntu, another Windows Server version, a Windows desktop, or anything else. The note says which. No login is offered and nothing is saved |
| `unsupported_target` | After login: not a stand-alone Windows Server 2022 (another version, a workstation, or joined to a domain), whatever the pairing answer said. Not saved |
| `pairing_not_confirmed` | The server's own records do not hold this pairing for this laptop. Start pairing again and use the new code |
| `collection_failed` | The collector threw on the server. No assessment is created |
| *No server answered* | The code expired or was mistyped (the helper window on the server shows "Wrong code from …"), pairing was stopped on the server after 5 wrong codes, or the laptop is not on the same network as the server. The server never answers a wrong code, so the laptop cannot say which |

## Limits and design notes

- Evidence collected over this channel is stored as `Live`, including the remediation runner's before/after evidence (since 3 November 2026; the 12 earlier runner records were relabelled). The file-era scans (19–26 October) were removed from the database on 3 November; a local backup is in `data/backup_before_cleanup_2026-11-03/`. `Imported` remains only for the command-line client's `--evidence file.json`. The **History and drift** table shows the source of every assessment.
- Hardening can cut this channel. Future firewall controls (for example disabling local firewall rule merging), WinRM service policies and network logon rights can break remoting. The Remediation Agent must refuse, or flag, any action that would disconnect its own channel before verification.
- The Remediation Agent runs [Invoke-RemediationAction.ps1](../../scripts/vm/Invoke-RemediationAction.ps1) over this channel for approved library actions, as described in [ARCHITECTURE.md](../design/ARCHITECTURE.md). Its precheck runs the same read-only collector without storing a new assessment.
- Nothing needs to be copied into the VM for the agentic page: the collector and runner are sent over the channel on every call.
- Nothing is run by hand inside the VM. The shared-folder worker was removed on 29 October, and the collector's and cross-check's save-to-file modes on 3 November: they needed a person inside the VM, so they did not satisfy D6.

## Ubuntu 22.04 servers (unified system, 8 November 2026)

Ubuntu servers are paired the same way, with their own small helper, and reached over SSH instead of WinRM.

```text
Laptop: Streamlit + agents (Python, paramiko)  --SSH-->  server 192.168.x.y:22
        found by its pairing code on the same network (UDP 47815); address, name, machine ID and host key never typed
```

1. On the **Servers** page, open **Ubuntu 22.04: pairing helper** and download `fyp-pair-ubuntu.py`. Copy it to the server and check it: `sha256sum fyp-pair-ubuntu.py` must print the value shown on the page.
2. On the server: `sudo python3 fyp-pair-ubuntu.py`. It prints the server name, the SSH port and host key fingerprint it vouches for, and a 9-digit code (10 minutes, one use). While the code is shown, if UFW is active it allows UDP 47815 from private networks only (rule comment `fyp-pairing`) and deletes those rules when it stops. It changes nothing else and keeps no record on the server.
3. On the laptop: **Servers > Add a server**, type the code, then the server account and its password (or one SSH private key file). The login is refused before the password is sent if the server's host key is not the one in the signed answer; after login the hostname and `/etc/machine-id` must match too.
4. The server is saved under **My servers** and its host key is pinned in the integration ledger. Later connections need only the password; a changed host key is refused, never accepted silently. If the server's address changes, run the helper again and use **Re-pair**.

Assessment and approved fixes also need the FYP helper bundle installed once on the server (`cis_compliance_dashboard_prototype/docs/VM_SETUP.md`); the Servers page shows the exact build command for each saved Ubuntu server.

| Message | Meaning and action |
| --- | --- |
| No server answered | Wrong or expired code, the helper has stopped, or the laptop is on another network. The helper prints "Wrong code" for each wrong attempt and stops after 5 from one address. |
| This Ubuntu version is not checked | Only Ubuntu 22.04 (22.04.5 LTS) is supported. |
| `verification_failed` | The host key, hostname or machine ID differs from the signed answer or from the pinned record. Check you are reaching the right server; pair again if it was reinstalled. |
